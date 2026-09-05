//! MIME message decomposition.
//!
//! Turns a raw RFC 5322 message into a flat list of scannable parts, each
//! carrying the identity the rest of the system uses to talk about it. Shared
//! deliberately: the `.eml` file extractor and the mail path need exactly the
//! same walk, and duplicating it would mean two parsers disagreeing about what
//! a message contains — which, for a scanner, is a bypass.
//!
//! # Why this exists
//!
//! Before this module, `.eml` extraction scraped six headers and treated the
//! rest of the file as plain text. A base64 attachment therefore reached the
//! scanner as base64, matched nothing, and the file came back clean. The
//! normalizer's base64 stage does not rescue it: MUAs line-wrap base64 at 76
//! columns, and decoding each wrapped line independently yields noise rather
//! than the payload.
//!
//! # Not a parser
//!
//! The parsing itself is `mail-parser`'s. Hand-rolling MIME is a well-known
//! source of scanner bypasses — an attacker who can make our boundary handling
//! disagree with the recipient's MUA gets content past us that the recipient
//! still sees. This module is the bounded, opinionated layer on top: identity,
//! limits, and the decisions about what is worth scanning.

use mail_parser::{MessageParser, MimeHeaders, PartType};
use std::sync::Arc;

/// Bounds applied while walking. Message structure is attacker-controlled, so
/// every recursion and accumulation here needs a ceiling.
#[derive(Debug, Clone, Copy)]
pub struct MimeLimits {
    /// Total parts to emit. A deeply nested `multipart` bomb is cheap to
    /// write and expensive to walk.
    pub max_parts: usize,
    /// Nesting depth. `message/rfc822` can contain a message containing a
    /// message; each level is legitimate and the nesting is unbounded.
    pub max_depth: usize,
    /// Total decoded bytes across all parts. Decoding expands: base64 grows
    /// by a third on the way out, and a small message can declare a large one.
    pub max_total_bytes: usize,
}

impl Default for MimeLimits {
    fn default() -> Self {
        Self {
            max_parts: 1_000,
            max_depth: 20,
            // Deliberately above the scanner's own cap: this bounds the walk,
            // while `MAX_INPUT_SIZE` bounds what any single part may hand to
            // the scanner. Conflating them would silently drop a part that is
            // individually scannable from a message that is merely large.
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

/// What a part is, from the scanner's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartKind {
    /// Body text — `text/plain`, `text/html`. Scanned directly, and
    /// contributes to the context envelope.
    Text,
    /// A file. Scanned by handing its bytes to an extractor; contributes only
    /// its filename to the envelope.
    Attachment,
    /// Structural (`multipart/*`, `message/rfc822`). Carries no content of its
    /// own — retained because its path is the parent of things that do.
    Container,
}

/// One addressable piece of a message.
#[derive(Debug, Clone)]
pub struct MimePart {
    /// Dotted MIME path — `"1"`, `"1.2"`, `"2.1.4"`.
    ///
    /// Identity is the path, never an ordinal. MIME nests, so a flat index
    /// cannot name a part inside a forwarded message, and a path stays stable
    /// across an MTA retry where a re-derived ordinal would not.
    pub path: String,
    pub kind: PartKind,
    /// Lowercased `type/subtype`, or `application/octet-stream` when absent —
    /// the RFC 2045 default.
    pub content_type: String,
    /// Filename from `Content-Disposition`, falling back to the
    /// `Content-Type` `name` attribute.
    pub filename: Option<String>,
    /// Decoded text, for parts that have any. `None` for binary attachments
    /// and containers.
    pub text: Option<String>,
    /// Decoded bytes for attachments, so a caller can hand them to a format
    /// extractor without re-parsing the message.
    ///
    /// Retained rather than re-read because the alternative is parsing the
    /// message twice, and the walk already charges every decoded byte against
    /// `max_total_bytes` — so this is bounded by the same budget rather than
    /// being a second, unbounded one. `None` for body text (already in
    /// `text`) and for containers (no content of their own).
    pub data: Option<Vec<u8>>,
    /// Decoded size in bytes, whether or not the text was retained.
    pub size: usize,
}

/// Envelope headers worth carrying alongside the parts.
#[derive(Debug, Clone, Default)]
pub struct MessageHeaders {
    pub from: Option<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    /// RFC 5322 `Message-ID`. An indexed attribute, never an identity — it is
    /// client-supplied, forgeable, and sometimes absent.
    pub message_id: Option<String>,
    pub date: Option<String>,
}

/// A decomposed message.
#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub headers: MessageHeaders,
    pub parts: Vec<MimePart>,
    /// Structural problems worth surfacing. A warning here means something
    /// was *not* inspected, which must never be reported as clean.
    pub warnings: Vec<String>,
}

impl ParsedMessage {
    /// Text of every textual part, in order.
    pub fn text_parts(&self) -> impl Iterator<Item = &MimePart> {
        self.parts
            .iter()
            .filter(|p| p.kind == PartKind::Text && p.text.is_some())
    }

    /// Parts that need an extractor.
    pub fn attachments(&self) -> impl Iterator<Item = &MimePart> {
        self.parts.iter().filter(|p| p.kind == PartKind::Attachment)
    }

    /// Everything concatenated — the whole message as one string.
    ///
    /// Convenient, and the wrong tool for scanning a large message: it
    /// materialises every part at once, which is what the per-part path
    /// exists to avoid.
    pub fn all_text(&self) -> String {
        let mut out = String::new();
        if let Some(s) = &self.headers.subject {
            out.push_str(s);
            out.push('\n');
        }
        for p in self.text_parts() {
            if let Some(t) = &p.text {
                out.push_str(t);
                out.push('\n');
            }
        }
        out
    }

    /// Context for scanning one part in isolation.
    ///
    /// Feeds [`crate::scanner::ScanConfig::context_envelope`]. Context gating
    /// is proximity-based *within one scanned text*, so scanning an attachment
    /// on its own hides the body that describes it — a spreadsheet of bare
    /// digits beside a body reading "payroll bank account details attached"
    /// only fires if the body reaches the gate.
    ///
    /// Excludes `exclude_path` so a part never supplies its own context: that
    /// would promote a local keyword to envelope evidence and score it as
    /// though it came from elsewhere.
    ///
    /// # Prefer [`Self::envelope_index`] for whole messages
    ///
    /// This rebuilds the envelope for one part. Calling it per part makes a
    /// message `O(parts × message bytes)` — measured at 41 s for 400 inline
    /// text parts — because both this string and the Aho-Corasick index built
    /// over it are discarded and remade for the next part.
    ///
    /// [`Self::envelope_index`] does the same work once for the whole message
    /// and makes exclusion a range filter. This method remains for scanning a
    /// single part in isolation, where there is no message-wide pass to amortise
    /// against.
    pub fn context_envelope(&self, exclude_path: &str) -> String {
        let mut out = String::new();
        if let Some(s) = &self.headers.subject {
            out.push_str(s);
            out.push('\n');
        }
        for p in &self.parts {
            if p.path == exclude_path {
                continue;
            }
            // Filenames are context in their own right: "2024-payroll.xlsx"
            // says what the bytes beside it are.
            if let Some(f) = &p.filename {
                out.push_str(f);
                out.push('\n');
            }
            if p.kind == PartKind::Text {
                if let Some(t) = &p.text {
                    out.push_str(t);
                    out.push('\n');
                }
            }
        }
        out
    }

    /// Index the context envelope **once** for the whole message.
    ///
    /// Then scan each part with `index.for_key(&part.path)`, which excludes
    /// that part's own contribution by byte range rather than by rebuilding
    /// the envelope without it. Same result as calling
    /// [`Self::context_envelope`] per part; `O(message)` once instead of
    /// `O(parts × message)`.
    ///
    /// ```no_run
    /// # use siphon_core::mime::parse_message;
    /// # use siphon_core::scanner::{scan_text_with_config, ScanConfig};
    /// # let raw: &[u8] = b"";
    /// let msg = parse_message(raw);
    /// let envelope = msg.envelope_index();
    /// for part in msg.text_parts() {
    ///     let config = ScanConfig {
    ///         shared_envelope: Some(envelope.for_key(&part.path)),
    ///         ..Default::default()
    ///     };
    ///     let _ = scan_text_with_config(part.text.as_deref().unwrap_or(""), &config);
    /// }
    /// ```
    pub fn envelope_index(&self) -> Arc<crate::context::EnvelopeIndex> {
        let mut builder = crate::context::EnvelopeBuilder::new();
        // The subject belongs to no part, so it is never excluded — every
        // part is scanned with it.
        if let Some(s) = &self.headers.subject {
            builder.push_shared(s);
        }
        for p in &self.parts {
            // A part's filename and text are pushed consecutively so its
            // range covers both; see EnvelopeBuilder::push_keyed.
            if let Some(f) = &p.filename {
                builder.push_keyed(&p.path, f);
            }
            if p.kind == PartKind::Text {
                if let Some(t) = &p.text {
                    builder.push_keyed(&p.path, t);
                }
            }
        }
        builder.build()
    }
}

/// Decompose a message with default limits.
pub fn parse_message(raw: &[u8]) -> ParsedMessage {
    parse_message_with_limits(raw, &MimeLimits::default())
}

/// Decompose a message.
///
/// Never fails: an unparseable message yields a single text part holding
/// whatever was readable, plus a warning. A scanner that refuses to look at
/// malformed input is a scanner an attacker can switch off by malforming the
/// input.
pub fn parse_message_with_limits(raw: &[u8], limits: &MimeLimits) -> ParsedMessage {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return ParsedMessage {
            headers: MessageHeaders::default(),
            parts: vec![MimePart {
                path: "1".into(),
                kind: PartKind::Text,
                content_type: "text/plain".into(),
                filename: None,
                text: Some(String::from_utf8_lossy(raw).into_owned()),
                data: None,
                size: raw.len(),
            }],
            warnings: vec!["message could not be parsed as MIME; scanned as plain text".to_string()],
        };
    };

    let mut out = ParsedMessage {
        headers: extract_headers(&msg),
        parts: Vec::new(),
        warnings: Vec::new(),
    };
    let mut budget = Budget {
        bytes: 0,
        stopped: false,
    };
    walk(&msg, 0, "1", 1, limits, &mut out, &mut budget);
    out
}

struct Budget {
    bytes: usize,
    stopped: bool,
}

fn extract_headers(msg: &mail_parser::Message<'_>) -> MessageHeaders {
    // Address headers can be a single address, a list, or an RFC 2369 group;
    // flatten to plain addresses and drop display names, which are sender-
    // controlled and add nothing an investigator can pivot on.
    let flatten = |a: Option<&mail_parser::Address<'_>>| -> Vec<String> {
        a.map(|a| {
            a.iter()
                .filter_map(|x| x.address.as_ref().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
    };
    MessageHeaders {
        from: flatten(msg.from()).into_iter().next(),
        to: flatten(msg.to()),
        subject: msg.subject().map(str::to_string),
        message_id: msg.message_id().map(str::to_string),
        date: msg.date().map(|d| d.to_rfc3339()),
    }
}

/// Walk the part tree, assigning dotted paths.
#[allow(clippy::too_many_arguments)]
fn walk(
    msg: &mail_parser::Message<'_>,
    part_id: usize,
    path: &str,
    depth: usize,
    limits: &MimeLimits,
    out: &mut ParsedMessage,
    budget: &mut Budget,
) {
    if budget.stopped {
        return;
    }
    if out.parts.len() >= limits.max_parts {
        stop(
            out,
            budget,
            format!("part limit ({}) reached", limits.max_parts),
        );
        return;
    }
    if depth > limits.max_depth {
        // Not scanned, and said so. A silently truncated walk is the failure
        // mode this whole module exists to remove.
        out.warnings.push(format!(
            "nesting deeper than {} at part {path}; not scanned",
            limits.max_depth
        ));
        return;
    }
    let Some(part) = msg.parts.get(part_id) else {
        return;
    };

    let content_type = part
        .content_type()
        .map(|ct| match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype().to_lowercase(), sub.to_lowercase()),
            None => ct.ctype().to_lowercase(),
        })
        // RFC 2045: absent Content-Type means text/plain, but a part with a
        // filename and no type is far more likely a file than a body.
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let filename = part.attachment_name().map(str::to_string);

    match &part.body {
        PartType::Multipart(children) => {
            out.parts.push(MimePart {
                path: path.to_string(),
                kind: PartKind::Container,
                content_type,
                filename,
                text: None,
                data: None,
                size: 0,
            });
            for (i, child) in children.iter().enumerate() {
                walk(
                    msg,
                    *child as usize,
                    &format!("{path}.{}", i + 1),
                    depth + 1,
                    limits,
                    out,
                    budget,
                );
                if budget.stopped {
                    return;
                }
            }
        }
        PartType::Message(inner) => {
            // A forwarded message. Its parts are addressed under this path,
            // so a finding inside a forward is still locatable.
            out.parts.push(MimePart {
                path: path.to_string(),
                kind: PartKind::Container,
                content_type,
                filename,
                text: None,
                data: None,
                size: 0,
            });
            walk(
                inner,
                0,
                &format!("{path}.1"),
                depth + 1,
                limits,
                out,
                budget,
            );
        }
        PartType::Text(text) | PartType::Html(text) => {
            let size = text.len();
            if !charge(budget, size, limits, out) {
                return;
            }
            let is_named = filename.is_some();
            out.parts.push(MimePart {
                path: path.to_string(),
                kind: if is_named {
                    // A text/* part with a filename is an attached file that
                    // happens to be text — a .csv of card numbers is not body
                    // copy, and treating it as context would let an attacker
                    // supply their own.
                    PartKind::Attachment
                } else {
                    PartKind::Text
                },
                content_type,
                filename,
                data: if is_named {
                    Some(text.as_bytes().to_vec())
                } else {
                    None
                },
                text: Some(text.to_string()),
                size,
            });
        }
        PartType::Binary(data) | PartType::InlineBinary(data) => {
            let size = data.len();
            if !charge(budget, size, limits, out) {
                return;
            }
            out.parts.push(MimePart {
                path: path.to_string(),
                kind: PartKind::Attachment,
                content_type,
                filename,
                text: None,
                data: Some(data.to_vec()),
                size,
            });
        }
    }
}

fn charge(budget: &mut Budget, size: usize, limits: &MimeLimits, out: &mut ParsedMessage) -> bool {
    budget.bytes = budget.bytes.saturating_add(size);
    if budget.bytes > limits.max_total_bytes {
        stop(
            out,
            budget,
            format!(
                "decoded content exceeded {} bytes; remaining parts not scanned",
                limits.max_total_bytes
            ),
        );
        return false;
    }
    true
}

fn stop(out: &mut ParsedMessage, budget: &mut Budget, why: String) {
    if !budget.stopped {
        out.warnings.push(why);
        budget.stopped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// The bypass this module was written for: a base64 attachment whose
    /// payload never reached the scanner, so the message came back clean.
    #[test]
    fn base64_attachment_is_decoded() {
        let payload = b"acct,card\nprimary,4111111111111111\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        // Wrapped at 76 columns, as a real MUA emits it. Unwrapped base64
        // would be decoded incidentally by the normalizer; wrapped is the
        // case that silently failed.
        let wrapped: String = b64
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n");

        let raw = format!(
            "From: a@example.com\r\nTo: b@example.com\r\nSubject: Q3\r\n\
             Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n\
             --BND\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
             --BND\r\nContent-Type: text/csv; name=\"cards.csv\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{wrapped}\r\n--BND--\r\n"
        );

        let parsed = parse_message(raw.as_bytes());
        let joined: String = parsed
            .parts
            .iter()
            .filter_map(|p| p.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("4111111111111111"),
            "base64 attachment must be decoded; got: {joined:?}"
        );
    }

    #[test]
    fn parts_are_addressed_by_mime_path() {
        let raw = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--B--\r\n";
        let parsed = parse_message(raw.as_bytes());
        let paths: Vec<&str> = parsed.parts.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["1", "1.1", "1.2"]);
    }

    #[test]
    fn nested_forwarded_message_is_walked() {
        let inner = "Content-Type: text/plain\r\n\r\ninner secret 4111111111111111\r\n";
        let raw = format!(
            "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
             --B\r\nContent-Type: text/plain\r\n\r\nouter\r\n\
             --B\r\nContent-Type: message/rfc822\r\n\r\n{inner}--B--\r\n"
        );
        let parsed = parse_message(raw.as_bytes());
        let all: String = parsed.all_text();
        assert!(
            all.contains("inner secret"),
            "a forwarded message must be walked, not treated as opaque: {all:?}"
        );
    }

    #[test]
    fn headers_are_extracted() {
        let raw = "From: sender@example.com\r\nTo: rcpt@example.com\r\n\
                   Subject: Payroll\r\nMessage-ID: <abc@example.com>\r\n\
                   Content-Type: text/plain\r\n\r\nbody\r\n";
        let p = parse_message(raw.as_bytes());
        assert_eq!(p.headers.from.as_deref(), Some("sender@example.com"));
        assert_eq!(p.headers.to, vec!["rcpt@example.com"]);
        assert_eq!(p.headers.subject.as_deref(), Some("Payroll"));
        assert_eq!(p.headers.message_id.as_deref(), Some("abc@example.com"));
    }

    /// A text part carrying a filename is a file, not body copy. Treating it
    /// as context would let a sender supply their own keywords.
    #[test]
    fn named_text_part_is_an_attachment_not_body() {
        let raw = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nbody copy\r\n\
                   --B\r\nContent-Type: text/csv; name=\"data.csv\"\r\n\r\na,b\r\n--B--\r\n";
        let p = parse_message(raw.as_bytes());
        let named = p.parts.iter().find(|x| x.filename.is_some()).unwrap();
        assert_eq!(named.kind, PartKind::Attachment);
    }

    #[test]
    fn envelope_excludes_the_part_being_scanned() {
        let raw = "Content-Type: multipart/mixed; boundary=\"B\"\r\n\
                   Subject: Payroll details\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nbank account attached\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\n493028461037\r\n--B--\r\n";
        let p = parse_message(raw.as_bytes());
        let env = p.context_envelope("1.2");
        assert!(env.contains("bank account"), "sibling body is context");
        assert!(env.contains("Payroll details"), "subject is context");
        assert!(
            !env.contains("493028461037"),
            "a part must not supply its own context, or a local keyword is \
             scored as though it came from elsewhere"
        );
    }

    #[test]
    fn unparseable_input_is_still_scannable() {
        let p = parse_message(b"\xff\xfe not a message at all");
        assert!(!p.parts.is_empty(), "must yield something to scan");
        assert!(
            p.parts.iter().any(|x| x.text.is_some()),
            "malformed input must not switch the scanner off"
        );
    }

    #[test]
    fn depth_limit_warns_rather_than_silently_truncating() {
        // Nested message/rfc822 beyond the configured depth.
        let mut raw = String::from("Content-Type: message/rfc822\r\n\r\n");
        for _ in 0..6 {
            raw.push_str("Content-Type: message/rfc822\r\n\r\n");
        }
        raw.push_str("Content-Type: text/plain\r\n\r\ndeep\r\n");
        let limits = MimeLimits {
            max_depth: 3,
            ..Default::default()
        };
        let p = parse_message_with_limits(raw.as_bytes(), &limits);
        assert!(
            p.warnings.iter().any(|w| w.contains("nesting")),
            "exceeding the depth limit must warn, not truncate silently: {:?}",
            p.warnings
        );
    }

    #[test]
    fn part_limit_warns() {
        let mut raw = String::from("Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n");
        for i in 0..50 {
            raw.push_str(&format!(
                "--B\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n"
            ));
        }
        raw.push_str("--B--\r\n");
        let limits = MimeLimits {
            max_parts: 10,
            ..Default::default()
        };
        let p = parse_message_with_limits(raw.as_bytes(), &limits);
        assert!(p.parts.len() <= 10);
        assert!(
            p.warnings.iter().any(|w| w.contains("part limit")),
            "hitting the part limit must be visible: {:?}",
            p.warnings
        );
    }

    // --- shared envelope ---------------------------------------------------

    use crate::scanner::{scan_text_with_config, ScanConfig};

    fn findings_with_rebuilt_envelope(msg: &ParsedMessage, path: &str, text: &str) -> Vec<String> {
        let config = ScanConfig {
            context_envelope: Some(msg.context_envelope(path)),
            ..Default::default()
        };
        let mut out: Vec<String> = scan_text_with_config(text, &config)
            .unwrap()
            .into_iter()
            .map(|m| format!("{}/{}/{}", m.category, m.sub_category, m.text))
            .collect();
        out.sort();
        out
    }

    fn findings_with_shared_envelope(msg: &ParsedMessage, path: &str, text: &str) -> Vec<String> {
        let envelope = msg.envelope_index();
        let config = ScanConfig {
            shared_envelope: Some(envelope.for_key(path)),
            ..Default::default()
        };
        let mut out: Vec<String> = scan_text_with_config(text, &config)
            .unwrap()
            .into_iter()
            .map(|m| format!("{}/{}/{}", m.category, m.sub_category, m.text))
            .collect();
        out.sort();
        out
    }

    /// A multi-part message where the body describes what the attachment
    /// contains — the case the envelope exists for.
    fn envelope_test_message() -> ParsedMessage {
        let raw = "From: hr@corp.example\r\nTo: b@corp.example\r\n\
                   Subject: Payroll export\r\n\
                   Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\n\
                   Attached is the payroll file. It has the social security number \
                   and date of birth columns the audit asked for.\r\n\
                   --B\r\nContent-Type: text/plain; name=\"payroll.csv\"\r\n\
                   Content-Disposition: attachment; filename=\"payroll.csv\"\r\n\r\n\
                   name,id\r\nAlice,425713482\r\nBob,318427156\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\n\
                   Regards, the finance team. Invoice 88213 is still open.\r\n--B--\r\n";
        parse_message(raw.as_bytes())
    }

    /// The whole point of the shared index: it must decide exactly what the
    /// per-part rebuild decided. Same evidence, amortised — not less evidence.
    #[test]
    fn shared_envelope_matches_the_rebuilt_one_for_every_part() {
        let msg = envelope_test_message();
        assert!(msg.parts.len() >= 3, "fixture should have several parts");

        for part in &msg.parts {
            let Some(text) = part.text.as_deref() else {
                continue;
            };
            assert_eq!(
                findings_with_rebuilt_envelope(&msg, &part.path, text),
                findings_with_shared_envelope(&msg, &part.path, text),
                "part {} disagreed between rebuilt and shared envelope",
                part.path
            );
        }
    }

    /// Exclusion is the correctness requirement, and range filtering is a
    /// different mechanism from omission — so test the property directly
    /// rather than trusting the equivalence test above to have covered it.
    ///
    /// A part's own keywords sit inside the shared index. If the range filter
    /// leaked, they would come back as *envelope* evidence for that same
    /// part, which is exactly the mis-scoring the exclusion exists to stop.
    #[test]
    fn a_part_does_not_supply_its_own_envelope_context() {
        // One part, holding both the keyword and the bare number. Nothing
        // else in the message mentions either.
        let raw = "Subject: files\r\n\
                   Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\n\
                   social security number listed below\r\n425713482\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\n\
                   unrelated closing line\r\n--B--\r\n";
        let msg = parse_message(raw.as_bytes());
        let envelope = msg.envelope_index();
        let self_part = msg
            .parts
            .iter()
            .find(|p| {
                p.text
                    .as_deref()
                    .is_some_and(|t| t.contains("social security number"))
            })
            .expect("fixture part");

        let excluded = envelope.for_key(&self_part.path);
        let not_excluded = envelope.whole();

        // The keyword is in the index — `whole()` sees it.
        assert!(
            not_excluded
                .hit_index()
                .expect("index built")
                .has_hit_outside(
                    "North America - United States",
                    "USA SSN",
                    not_excluded.exclude()
                ),
            "fixture must put an SSN context keyword in the envelope at all",
        );
        // ...and excluding that part's range removes it.
        assert!(
            !excluded.hit_index().expect("index built").has_hit_outside(
                "North America - United States",
                "USA SSN",
                excluded.exclude()
            ),
            "a part's own keyword leaked back as envelope evidence for itself",
        );
    }

    /// The cross-part case the envelope was introduced for: keyword in the
    /// body, bare digits in the attachment.
    #[test]
    fn context_still_crosses_from_one_part_to_another() {
        let msg = envelope_test_message();
        let attachment = msg
            .parts
            .iter()
            .find(|p| p.filename.as_deref() == Some("payroll.csv"))
            .expect("fixture attachment");
        let envelope = msg.envelope_index();
        let view = envelope.for_key(&attachment.path);

        assert!(
            view.hit_index().expect("index built").has_hit_outside(
                "North America - United States",
                "USA SSN",
                view.exclude()
            ),
            "the body's keyword must still reach the attachment's scan",
        );
    }

    /// Sections are newline-separated so Aho-Corasick cannot match across the
    /// join. Without that, a keyword formed from one part's tail and the
    /// next part's head would be attributed to whichever part it started in —
    /// letting a part contribute context to itself via its neighbour's range.
    #[test]
    fn keywords_do_not_form_across_the_section_join() {
        let mut builder = crate::context::EnvelopeBuilder::new();
        builder.push_keyed("1", "social security nu");
        builder.push_keyed("2", "mber");
        let index = builder.build();

        // Excluding neither part, the spliced keyword must still not exist.
        let whole = index.whole();
        assert!(
            !whole.hit_index().expect("index built").has_hit_outside(
                "North America - United States",
                "USA SSN",
                whole.exclude()
            ),
            "a keyword was matched across the section boundary",
        );
    }

    /// A part contributing both a filename and a body must exclude both, or
    /// half of its own material leaks back as envelope evidence.
    #[test]
    fn a_parts_filename_and_body_are_excluded_together() {
        let mut builder = crate::context::EnvelopeBuilder::new();
        builder.push_keyed("1", "social-security-numbers.csv");
        builder.push_keyed("1", "425713482");
        builder.push_keyed("2", "unrelated");
        let index = builder.build();

        let view = index.for_key("1");
        assert!(
            !view.hit_index().expect("index built").has_hit_outside(
                "North America - United States",
                "USA SSN",
                view.exclude()
            ),
            "the filename half of a part's contribution was not excluded",
        );
    }

    /// An envelope built once and used across parts must not be slower per
    /// part as the message grows — that regression is the whole reason this
    /// type exists, and it is invisible in a correctness test.
    #[test]
    fn envelope_index_is_built_once_not_once_per_part() {
        fn message_with(parts: usize) -> ParsedMessage {
            let mut raw = String::from(
                "Subject: report\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
            );
            for i in 0..parts {
                raw.push_str(&format!(
                    "--B\r\nContent-Type: text/plain\r\n\r\n\
                     Section {i}: account number and routing number for the wire \
                     transfer, plus the social security number column.\r\n"
                ));
            }
            raw.push_str("--B--\r\n");
            parse_message(raw.as_bytes())
        }

        // Building the index is O(message) regardless of part count, so the
        // per-part cost of *obtaining a view* must be constant.
        let small = message_with(8);
        let large = message_with(64);
        let small_index = small.envelope_index();
        let large_index = large.envelope_index();

        // Same envelope text length per part in both, so the large message's
        // envelope is ~8x the small one's.
        assert!(
            large_index.text().len() > small_index.text().len() * 4,
            "fixture should scale the envelope with part count",
        );

        // A view is an Arc clone and a range lookup: no text is copied, so
        // both envelopes hand out views referring to the same single text.
        let paths: Vec<&str> = large
            .parts
            .iter()
            .filter(|p| p.kind == PartKind::Text)
            .map(|p| p.path.as_str())
            .collect();
        assert!(paths.len() >= 2, "fixture should have several text parts");
        let view_a = large_index.for_key(paths[0]);
        let view_b = large_index.for_key(paths[1]);
        assert!(std::ptr::eq(
            view_a.envelope_text().as_ptr(),
            view_b.envelope_text().as_ptr()
        ));
        assert_ne!(
            view_a.exclude(),
            view_b.exclude(),
            "different parts must exclude different ranges"
        );
    }
}
