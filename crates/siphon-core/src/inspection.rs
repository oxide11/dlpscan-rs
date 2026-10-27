//! What a verdict is allowed to mean.
//!
//! A scanner that returns zero matches has answered one of two different
//! questions: "I read all of it and found nothing", or "I found nothing in
//! the part I managed to read". Nine audit rounds between 2026-09-03 and
//! 2026-10-15 each found an ingress giving the second answer in the voice
//! of the first — a `.zip` whose text entry was never walked, an encrypted
//! entry skipped in silence, an ICAP body drained past its limit, a MIME
//! part whose extraction was unfaithful, a match cap that produced a
//! "redacted" output still holding values. Each was fixed where it was
//! found, with a warning string, a `truncated` flag, a `scanned: bool`, a
//! `format_mismatch` metadata key or, in `siphon-mail`, a proper
//! [`Inspection`] enum — and the next round found the path that had none.
//!
//! This module is that enum, lifted into the crate every ingress already
//! depends on, with the reasons made explicit. The rule it encodes is the
//! one `siphon_mail::inspection()` already applies to mail: **a verdict is
//! complete only when every unit of content was read and matched; anything
//! else is incomplete, and an empty set of units is incomplete, not clean.**
//! Nothing here decides what to *do* about an incomplete inspection —
//! deliver, defer, block, exit non-zero — that stays with each ingress,
//! because the right answer differs for a proxy, a mail filter and a CLI.
//! What they may no longer do is report "clean" without saying so.
//!
//! Adoption is incremental (see `docs/architecture/inspection-outcome.md`):
//! an ingress that still carries warning strings maps them in with
//! [`Unread::Other`] until its extractors are typed.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Why some content was not read.
///
/// Variants name the *cause*, not the component: a per-entry size cap in a
/// zip and an oversize ICAP body are both [`Unread::Oversize`], and a
/// consumer that wants to treat "too big" one way does not need to know
/// which ingress said so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Unread {
    /// Larger than a limit the reader enforces. `limit` is the cap in bytes
    /// when known; `unit` names what was capped (`"file"`, `"entry"`,
    /// `"body"`, `"text"`).
    Oversize {
        unit: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<u64>,
    },
    /// The reader stopped before the end: a transfer cut at a byte limit, a
    /// row or entry count cap, a content cap inside an archive member.
    Truncated { unit: String },
    /// Encrypted or password-protected; nothing inside was seen.
    Encrypted { unit: String },
    /// An archive inside an archive that the reader does not descend into.
    NestedArchive { unit: String },
    /// A format or MIME type the reader has no extractor for: a document
    /// nobody could open, a binary body on a proxy. A gap.
    Unsupported { unit: String },
    /// A member the reader passes over because, by its name, it is not
    /// something this reader opens for text: an image or a binary inside a
    /// plain archive, an OLE object or an embedded PDF under an Office
    /// package's `embeddings/`. Nearly every real archive and document
    /// carries one, so this reason is *informational*: it is listed, so a
    /// reader can see what was passed over, and [`Inspection::has_gap`]
    /// does not count it. Contrast [`Unread::Unsupported`], which is a
    /// document in a format no reader handles — that is a gap.
    NotText { unit: String },
    /// The reader tried and failed; `detail` is the error text.
    ReadError { unit: String, detail: String },
    /// The bytes did not match the format the name or type claimed.
    FormatMismatch { declared: String, detected: String },
    /// The scanner stopped matching before the end of the text (a match
    /// cap, a per-pattern cap). The text was read; the verdict is partial.
    MatchCapReached,
    /// A warning string from an ingress that has not yet been typed. Keep
    /// these flowing rather than dropping them; retire the variant as the
    /// producers move to the ones above.
    Other { detail: String },
}

impl Unread {
    /// The unit of content this reason is about, for display and grouping.
    pub fn unit(&self) -> Option<&str> {
        match self {
            Unread::Oversize { unit, .. }
            | Unread::Truncated { unit }
            | Unread::Encrypted { unit }
            | Unread::NestedArchive { unit }
            | Unread::Unsupported { unit }
            | Unread::NotText { unit }
            | Unread::ReadError { unit, .. } => Some(unit),
            Unread::FormatMismatch { .. } | Unread::MatchCapReached | Unread::Other { .. } => None,
        }
    }

    /// Whether this reason is a note rather than a gap.
    ///
    /// A gap is content that may hold a value and was not read: a fail-closed
    /// consumer acts on it. An informational reason says the reader passed
    /// over a member it does not open for text at all (an image in a zip, an
    /// OLE object in a docx); it is reported so nobody has to guess, and
    /// acting on it would defer ordinary mail for a `.png`. Today only
    /// [`Unread::NotText`] is informational; a consumer should call this
    /// rather than match the variant, so a second informational reason does
    /// not have to be taught to every ingress.
    pub fn is_informational(&self) -> bool {
        matches!(self, Unread::NotText { .. })
    }
}

impl fmt::Display for Unread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unread::Oversize {
                unit,
                limit: Some(l),
            } => {
                write!(f, "{unit} exceeds the {l}-byte limit; not read")
            }
            Unread::Oversize { unit, limit: None } => {
                write!(f, "{unit} exceeds size limit; not read")
            }
            Unread::Truncated { unit } => write!(f, "{unit} truncated; only part of it was read"),
            Unread::Encrypted { unit } => write!(f, "{unit} is encrypted; not read"),
            Unread::NestedArchive { unit } => write!(f, "{unit} is a nested archive; not read"),
            Unread::Unsupported { unit } => write!(f, "{unit} is not a readable format; not read"),
            Unread::NotText { unit } => {
                write!(
                    f,
                    "{unit} is not a text member this reader opens; passed over"
                )
            }
            Unread::ReadError { unit, detail } => write!(f, "{unit} could not be read: {detail}"),
            Unread::FormatMismatch { declared, detected } => {
                write!(f, "content is {detected}, not the declared {declared}")
            }
            Unread::MatchCapReached => write!(f, "match cap reached; matching stopped early"),
            Unread::Other { detail } => f.write_str(detail),
        }
    }
}

/// Whether a verdict covers everything it was asked about.
///
/// Built with [`Inspection::new`] and [`Inspection::unread`]; queried with
/// [`Inspection::is_complete`]. A freshly built value is complete; it
/// becomes incomplete the moment anything is reported unread, and never
/// goes back. There is no way to construct `Complete` *and* carry reasons,
/// which is the invariant the string-and-flag versions could not hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Inspection {
    /// Every unit of content was read and matched.
    #[default]
    Complete,
    /// Some content was not read; `unread` says what and why. The verdict
    /// that accompanies this value covers only what *was* read.
    Incomplete { unread: Vec<Unread> },
}

impl Inspection {
    /// Start complete; call [`unread`](Self::unread) for anything not read.
    pub fn new() -> Self {
        Inspection::Complete
    }

    /// The outcome for content that had no units at all. Mirrors
    /// `siphon_mail::inspection()`: no parts is not a clean bill of health,
    /// because nothing was examined.
    pub fn nothing_to_inspect(unit: &str) -> Self {
        Inspection::Incomplete {
            unread: vec![Unread::Unsupported {
                unit: format!("{unit} (no readable content)"),
            }],
        }
    }

    /// Record that a unit of content was not read. Idempotent in effect:
    /// once incomplete, always incomplete; reasons accumulate in order.
    pub fn unread(&mut self, reason: Unread) {
        match self {
            Inspection::Complete => {
                *self = Inspection::Incomplete {
                    unread: vec![reason],
                }
            }
            Inspection::Incomplete { unread } => unread.push(reason),
        }
    }

    /// Builder form of [`unread`](Self::unread).
    pub fn with_unread(mut self, reason: Unread) -> Self {
        self.unread(reason);
        self
    }

    /// Fold another inspection in: a container is complete only when every
    /// member was.
    pub fn merge(&mut self, other: Inspection) {
        if let Inspection::Incomplete { unread } = other {
            for r in unread {
                self.unread(r);
            }
        }
    }

    /// Absorb warning strings from an ingress that has not been typed yet.
    /// Every non-empty string counts: a reader that had something to warn
    /// about did not read everything, and silently dropping the warning is
    /// exactly the failure this type exists to end.
    pub fn absorb_warnings<I, S>(&mut self, warnings: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for w in warnings {
            let w = w.as_ref().trim();
            if !w.is_empty() {
                self.unread(Unread::Other {
                    detail: w.to_string(),
                });
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, Inspection::Complete)
    }

    /// Whether anything that may hold a value went unread.
    ///
    /// This is the question a fail-closed consumer asks. [`is_complete`]
    /// answers the stricter one — was *everything* read — and stays `false`
    /// when the only reasons are informational ([`Unread::is_informational`]),
    /// because a verdict over an archive with an unopened image in it does
    /// not cover the image, and the reader should not pretend otherwise. But
    /// an image is not a gap a policy should defer mail over, so the milter,
    /// siphon-fs's coverage counter and the CLI's `--on-incomplete fail` read
    /// this method, not `is_complete`. The two invariants still hold: there
    /// is no way to be `Complete` and carry reasons, and no way to have a
    /// gap and not be `Incomplete`.
    ///
    /// [`is_complete`]: Inspection::is_complete
    pub fn has_gap(&self) -> bool {
        self.gaps().next().is_some()
    }

    /// The reasons that are gaps, in the order they were recorded; the
    /// informational ones are left out. `unread_reasons` has all of them.
    pub fn gaps(&self) -> impl Iterator<Item = &Unread> {
        self.unread_reasons()
            .iter()
            .filter(|u| !u.is_informational())
    }

    /// The reasons, empty when complete.
    pub fn unread_reasons(&self) -> &[Unread] {
        match self {
            Inspection::Complete => &[],
            Inspection::Incomplete { unread } => unread,
        }
    }

    /// One line per reason, for a CLI "Unscanned content:" block or an
    /// `X-DLP-Reason` header. Empty when complete.
    pub fn describe(&self) -> Vec<String> {
        self.unread_reasons()
            .iter()
            .map(|r| r.to_string())
            .collect()
    }
}

impl fmt::Display for Inspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inspection::Complete => f.write_str("complete"),
            Inspection::Incomplete { unread } => {
                write!(f, "incomplete ({} unread)", unread.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_complete_and_has_no_reasons() {
        let i = Inspection::new();
        assert!(i.is_complete());
        assert!(i.unread_reasons().is_empty());
        assert!(i.describe().is_empty());
        assert_eq!(i.to_string(), "complete");
    }

    #[test]
    fn one_unread_makes_it_incomplete_for_good() {
        let mut i = Inspection::new();
        i.unread(Unread::Encrypted {
            unit: "entry secret.docx".into(),
        });
        assert!(!i.is_complete());
        // A later "all good" from another member cannot undo it.
        i.merge(Inspection::Complete);
        assert!(!i.is_complete());
        assert_eq!(i.unread_reasons().len(), 1);
    }

    #[test]
    fn reasons_accumulate_in_order() {
        let i = Inspection::new()
            .with_unread(Unread::Oversize {
                unit: "entry a.bin".into(),
                limit: Some(100),
            })
            .with_unread(Unread::NestedArchive {
                unit: "entry inner.zip".into(),
            });
        let lines = i.describe();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("entry a.bin") && lines[0].contains("100-byte"));
        assert!(lines[1].contains("nested archive"));
        assert_eq!(i.to_string(), "incomplete (2 unread)");
    }

    #[test]
    fn merge_folds_a_members_reasons_into_the_container() {
        let member = Inspection::new().with_unread(Unread::Truncated {
            unit: "entry big.txt".into(),
        });
        let mut container = Inspection::new();
        container.merge(member);
        assert!(!container.is_complete());
        assert_eq!(container.unread_reasons()[0].unit(), Some("entry big.txt"));
    }

    #[test]
    fn nothing_to_inspect_is_incomplete_not_clean() {
        let i = Inspection::nothing_to_inspect("message");
        assert!(!i.is_complete());
        assert!(i.describe()[0].contains("message"));
    }

    #[test]
    fn absorb_warnings_keeps_every_non_empty_string() {
        let mut i = Inspection::new();
        i.absorb_warnings(["nested archive not scanned: inner.zip", "  ", ""]);
        assert_eq!(i.unread_reasons().len(), 1);
        assert_eq!(
            i.unread_reasons()[0],
            Unread::Other {
                detail: "nested archive not scanned: inner.zip".into()
            }
        );
    }

    #[test]
    fn absorb_no_warnings_stays_complete() {
        let mut i = Inspection::new();
        i.absorb_warnings(Vec::<String>::new());
        assert!(i.is_complete());
    }

    #[test]
    fn serde_round_trip_and_wire_shape() {
        let i = Inspection::new().with_unread(Unread::FormatMismatch {
            declared: "txt".into(),
            detected: "zip".into(),
        });
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains("\"status\":\"incomplete\""));
        assert!(json.contains("\"kind\":\"format_mismatch\""));
        let back: Inspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, i);
        assert_eq!(
            serde_json::to_string(&Inspection::Complete).unwrap(),
            "{\"status\":\"complete\"}"
        );
    }

    #[test]
    fn oversize_without_a_known_limit_still_reads_sensibly() {
        let r = Unread::Oversize {
            unit: "body".into(),
            limit: None,
        };
        assert_eq!(r.to_string(), "body exceeds size limit; not read");
    }

    /// An informational reason is reported, makes the inspection incomplete
    /// (the image was not read, and the type does not pretend it was), and
    /// is not a gap: a fail-closed consumer reading `has_gap` lets it pass.
    #[test]
    fn an_informational_reason_is_incomplete_but_not_a_gap() {
        let i = Inspection::new().with_unread(Unread::NotText {
            unit: "entry photo.png".into(),
        });
        assert!(!i.is_complete());
        assert!(!i.has_gap());
        assert_eq!(i.gaps().count(), 0);
        assert_eq!(i.unread_reasons().len(), 1);
        assert_eq!(
            i.describe(),
            vec!["entry photo.png is not a text member this reader opens; passed over"]
        );
        assert_eq!(i.unread_reasons()[0].unit(), Some("entry photo.png"));
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains("\"kind\":\"not_text\""), "{json}");
    }

    /// One gap among any number of notes is still a gap, and `gaps()` hands
    /// back exactly the reasons a policy should act on.
    #[test]
    fn a_gap_beside_informational_reasons_is_still_a_gap() {
        let i = Inspection::new()
            .with_unread(Unread::NotText {
                unit: "entry a.png".into(),
            })
            .with_unread(Unread::Encrypted {
                unit: "entry b.txt".into(),
            })
            .with_unread(Unread::NotText {
                unit: "entry c.gif".into(),
            });
        assert!(i.has_gap());
        let gaps: Vec<_> = i.gaps().collect();
        assert_eq!(gaps.len(), 1);
        assert!(matches!(gaps[0], Unread::Encrypted { unit } if unit == "entry b.txt"));
        assert_eq!(i.unread_reasons().len(), 3);
    }

    /// Every reason that is not the informational one is a gap. Pinned so a
    /// new variant has to say which side it is on.
    #[test]
    fn every_other_reason_is_a_gap() {
        let reasons = [
            Unread::Oversize {
                unit: "u".into(),
                limit: None,
            },
            Unread::Truncated { unit: "u".into() },
            Unread::Encrypted { unit: "u".into() },
            Unread::NestedArchive { unit: "u".into() },
            Unread::Unsupported { unit: "u".into() },
            Unread::ReadError {
                unit: "u".into(),
                detail: "d".into(),
            },
            Unread::FormatMismatch {
                declared: "a".into(),
                detected: "b".into(),
            },
            Unread::MatchCapReached,
            Unread::Other { detail: "d".into() },
        ];
        for r in reasons {
            assert!(!r.is_informational(), "{r:?}");
            assert!(Inspection::new().with_unread(r).has_gap());
        }
    }
}
