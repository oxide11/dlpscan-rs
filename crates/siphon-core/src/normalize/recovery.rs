//! Value recovery for any check-digit identifier, not only cards.
//!
//! The recoveries in `generate_alternative_decodings` (zero padding, letter
//! noise, a base64 tail, a value split over JSON fields, rot13 of base64) were
//! written for card numbers: each is bounded to 13–19 digits and assumes a
//! digit-only value. That bound is part of what keeps them safe, because the
//! alt pass runs always-run patterns there with no keyword at all.
//!
//! The same evasions hide a SIN, an ABA routing number or an IBAN just as
//! well. The variants built here drop the card-length assumption and accept
//! alphanumeric values, so they are only ever offered to the scanner's
//! check-digit route: a match on one of them needs both a real check digit
//! and a context keyword beside it. Every variant is the input with one span
//! rewritten in place, so a keyword next to the evaded value is still next to
//! the recovered one.

use base64::{engine::general_purpose::STANDARD, Engine};

/// Most variants any one helper may contribute. The alt pass re-normalizes
/// and re-scans each, so the fan-out on adversarial input must stay bounded.
const MAX_VARIANTS_PER_HELPER: usize = 16;

/// Shortest value worth recovering: a 6-character identifier is already at
/// the edge of what a check digit can tell apart from noise.
const MIN_VALUE_LEN: usize = 6;

/// Longest value worth recovering: an IBAN tops out at 34 characters.
const MAX_VALUE_LEN: usize = 34;

/// Characters a recovered identifier may consist of once decoded. Separators
/// inside a value (`742-18-5503`, `130 692 544`) are kept, since the alt text
/// is re-normalized before matching and normalization strips them there.
fn is_value_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b' ' || b == b'.'
}

/// Copy of `text` with `text[start..end]` replaced by `with`.
fn splice(text: &str, start: usize, end: usize, with: &str) -> String {
    let mut out = String::with_capacity(text.len() + with.len());
    out.push_str(&text[..start]);
    out.push_str(with);
    out.push_str(&text[end..]);
    out
}

/// Byte ranges of maximal runs whose bytes satisfy `pred`.
fn runs(text: &str, pred: impl Fn(u8) -> bool) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !pred(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && pred(bytes[i]) {
            i += 1;
        }
        out.push((start, i));
    }
    out
}

fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Decode standard base64 into an identifier-shaped string, or nothing.
fn decode_b64_value(s: &str) -> Option<String> {
    if s.len() < 4 || !s.len().is_multiple_of(4) {
        return None;
    }
    let raw = STANDARD.decode(s).ok()?;
    if raw.is_empty() || !raw.iter().copied().all(is_value_byte) {
        return None;
    }
    // At least one alphanumeric: a decode to all separators carries nothing.
    if !raw.iter().any(u8::is_ascii_alphanumeric) {
        return None;
    }
    String::from_utf8(raw).ok()
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

/// Strip zero padding from either end of a digit run, one zero at a time.
///
/// The card helper trims only to a fixed list of card/SSN lengths, which
/// misses a 9-digit routing number or an IBAN's 20-digit body. Here every
/// trim from one up to the padding length is offered; the check digit picks
/// the right one. A run of zeros glued to the front of a letter-led value
/// (`00000GB82WEST…`) is padding of the same kind and is removed outright.
fn strip_zero_padding(text: &str) -> Vec<(String, bool)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (start, end) in runs(text, |b| b.is_ascii_digit()) {
        let run = &text[start..end];
        let lead = run.bytes().take_while(|&b| b == b'0').count();
        let trail = run.bytes().rev().take_while(|&b| b == b'0').count();
        let glued_before_letter = end < bytes.len() && bytes[end].is_ascii_alphabetic();
        let free_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();

        if lead == run.len() {
            // All zeros: padding only when it is glued to a following value.
            if lead >= 3 && glued_before_letter && free_before {
                out.push((splice(text, start, end, ""), true));
            }
            continue;
        }
        // Padding sits at the edge of a value. A short run is ordinary text
        // (`fe80::1` is not a padded `fe8`), and zeros with a letter on their
        // outer side are inside a token (`N0003062517` is not a padded
        // `N3062517`). One or two trailing zeros are how numbers end, so a
        // strip only counts as exact once it removes three or more.
        if !(8..=48).contains(&run.len()) {
            continue;
        }
        let free_after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if free_before {
            for k in 1..=lead.min(12) {
                out.push((splice(text, start, start + k, ""), k == lead && k >= 3));
            }
        }
        if free_after {
            for k in 1..=trail.min(12) {
                out.push((splice(text, end - k, end, ""), k == trail && k >= 3));
            }
        }
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out.truncate(MAX_VARIANTS_PER_HELPER);
    out
}

/// Separate a digit block from letters glued on either side.
///
/// `XXXXXXXXXX130692544XXXXXXXXXX` keeps the SIN inside one word, so no `\b`
/// falls at its edges. The card helper does the same for 13–19 digits only.
fn isolate_letter_bounded_digits(text: &str) -> Vec<(String, bool)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (start, end) in runs(text, |b| b.is_ascii_digit()) {
        if !(MIN_VALUE_LEN..=MAX_VALUE_LEN).contains(&(end - start)) {
            continue;
        }
        let letter_before = start > 0 && bytes[start - 1].is_ascii_alphabetic();
        let letter_after = end < bytes.len() && bytes[end].is_ascii_alphabetic();
        if !letter_before && !letter_after {
            continue;
        }
        out.push((
            splice(text, start, end, &format!(" {} ", &text[start..end])),
            true,
        ));
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out
}

/// Strip a run of one repeated letter padding an alphanumeric value.
///
/// Digit blocks are separated from letter padding above, but an ISIN, CUSIP,
/// LEI or IBAN is itself made of letters, so `XXXXXXXXXXUS0378331005XXXXXXXXXX`
/// has no digit/letter edge at the value's boundary. Padding of one repeated
/// letter does mark it, though: four or more of the same letter is not how
/// any of these identifiers begin or end. The run is removed whole and also
/// with one letter left behind, in case the value starts or ends with the
/// padding letter itself.
fn strip_repeated_letter_padding(text: &str) -> Vec<(String, bool)> {
    const MIN_PAD: usize = 4;
    let mut out = Vec::new();
    for (start, end) in runs(text, |b| b.is_ascii_alphanumeric()) {
        let token = &text.as_bytes()[start..end];
        let pad_len = |it: &mut dyn Iterator<Item = &u8>, first: u8| {
            it.take_while(|&&b| b.eq_ignore_ascii_case(&first)).count()
        };
        let lead = if token[0].is_ascii_alphabetic() {
            pad_len(&mut token.iter(), token[0])
        } else {
            0
        };
        let last = token[token.len() - 1];
        let trail = if last.is_ascii_alphabetic() {
            pad_len(&mut token.iter().rev(), last)
        } else {
            0
        };
        if (lead < MIN_PAD && trail < MIN_PAD) || lead + trail >= token.len() {
            continue;
        }
        let leads: &[usize] = if lead >= MIN_PAD {
            &[lead, lead - 1]
        } else {
            &[0]
        };
        let trails: &[usize] = if trail >= MIN_PAD {
            &[trail, trail - 1]
        } else {
            &[0]
        };
        for &l in leads {
            for &t in trails {
                let inner = &text[start + l..end - t];
                if (MIN_VALUE_LEN..=MAX_VALUE_LEN).contains(&inner.len()) {
                    // Only the whole-run strip is one candidate per value;
                    // leaving a letter behind is a second guess.
                    let exact = (l == lead || lead < MIN_PAD) && (t == trail || trail < MIN_PAD);
                    out.push((splice(text, start, end, &format!(" {inner} ")), exact));
                }
            }
        }
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out.truncate(MAX_VARIANTS_PER_HELPER);
    out
}

/// Decode a base64 tail that follows a plaintext head in the same token.
///
/// `base64_partial` writes the first few characters in clear and encodes the
/// rest: `130 6` + base64(`92 544`), or `GB82WEST123` + base64(`45698765432`).
/// The card helper needs an all-digit head. Here any suffix of the token whose
/// length is a multiple of four is tried, longest first, and the first that
/// decodes to identifier characters replaces itself in place. The head may
/// also sit in an earlier token (`130 6OTIg…` splits at the space), which
/// needs nothing special: only the tail is rewritten.
fn decode_base64_tails(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (start, end) in runs(text, is_b64_byte) {
        let token = &text[start..end];
        if token.len() < 8 || token.len() > 96 {
            continue;
        }
        // Longest first: a shorter suffix of a real tail usually decodes too
        // (any 4-symbol block is a whole number of bytes) and would leave
        // part of the encoding behind.
        let first_split = token.len() % 4;
        for split in (first_split..token.len().saturating_sub(7)).step_by(4) {
            let tail = &token[split..];
            // A '=' may only end the token, which the full-token decode
            // below already rejects if misplaced; skip heads ending in '='.
            if token[..split].contains('=') {
                continue;
            }
            if let Some(decoded) = decode_b64_value(tail) {
                // split == 0 is a whole-token decode; stage 4c owns that.
                if split > 0 {
                    out.push((splice(text, start + split, end, &decoded), true));
                }
                break;
            }
        }
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out
}

/// Undo rot13 applied on top of base64, one token at a time.
///
/// The card path rotates the whole input, which also rotates every keyword
/// beside the value (`Social insurance number` → `Fbpvny vafhenapr ahzore`).
/// That is harmless for a pattern that needs no keyword and fatal for one
/// that does. Here only a token whose rotation decodes to an identifier is
/// rewritten.
fn decode_rot13_base64_tokens(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (start, end) in runs(text, is_b64_byte) {
        let token = &text[start..end];
        if token.len() < 8 || token.len() > 96 {
            continue;
        }
        if let Some(decoded) = decode_b64_value(&rot13(token)) {
            out.push((splice(text, start, end, &decoded), true));
        }
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out
}

/// Rejoin a value split across indexed fields of one record.
///
/// `{"part1": "130 6", "part2": "92 544"}` — the card helper joins digit-only
/// values to a card length and hands back the joined value alone, which
/// drops the keyword in front of the record. Here alphanumeric values are
/// joined at any identifier length, and the whole run of fields is rewritten
/// in place so the record's surroundings survive.
fn join_indexed_fields(text: &str) -> Vec<(String, bool)> {
    // (stem, index, value, span of the `"key": "value"` pair)
    let mut fields: Vec<(&str, u32, &str, (usize, usize))> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let key_start = i + 1;
        let Some(key_len) = text[key_start..].find('"') else {
            break;
        };
        let key = &text[key_start..key_start + key_len];
        let mut j = key_start + key_len + 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            i = key_start + key_len + 1;
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'"' {
            i = j;
            continue;
        }
        let val_start = j + 1;
        let Some(val_len) = text[val_start..].find('"') else {
            break;
        };
        let value = &text[val_start..val_start + val_len];
        let pair_end = val_start + val_len + 1;
        i = pair_end;

        let stem = key.trim_end_matches(|c: char| c.is_ascii_digit());
        let idx = &key[stem.len()..];
        if stem.is_empty()
            || idx.is_empty()
            || idx.len() > 2
            || !(1..=MAX_VALUE_LEN).contains(&value.len())
            || !value.bytes().all(is_value_byte)
        {
            continue;
        }
        if let Ok(n) = idx.parse::<u32>() {
            fields.push((stem, n, value, (key_start - 1, pair_end)));
        }
    }

    let mut out = Vec::new();
    for w in 0..fields.len() {
        let mut joined = String::from(fields[w].2);
        for k in w + 1..fields.len().min(w + 4) {
            let (prev, cur) = (fields[k - 1], fields[k]);
            if cur.0 != prev.0 || cur.1 != prev.1 + 1 {
                break;
            }
            joined.push_str(cur.2);
            let compact = joined.bytes().filter(u8::is_ascii_alphanumeric).count();
            if (MIN_VALUE_LEN..=MAX_VALUE_LEN).contains(&compact) {
                out.push((splice(text, fields[w].3 .0, cur.3 .1, &joined), true));
            }
        }
        if out.len() >= MAX_VARIANTS_PER_HELPER {
            break;
        }
    }
    out
}

/// A recovery helper: each variant with whether it is exact.
type Helper = fn(&str) -> Vec<(String, bool)>;

/// One recovered alternative: the input with an evaded value restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub text: String,
    /// The only candidate this recovery offers for the value it restored —
    /// all of the padding stripped, the whole base64 tail decoded — rather
    /// than one of several guesses (a zero trimmed at a time). Inexact
    /// recoveries rely on a check digit to pick the right guess; an exact one
    /// stands where the evaded value stood, so a rule may hold it to the bar
    /// it holds a plainly written value to.
    pub exact: bool,
}

/// Alternatives for the scanner's keyword-backed routes only.
///
/// Each is the input with one evaded value recovered in place. The scanner
/// must not run keyword-free patterns over these (mod-97 aside): they relax
/// the card-length bounds that make the keyword-free alternatives safe.
pub fn generate_keyword_gated_recoveries(text: &str) -> Vec<Recovery> {
    let mut out: Vec<Recovery> = Vec::new();
    let helpers: [Helper; 6] = [
        strip_zero_padding,
        isolate_letter_bounded_digits,
        strip_repeated_letter_padding,
        decode_base64_tails,
        decode_rot13_base64_tokens,
        join_indexed_fields,
    ];
    for helper in helpers {
        for (v, exact) in helper(text) {
            if v == text {
                continue;
            }
            match out.iter_mut().find(|r| r.text == v) {
                // Two helpers reached the same text; exact if either was.
                Some(seen) => seen.exact |= exact,
                None => out.push(Recovery { text: v, exact }),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovers(input: &str, needle: &str) -> bool {
        generate_keyword_gated_recoveries(input)
            .iter()
            .any(|v| v.text.contains(needle))
    }

    #[test]
    fn zero_padding_any_length() {
        assert!(recovers("routing 0000021000021 ok", " 021000021 ok"));
        assert!(recovers(
            "iban DE893704004405320130000000 x",
            "DE89370400440532013000 x"
        ));
        assert!(recovers(
            "iban 00000GB82WEST12345698765432.",
            "iban GB82WEST"
        ));
    }

    #[test]
    fn only_the_full_strip_is_exact() {
        let v = generate_keyword_gated_recoveries("SSN 00000742185503 ok");
        let exact: Vec<&str> = v
            .iter()
            .filter(|r| r.exact)
            .map(|r| r.text.as_str())
            .collect();
        assert_eq!(exact, ["SSN 742185503 ok"], "{v:?}");
        assert!(v.iter().any(|r| !r.exact && r.text == "SSN 0742185503 ok"));
    }

    #[test]
    fn letter_glued_short_ids() {
        assert!(recovers(
            "SIN XXXXXXXXXX130692544XXXXXXXXXX ok",
            " 130692544 "
        ));
    }

    #[test]
    fn repeated_letter_padding_around_alnum_ids() {
        assert!(recovers(
            "ISIN XXXXXXXXXXUS0378331005XXXXXXXXXX: split",
            " US0378331005 :"
        ));
        // The value ends in the padding letter: keep one back.
        assert!(recovers("id XXXXAB12CDXXXXX ok", " AB12CDX "));
        // An ordinary word is not padding.
        assert!(generate_keyword_gated_recoveries("the bookkeeper").is_empty());
    }

    #[test]
    fn base64_tail_after_any_head() {
        // 130 6 + base64("92 544")
        assert!(recovers("SIN 130 6OTIgNTQ0 ok", "130 692 544 ok"));
        // GB82WEST123 + base64("45698765432")
        assert!(recovers(
            "account GB82WEST123NDU2OTg3NjU0MzI=.",
            "GB82WEST12345698765432."
        ));
    }

    #[test]
    fn rot13_base64_token_keeps_keyword() {
        // rot13(base64("130 692 544"))
        let v = generate_keyword_gated_recoveries("Social insurance number ZGZjVQL5ZvN1AQD= ok");
        assert!(
            v.iter()
                .any(|s| s.exact && s.text == "Social insurance number 130 692 544 ok"),
            "{v:?}"
        );
    }

    #[test]
    fn json_split_keeps_surroundings() {
        let v = generate_keyword_gated_recoveries(
            r#"Social insurance number {"part1": "130 6", "part2": "92 544"} ok"#,
        );
        assert!(
            v.iter()
                .any(|s| s.exact && s.text == "Social insurance number {130 692 544} ok"),
            "{v:?}"
        );
    }

    #[test]
    fn unrelated_fields_are_not_joined() {
        let v = generate_keyword_gated_recoveries(r#"{"zip": "12345", "phone": "5551234"}"#);
        assert!(v.is_empty(), "{v:?}");
    }
}
