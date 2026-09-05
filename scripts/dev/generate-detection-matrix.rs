//! Generator for `src/conformance/detections_data.rs`.
//!
//! Kept here rather than in `tests/` because it is not part of the suite and
//! its two dependencies are not part of the project. Producing the matrix
//! needs `rand_regex` and `regex-syntax`; *using* it needs neither, and a
//! scanner should not carry a regex fuzzer in its lockfile for the sake of a
//! table that is regenerated when the patterns change.
//!
//! To run it:
//!
//! ```bash
//! cargo add --dev rand_regex regex-syntax
//! cp scripts/dev/generate-detection-matrix.rs tests/gen_matrix.rs
//! cargo test --features conformance --test gen_matrix -- --nocapture
//! rm tests/gen_matrix.rs && cargo remove --dev rand_regex regex-syntax
//! ```
//!
//! It writes the whole table — cases and diagnoses — and verifies every case
//! against the real scanner before emitting it. A slot that cannot be made to
//! behave is carried as a declared gap with the reason, never dropped.
//!
//! # After regenerating
//!
//! Split every case literal in two before committing, or GitHub push
//! protection will refuse the push: some of these patterns detect
//! credentials, so some of these cases are shaped exactly like credentials.
//! `concat!` is expanded at compile time, so the scanner under test still
//! sees the whole value — see the header of the generated file, which
//! explains the split and where the split point may fall.

#![cfg(feature = "conformance")]

use rand::distr::Distribution;
use rand::SeedableRng;
use siphon_core::context::CONTEXT_KEYWORDS;
use siphon_core::patterns::PATTERNS;
use siphon_core::scanner::{scan_text_with_config, ScanConfig};

/// Strip constructs `rand_regex` cannot sample from, and pin the shorthand
/// classes to ASCII.
///
/// Two jobs. Anchors and look-arounds constrain *where* a match may sit
/// rather than what it looks like, so dropping them widens the generated
/// language without changing its shape.
///
/// The second job matters more. `\d` in Unicode mode is every decimal digit
/// in Unicode, so a sampler asked for `4\d{3}` cheerfully returns
/// "4꤆۳౮" — a perfectly valid match for the pattern, and useless as a
/// seed, because no real card number is written in Devanagari. Rewriting the
/// shorthands to their ASCII ranges keeps the generated values in the
/// alphabet the pattern is actually about, while leaving explicit Unicode
/// literals like `\x{2013}` in separator classes untouched.
///
/// Anything this mangles simply fails verification, and costs nothing — the
/// real scanner is the judge, not this function.
fn samplable(re: &str) -> String {
    // (outside a class, inside a class)
    fn shorthand(c: u8) -> Option<(&'static str, &'static str)> {
        match c {
            b'd' => Some(("[0-9]", "0-9")),
            b'w' => Some(("[A-Za-z0-9_]", "A-Za-z0-9_")),
            b's' => Some((r"[ \t]", r" \t")),
            _ => None,
        }
    }

    let mut out = String::with_capacity(re.len());
    let b = re.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // Look-around groups: (?= (?! (?<= (?<!
        if b[i] == b'(' && i + 2 < b.len() && b[i + 1] == b'?' {
            let rest = &re[i..];
            if rest.starts_with("(?=")
                || rest.starts_with("(?!")
                || rest.starts_with("(?<=")
                || rest.starts_with("(?<!")
            {
                let mut depth = 0;
                let mut j = i;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j + 1;
                continue;
            }
        }

        if b[i] == b'\\' && i + 1 < b.len() {
            let n = b[i + 1];
            if n == b'b' || n == b'B' || n == b'A' || n == b'z' {
                i += 2; // word / text boundary: position, not content
                continue;
            }
            if let Some((outside, _)) = shorthand(n) {
                out.push_str(outside);
                i += 2;
                continue;
            }
            out.push('\\');
            out.push(n as char);
            i += 2;
            continue;
        }

        if b[i] == b'^' || b[i] == b'$' {
            i += 1;
            continue;
        }

        if b[i] == b'[' {
            // Copy the class, rewriting shorthands inside it.
            out.push('[');
            let mut j = i + 1;
            if j < b.len() && b[j] == b'^' {
                out.push('^');
                j += 1;
            }
            if j < b.len() && b[j] == b']' {
                out.push(']');
                j += 1;
            }
            while j < b.len() && b[j] != b']' {
                if b[j] == b'\\' && j + 1 < b.len() {
                    if let Some((_, inside)) = shorthand(b[j + 1]) {
                        out.push_str(inside);
                    } else {
                        out.push('\\');
                        out.push(b[j + 1] as char);
                    }
                    j += 2;
                    continue;
                }
                let ch = re[j..].chars().next().unwrap();
                out.push(ch);
                j += ch.len_utf8();
            }
            out.push(']');
            i = j + 1;
            continue;
        }

        let ch = re[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A context keyword for this pattern, if it has one.
fn keyword_for(category: &str, sub_category: &str) -> Option<&'static str> {
    CONTEXT_KEYWORDS
        .iter()
        .find(|(c, s, _)| *c == category && *s == sub_category)
        .and_then(|(_, _, e)| e.keywords.first().copied())
        .or_else(|| {
            CONTEXT_KEYWORDS
                .iter()
                .find(|(c, _, _)| *c == category)
                .and_then(|(_, _, e)| e.keywords.first().copied())
        })
}

/// Wrap a candidate value in the smallest text that gives the pattern a fair
/// chance: a context keyword when one exists, because a context-gated pattern
/// is *supposed* to stay quiet without one.
fn probe(kw: Option<&str>, value: &str) -> String {
    match kw {
        Some(k) => format!("{k}: {value}"),
        None => format!("Reference {value} on file"),
    }
}

fn fires(text: &str, sub_category: &str, value: &str) -> bool {
    let cfg = ScanConfig {
        min_confidence: 0.0,
        ..Default::default()
    };
    match scan_text_with_config(text, &cfg) {
        Ok(ms) => ms
            .iter()
            .any(|m| m.sub_category == sub_category && (m.text.contains(value) || value.contains(&m.text))),
        Err(_) => false,
    }
}

/// Values from the hand-labelled corpus in `tests/corpus/`.
///
/// Tried before generation, because these are the hard ones. A Base58Check
/// bitcoin address carries a SHA-256 checksum over its own payload, so the
/// chance of sampling a valid one from the regex is nil; an IBAN needs
/// mod-97 to land *and* a real country code. Somebody already worked these
/// out and wrote them down — the generator's job is the long tail, not the
/// cases a human has already verified.
fn corpus_seeds() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(raw) = std::fs::read_to_string("tests/corpus/labels.jsonl") else {
        return out;
    };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(exp) = v.get("expected").and_then(|e| e.as_array()) else {
            continue;
        };
        for e in exp {
            let (Some(sub), Some(text)) = (
                e.get("sub_category").and_then(|x| x.as_str()),
                e.get("text").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            out.entry(sub.to_string()).or_insert_with(|| text.to_string());
        }
    }
    out
}


/// Does this sub_category fire anywhere in `text`, regardless of value?
fn fires_any(text: &str, sub_category: &str) -> bool {
    let cfg = ScanConfig {
        min_confidence: 0.0,
        ..Default::default()
    };
    match scan_text_with_config(text, &cfg) {
        Ok(ms) => ms.iter().any(|m| m.sub_category == sub_category),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Case construction
// ---------------------------------------------------------------------------

const PROSE: &str = "Quarterly planning notes. The team agreed to move the \
retrospective to Thursday and to close the remaining documentation tasks \
before the end of the sprint. Nothing in this paragraph is a customer record.";

/// The value sitting where a real document would put it.
fn structural(kw: Option<&str>, value: &str) -> String {
    format!(
        "INTERNAL MEMO\nRe: account review\n\n{PROSE}\n\nOn file:\n  {}: {value}\n\nEnd of memo.\n",
        kw.unwrap_or("reference")
    )
}

/// Mutations tried, in order, until one stops the pattern firing.
///
/// A near-miss is what separates a pattern that checks substance from one
/// that only checks shape. For a checksummed identifier, changing one
/// character is enough; for a fixed-width one, dropping a character is. A
/// pattern for which none of these works matches anything of roughly the
/// right shape, which is worth knowing.
fn near_misses(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > 1 {
        out.push(chars[..chars.len() - 1].iter().collect());
        out.push(chars[1..].iter().collect());
    }
    // Bump the last alphanumeric — breaks a checksum, keeps the shape.
    if let Some(pos) = chars.iter().rposition(|c| c.is_ascii_alphanumeric()) {
        let c = chars[pos];
        let swapped = if c.is_ascii_digit() {
            if c == '0' { '7' } else { char::from_digit((c.to_digit(10).unwrap() + 5) % 10, 10).unwrap() }
        } else if c.is_ascii_uppercase() {
            if c == 'A' { 'Q' } else { 'A' }
        } else if c == 'a' { 'q' } else { 'a' };
        let mut m = chars.clone();
        m[pos] = swapped;
        out.push(m.into_iter().collect());
    }
    // Lengthen it past its own shape.
    out.push(format!("{value}7"));
    out
}

/// Transformations tried, in order, until one still fires.
///
/// Each is something the normalizer is supposed to undo, so a value wearing
/// one should still be found. Where none works, the pattern is reachable
/// only in its literal form — a bypass shape worth recording.
fn evasions(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > 3 {
        let mid = chars.len() / 2;
        // Zero-width space through the middle.
        let mut z: String = chars[..mid].iter().collect();
        z.push('\u{200B}');
        z.extend(chars[mid..].iter());
        out.push(z);
    }
    // Full-width digits.
    if value.chars().any(|c| c.is_ascii_digit()) {
        out.push(
            value
                .chars()
                .map(|c| {
                    if c.is_ascii_digit() {
                        char::from_u32(c as u32 - '0' as u32 + 0xFF10).unwrap()
                    } else {
                        c
                    }
                })
                .collect(),
        );
    }
    // HTML numeric entities.
    out.push(value.chars().map(|c| format!("&#{};", c as u32)).collect());
    out
}

/// Emit a Rust string literal.
fn lit(s: &str) -> String {
    format!("{s:?}")
}

#[test]
fn generate_matrix() {
    let corpus = corpus_seeds();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5117_00_5EED_u64);

    let mut rows: Vec<String> = Vec::new();
    let mut unseeded: Vec<String> = Vec::new();
    let mut seeded = 0usize;
    let mut from_corpus = 0usize;
    let mut gaps: std::collections::BTreeMap<&str, usize> = Default::default();

    for pat in PATTERNS.iter() {
        let kw = keyword_for(pat.category, pat.sub_category);

        // --- seed -----------------------------------------------------------
        let mut value: Option<String> = None;
        if let Some(v) = corpus.get(pat.sub_category) {
            if fires(&probe(kw, v), pat.sub_category, v) {
                value = Some(v.clone());
                from_corpus += 1;
            }
        }
        if value.is_none() {
            let src = samplable(pat.regex);
            if let Ok(hir) = regex_syntax::ParserBuilder::new()
                .case_insensitive(pat.case_insensitive)
                .build()
                .parse(&src)
            {
                if let Ok(g) = rand_regex::Regex::with_hir(hir, 8) {
                    for _ in 0..3000 {
                        let cand: String = g.sample(&mut rng);
                        if cand.trim().is_empty() || cand.len() > 120 || !cand.is_ascii() {
                            continue;
                        }
                        if fires(&probe(kw, &cand), pat.sub_category, &cand) {
                            value = Some(cand);
                            break;
                        }
                    }
                }
            }
        }

        let Some(value) = value else {
            // Diagnose rather than just record the absence: an unobservable
            // pattern and an unsamplable one are different problems.
            let shape_twins = PATTERNS
                .iter()
                .filter(|q| q.regex == pat.regex && q.sub_category != pat.sub_category)
                .count();
            let reason = if shape_twins > 0 {
                format!(
                    "no value can be produced that this pattern wins: {shape_twins} other \
                     pattern(s) carry the identical regex, and deduplication keeps only one \
                     of them on any given span"
                )
            } else {
                "no candidate matching this regex was reported under this sub_category, in \
                 3000 samples and the labelled corpus"
                    .to_string()
            };
            unseeded.push(format!(
                "    ({}, {}, {}),",
                lit(pat.category),
                lit(pat.sub_category),
                lit(&reason)
            ));
            continue;
        };
        seeded += 1;

        let mut push = |slot: u8, text: String, fire: bool, gap: &str| {
            if !gap.is_empty() {
                *gaps.entry(match slot {
                    0 => "clean",
                    2 => "structural",
                    3 => "damaged",
                    _ => "evasive",
                })
                .or_default() += 1;
            }
            rows.push(format!(
                "    ({}, {}, {slot}, {}, {fire}, {}),",
                lit(pat.category),
                lit(pat.sub_category),
                lit(&text),
                lit(gap)
            ));
        };

        // --- slot 0: clean ---------------------------------------------------
        let clean_fires = fires_any(PROSE, pat.sub_category);
        push(
            0,
            PROSE.to_string(),
            false,
            if clean_fires {
                "this pattern fires on ordinary prose containing none of its values"
            } else {
                ""
            },
        );

        // --- slot 1: single --------------------------------------------------
        push(1, probe(kw, &value), true, "");

        // --- slot 2: structural ----------------------------------------------
        let doc = structural(kw, &value);
        let ok = fires(&doc, pat.sub_category, &value);
        push(
            2,
            doc,
            true,
            if ok { "" } else { "found alone, but not once surrounded by ordinary document text" },
        );

        // --- slot 3: damaged -------------------------------------------------
        //
        // The label has to go when the label itself trips the pattern. For a
        // phrase pattern like "Work Product" the probe's own prefix
        // ("work product: ") is a match, so a near miss carrying it fails for
        // a reason that has nothing to do with the mutation being tested.
        let dmg_kw = match kw {
            Some(k) if fires_any(&format!("{k}: "), pat.sub_category) => None,
            other => other,
        };
        // Checked with fires_any, not fires: the assertion this feeds is that
        // the sub_category does not appear *at all*, so the generator has to
        // hold itself to the same bar or it emits cases that cannot pass.
        let mut chosen = None;
        for m in near_misses(&value) {
            if m.trim().is_empty() {
                continue;
            }
            if !fires_any(&probe(dmg_kw, &m), pat.sub_category) {
                chosen = Some(m);
                break;
            }
        }
        match chosen {
            Some(m) => push(3, probe(dmg_kw, &m), false, ""),
            None => push(
                3,
                probe(dmg_kw, &format!("{value}7")),
                false,
                "no near miss could be constructed: every mutation tried still matched, so \
                 this pattern is checking shape and not substance",
            ),
        }

        // --- slot 4: evasive -------------------------------------------------
        let mut chosen = None;
        for e in evasions(&value) {
            if fires(&probe(kw, &e), pat.sub_category, &value) || fires(&probe(kw, &e), pat.sub_category, &e) {
                chosen = Some(e);
                break;
            }
        }
        match chosen {
            Some(e) => push(4, probe(kw, &e), true, ""),
            None => push(
                4,
                probe(kw, &evasions(&value).remove(0)),
                true,
                "no tested transformation survives normalization: zero-width insertion, \
                 full-width digits and HTML entities all stop this pattern firing",
            ),
        }
    }

    let total_gaps: usize = gaps.values().sum();
    eprintln!(
        "MATRIX: {seeded} of {} patterns seeded ({from_corpus} from the labelled corpus), \
         {} cases, {total_gaps} declared gaps",
        PATTERNS.len(),
        rows.len()
    );
    for (k, v) in &gaps {
        eprintln!("  gap[{k}] = {v}");
    }
    eprintln!("UNSEEDED: {}", unseeded.len());

    let body = format!(
        "//! Generated detection cases — DO NOT EDIT BY HAND.\n\
         //!\n\
         //! Five cases for every pattern that can be observed at all, built by\n\
         //! sampling each pattern's own regex (or taking a value from the\n\
         //! hand-labelled corpus in tests/corpus/) and keeping only what the real\n\
         //! scanner confirms. Regenerate with tests/zz_seedgen.rs — see git\n\
         //! history; it is not kept in the tree, because `rand_regex` is a\n\
         //! dependency for producing this file and not for using it.\n\
         //!\n\
         //! Note what this can and cannot catch. The positive slots are seeded\n\
         //! from the scanner's own behaviour, so they are a regression suite:\n\
         //! they pin today's answers and fail when those change. The negative\n\
         //! slots are not circular — a near miss is derived by mutating the\n\
         //! value, and asserting it stays quiet tests the pattern's substance\n\
         //! rather than its shape.\n\n\
         /// (category, sub_category, slot, text, expect_fire, gap_reason)\n\
         ///\n\
         /// Slots: 0 clean · 1 single · 2 structural · 3 damaged · 4 evasive.\n\
         /// An empty gap_reason means the case is enforced.\n\
         pub static DETECTIONS: &[(&str, &str, u8, &str, bool, &str)] = &[\n{}\n];\n\n\
         /// Patterns with no observable example, and why.\n\
         ///\n\
         /// Not a failure of the generator so much as a finding about the\n\
         /// pattern set: most of these carry a regex identical to a sibling's,\n\
         /// so deduplication means only one of them can ever be reported.\n\
         pub static UNSEEDED: &[(&str, &str, &str)] = &[\n{}\n];\n",
        rows.join("\n"),
        unseeded.join("\n")
    );
    let size = body.len();
    std::fs::write("src/conformance/detections_data.rs", body).unwrap();
    eprintln!("wrote src/conformance/detections_data.rs ({size} bytes)");
}
