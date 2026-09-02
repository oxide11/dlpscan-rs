//! Detection baselines against real public-record documents.
//!
//! Everything else in `tests/` checks the scanner against fixtures we wrote,
//! which can only confirm what we already thought to encode. These three files
//! are documents other people wrote — legislative directories of elected
//! representatives, committed under the official public records exemption in
//! `FUTURE.md`. See `corpus/public_records/PROVENANCE.md`.
//!
//! The numbers below are **descriptive, not aspirational**. Several of them
//! record bugs, and are asserted as ranges around today's behaviour so the
//! defects cannot silently get worse while a fix is pending. A test here
//! failing because detection *improved* is good news: re-derive the baseline
//! and raise it in the same commit that earned it.
//!
//! Ground truth is derived independently, by scanning the file with a plain
//! regex for the shape in question, so it does not inherit any assumption from
//! the scanner under test.

use siphon::{scan_text, ScanConfig};
use std::path::PathBuf;

fn corpus(name: &str) -> String {
    let p: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "corpus",
        "public_records",
        name,
    ]
    .iter()
    .collect();
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// Count non-overlapping occurrences of a simple shape, left to right.
fn count_shape(hay: &str, is_match: impl Fn(&[u8]) -> bool, width: usize) -> usize {
    let b = hay.as_bytes();
    let (mut i, mut n) = (0usize, 0usize);
    while i + width <= b.len() {
        if is_match(&b[i..i + width]) {
            n += 1;
            i += width;
        } else {
            i += 1;
        }
    }
    n
}

/// `NNN-NNN-NNNN`, not adjacent to another digit.
fn is_dashed_phone(w: &[u8]) -> bool {
    w.len() == 12
        && w[..3].iter().all(u8::is_ascii_digit)
        && w[3] == b'-'
        && w[4..7].iter().all(u8::is_ascii_digit)
        && w[7] == b'-'
        && w[8..].iter().all(u8::is_ascii_digit)
}

fn found(matches: &[siphon::Match], sub: &str) -> usize {
    matches.iter().filter(|m| m.sub_category == sub).count()
}

// ---------------------------------------------------------------------------
// Canada — House of Commons member addresses
// ---------------------------------------------------------------------------

/// 1,306 telephone numbers across 35 area codes. Phone recall sits at ~87%;
/// the shortfall is normalization fusing a number with whatever digits follow
/// it (`"...8490 417"` collapses to one 13-digit run that matches nothing).
#[test]
fn canada_mp_addresses_phone_recall() {
    let text = corpus("ca_mp_addresses.txt");
    let truth = count_shape(&text, is_dashed_phone, 12);
    assert!(
        truth > 1_200,
        "corpus changed: expected >1200 dashed phone numbers, found {truth}"
    );

    let m = scan_text(&text).unwrap();
    let hits = found(&m, "US Phone Number");
    let recall = hits as f64 / truth as f64;

    // Baseline 2026-09-02: 1141/1306 = 87.4%.
    assert!(
        (0.80..=1.0).contains(&recall),
        "phone recall {recall:.3} ({hits}/{truth}) outside the pinned band; \
         if this rose, re-derive the baseline and raise the floor"
    );
}

/// 408 Canadian postal codes in rendered address blocks.
///
/// This test previously asserted that the scanner found **none** of them.
/// `Canada Postal Code` declares `context_required: false`, but its specificity
/// (0.75) sat below the 0.85 always-run threshold, so the Aho-Corasick
/// prefilter keyword-gated it regardless — and an address block as a human
/// writes it ("Edmonton, Alberta / T5A 1B7") carries no keyword, so the pattern
/// never ran. `uk_mps_postcode_recall` scored 100% on the same class of data
/// purely because its CSV has a `Postcode` column header.
///
/// Promoting both postal patterns to always-run fixed it: 0 -> 404 of 408, with
/// no regression in any other suite and no change to the false-positive counts
/// below. The assertion is now recall, as the old failure message instructed.
#[test]
fn canada_mp_addresses_postal_code_recall() {
    let text = corpus("ca_mp_addresses.txt");
    let truth = count_shape(
        &text,
        |w| {
            w[0].is_ascii_uppercase()
                && w[1].is_ascii_digit()
                && w[2].is_ascii_uppercase()
                && w[3] == b' '
                && w[4].is_ascii_digit()
                && w[5].is_ascii_uppercase()
                && w[6].is_ascii_digit()
        },
        7,
    );
    assert!(
        truth > 380,
        "corpus changed: expected >380 postal codes, found {truth}"
    );

    let m = scan_text(&text).unwrap();
    let hits = found(&m, "Canada Postal Code");
    let recall = hits as f64 / truth as f64;

    // Baseline 2026-09-02, after the always-run promotion: 404/408 = 99.0%.
    assert!(
        recall >= 0.95,
        "Canada postal recall fell to {recall:.3} ({hits}/{truth}); the \
         always-run promotion may have been reverted"
    );
}

/// The same fusing that hides phone numbers also manufactures findings: a
/// number joined across a line break to the next one yields digit runs long
/// enough to satisfy card and national-ID patterns. Roughly 250 such matches
/// appear on a document that contains no identifiers at all.
#[test]
fn canada_mp_addresses_false_positive_ceiling() {
    let text = corpus("ca_mp_addresses.txt");
    let m = scan_text(&text).unwrap();

    // Nothing in a legislative contact directory is a payment card.
    let pans = found(&m, "PAN");
    assert!(
        pans <= 12,
        "PAN false positives rose to {pans} (baseline 8) on a contact directory"
    );

    // The false-positive surface: everything that is neither a phone number nor
    // a postal code, both of which this document genuinely contains.
    //
    // Postal codes were excluded from this count on 2026-09-02. Before the
    // always-run promotion they were undetected, so "not a phone number" was a
    // serviceable proxy for "wrong"; afterwards the 404 correctly-found postal
    // codes pushed it from 269 to 673 and the proxy stopped meaning anything.
    let expected = found(&m, "US Phone Number") + found(&m, "Canada Postal Code");
    let false_surface = m.len() - expected;
    assert!(
        false_surface <= 320,
        "spurious findings rose to {false_surface} (baseline ~269); the \
         false-positive surface on benign public data is growing"
    );
}

// ---------------------------------------------------------------------------
// UK — Parliament members CSV (the control)
// ---------------------------------------------------------------------------

/// 649 postcodes, all detected — but only because the CSV carries a `Postcode`
/// column header supplying the keyword the prefilter demands. This is the
/// counterexample that isolates the gating defect: identical pattern class to
/// the Canadian file, opposite result, and the sole difference is a header.
#[test]
fn uk_mps_postcode_recall() {
    let text = corpus("uk_mps.csv");
    let m = scan_text(&text).unwrap();
    let hits = found(&m, "UK Postcode");

    // Baseline 2026-09-02: 649/649.
    assert!(
        hits >= 600,
        "UK postcode detections fell to {hits} (baseline 649)"
    );
}

/// 643 official parliamentary email addresses, all detected. Email is
/// always-run, so unlike the postcodes it does not depend on a helpful header.
#[test]
fn uk_mps_email_recall() {
    let text = corpus("uk_mps.csv");
    let m = scan_text(&text).unwrap();
    let hits = found(&m, "Email Address");

    // Baseline 2026-09-02: 643/643.
    assert!(
        hits >= 600,
        "email detections fell to {hits} (baseline 643)"
    );
}

/// A contact directory should not look like a breach dump. Pins the overall
/// shape of what is found so a future pattern addition that fires broadly on
/// names, constituencies or parliamentary emails shows up here.
#[test]
fn uk_mps_no_spurious_identifier_findings() {
    let text = corpus("uk_mps.csv");
    let cfg = ScanConfig {
        min_confidence: 0.5,
        ..Default::default()
    };
    let m = siphon::scanner::scan_text_with_config(&text, &cfg).unwrap();

    let unexpected: Vec<&str> = m
        .iter()
        .map(|x| x.sub_category.as_str())
        .filter(|s| !matches!(*s, "UK Postcode" | "Email Address"))
        .collect();

    assert!(
        unexpected.len() <= 40,
        "{} unexpected findings on the UK directory, e.g. {:?}",
        unexpected.len(),
        &unexpected[..unexpected.len().min(8)]
    );
}

// ---------------------------------------------------------------------------
// Negative controls
// ---------------------------------------------------------------------------

/// Near-miss strings that look like contact data and are not. Supplied with the
/// public-records corpus build as deliberate false-positive traps.
///
/// Two are known to still fire and are listed as such rather than quietly
/// excluded: a dotted version string that satisfies the British NHS pattern,
/// and a bare ten-digit checksum that satisfies US Phone Number. Both predate
/// the postal work and neither has a fix yet; pinning the count stops the set
/// from growing unnoticed.
#[test]
fn negative_controls_do_not_fire() {
    let cases: &[(&str, &str)] = &[
        ("NEG001", "Build 2026.09.02 completed in 613 ms."),
        ("NEG002", "Release candidate AB1-2CD passed 416 checks."),
        ("NEG003", "Service returned HTTP 404 from node 10.0.0.8."),
        ("NEG004", "Ticket K1A-0A6-DEV is assigned to queue PARL."),
        (
            "NEG005",
            "Version 514.398.6400 is not a telephone number in this context.",
        ),
        (
            "NEG006",
            "Use placeholder user@example.invalid in documentation.",
        ),
        (
            "NEG007",
            "The string Jane Doe is a generic placeholder, not a director.",
        ),
        ("NEG008", "Checksum 6139920946 failed validation."),
    ];
    // Known-firing controls, with the pattern each currently trips.
    const KNOWN_FIRING: &[&str] = &["NEG005", "NEG008"];

    let mut unexpected = Vec::new();
    for (id, text) in cases {
        let n = scan_text(text).unwrap().len();
        let expected_to_fire = KNOWN_FIRING.contains(id);
        if n > 0 && !expected_to_fire {
            unexpected.push(format!("{id} fired {n} time(s): {text}"));
        }
        if n == 0 && expected_to_fire {
            unexpected.push(format!(
                "{id} no longer fires — a false positive was fixed; \
                 remove it from KNOWN_FIRING"
            ));
        }
    }
    assert!(unexpected.is_empty(), "{unexpected:#?}");
}

/// NEG002 specifically: `AB1-2CD` is a product code whose ROT13 image
/// (`NO12PQ`) is a structurally valid UK postcode. It fired once UK Postcode
/// became always-run, because the alt-decoding pass had no specificity floor.
/// Regression guard for that floor.
#[test]
fn rot13_alt_decoding_does_not_manufacture_postcodes() {
    let m = scan_text("Release candidate AB1-2CD passed 416 checks.").unwrap();
    assert!(
        !m.iter().any(|x| x.sub_category == "UK Postcode"),
        "ROT13 alt-decoding produced a postcode from a product code: {:?}",
        m.iter()
            .map(|x| (&x.sub_category, &x.text))
            .collect::<Vec<_>>()
    );
}
