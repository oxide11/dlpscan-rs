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

/// 408 Canadian postal codes, of which the scanner finds **none**.
///
/// `Canada Postal Code` declares `context_required: false`, but its specificity
/// (0.75) is below the 0.85 always-run threshold, so the Aho-Corasick prefilter
/// gates it on a keyword anyway. Address blocks as humans write them carry no
/// such keyword, so the pattern never runs. Compare `uk_mps_postcode_recall`,
/// where a CSV column header supplies one and recall is total.
///
/// This asserts the bug. When the gating is fixed, this test should fail.
#[test]
fn canada_mp_addresses_postal_codes_are_missed() {
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
    assert_eq!(
        found(&m, "Canada Postal Code"),
        0,
        "postal codes are now detected in a bare address block — the prefilter \
         gating described in FUTURE.md has changed. That is an improvement: \
         update this test to assert recall instead of absence."
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

    // Total findings that are not phone numbers, i.e. the FP surface.
    let non_phone = m.len() - found(&m, "US Phone Number");
    assert!(
        non_phone <= 320,
        "non-phone findings rose to {non_phone} (baseline ~269); the \
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
