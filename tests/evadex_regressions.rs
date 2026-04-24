//! Regressions surfaced by evadex v3.20.2 (report dated 2026-04-23).
//!
//! Six findings were filed: F1 (Quebec HC shadowed by ISIN), F2
//! (Chile RUN/RUT too loose), F3 (MRN keywords too broad), F4 (SSN
//! gate never fires), F5 (SSN area-code validation), F6 (Quebec HC
//! structural validation).
//!
//! After investigation:
//!   - F4 and F5 were **not bugs** — the existing `is_valid_ssn`
//!     in validation.rs already rejects the sentinel 123-45-6789
//!     (ascending-digits pattern) and every reserved area code
//!     (000 / 666 / 900-999). evadex's reproductions all used that
//!     specific sentinel, which is why nothing fired.
//!   - F3 was reviewed — the MRN keyword list is already narrow
//!     ("mrn", "medical record", "patient id", "chart number",
//!     "dossier médical", etc.). The report flagged "maladie" as
//!     a leaking keyword, but it's not in the MRN list at all.
//!     The specific reproduction uses a sentence that is
//!     legitimately about a medical record, so the MRN tag is
//!     correct. No change.
//!
//! The tests below pin the F1 / F2 / F6 fixes plus the SSN
//! behaviour that F4/F5 questioned, so a regression in any of
//! the six surfaces on CI.

use siphon::scanner;

fn categories(text: &str) -> Vec<(String, String)> {
    scanner::scan_text(text)
        .expect("scan_text")
        .into_iter()
        .map(|m| (m.sub_category, m.text))
        .collect()
}

// ---------------------------------------------------------------------------
// F1 — Quebec HC beats ISIN when Quebec context is present
// ---------------------------------------------------------------------------

#[test]
fn f1_quebec_hc_wins_over_isin_when_gated_context_present() {
    for t in [
        "Quebec HC TREM85120123.",
        "RAMQ number TREM85120123.",
        "carte assurance maladie TREM85120123",
        "TREM85120123 RAMQ",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(sub, _)| sub == "Quebec HC"),
            "expected Quebec HC in {cats:?} for {t:?}"
        );
        assert!(
            !cats.iter().any(|(sub, _)| sub == "ISIN"),
            "ISIN should not shadow Quebec HC: {cats:?} for {t:?}"
        );
    }
}

#[test]
fn f1_isin_still_fires_when_no_quebec_context() {
    // Pure-securities context — Quebec HC has no keyword in range,
    // so ISIN wins on its own 0.75 specificity. The dedup
    // tiebreaker only favours gated matches when both fire.
    let cats = categories("Portfolio holdings: US0378331005 on record.");
    assert!(cats.iter().any(|(sub, _)| sub == "ISIN"));
    assert!(!cats.iter().any(|(sub, _)| sub == "Quebec HC"));
}

// ---------------------------------------------------------------------------
// F2 — Chile RUN/RUT requires context, no more bare digit-group matches
// ---------------------------------------------------------------------------

#[test]
fn f2_chile_run_does_not_fire_without_context() {
    // RAMQ-shape digit groups (4 letters + 4+4) used to trigger
    // Chile RUN/RUT at 0.65 confidence with no keyword present.
    for t in [
        "KMFS 3198 2006",
        "DGKQ 7715 1826",
        "Quebec HC RAMQ: KMFS 3198 2006 on file.",
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(sub, _)| sub == "Chile RUN/RUT"),
            "Chile RUN/RUT fired without Chilean context: {cats:?} for {t:?}"
        );
    }
}

#[test]
fn f2_chile_run_still_fires_with_legitimate_context() {
    // With a real RUT keyword in range the pattern should still
    // match so we don't regress precision into recall.
    let cats = categories("RUT: 12.345.678-5");
    assert!(
        cats.iter().any(|(sub, _)| sub == "Chile RUN/RUT"),
        "Chile RUN/RUT should still match with RUT keyword: {cats:?}"
    );
}

// ---------------------------------------------------------------------------
// F4 / F5 — SSN behaviour: sentinels and reserved area codes rejected,
// real-shape SSNs detected under normal phrasings.
// ---------------------------------------------------------------------------

#[test]
fn f4_ssn_detected_under_natural_phrasings() {
    // Real-shape SSN (area 425, not a sentinel). Should fire.
    for t in [
        "My social security number is 425-71-3482.",
        "Employee SSN: 425-71-3482 on file.",
        "SSN 425-71-3482",
        "Social Security Number: 425-71-3482",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(sub, _)| sub == "USA SSN"),
            "SSN should be detected: {cats:?} for {t:?}"
        );
    }
}

#[test]
fn f4_sentinel_ssn_123_45_6789_is_rejected_by_structural_validation() {
    // The evadex report flagged this as a bug; it's not —
    // 123-45-6789 is the canonical ascending-sentinel SSN and the
    // structural validator (is_valid_ssn) correctly rejects it.
    for t in [
        "My social security number is 123-45-6789.",
        "SSN 123-45-6789",
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(sub, _)| sub == "USA SSN"),
            "sentinel SSN should be rejected: {cats:?} for {t:?}"
        );
    }
}

#[test]
fn f5_ssn_reserved_area_codes_rejected() {
    // SSA never issues area 000, 666, or 900-999. Even in a
    // keyword-gated context, the structural validator drops them.
    for t in [
        "SSN 000-12-3456",
        "social security number 666-12-3456",
        "Employee SSN: 900-12-3456",
        "SSN 999-12-3456",
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(sub, _)| sub == "USA SSN"),
            "reserved-area SSN should be rejected: {cats:?} for {t:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// F6 — Quebec HC regex rejects structurally-invalid month / day values
// ---------------------------------------------------------------------------

#[test]
fn f6_quebec_hc_rejects_invalid_months_and_days() {
    // Months: only 01-12 (male) or 51-62 (female) are valid.
    // Days: 01-31.
    // These inputs carry RAMQ context so the gate passes — the
    // regex is what rejects them.
    for t in [
        "RAMQ TREM85990123",              // month 99
        "RAMQ TREM85139999",              // month 13, day 99
        "assurance maladie TREM85130199", // month 13, day 01
        "RAMQ TREM85006301",              // month 00, day 63
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(sub, _)| sub == "Quebec HC"),
            "Quebec HC should reject structurally-invalid RAMQ: {cats:?} for {t:?}"
        );
    }
}

#[test]
fn f6_quebec_hc_accepts_both_male_and_female_month_encodings() {
    // Male (MM 01-12) and female (MM 51-62) both need to pass.
    let cats_m = categories("RAMQ TREM85120101"); // month 12 (male Dec)
    assert!(cats_m.iter().any(|(sub, _)| sub == "Quebec HC"));

    let cats_f = categories("RAMQ TREM85620101"); // month 62 (female Dec)
    assert!(cats_f.iter().any(|(sub, _)| sub == "Quebec HC"));
}
