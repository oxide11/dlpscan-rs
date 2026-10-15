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

// ---------------------------------------------------------------------------
// evadex 3.40 seed diagnosis (2026-10-14): northam categories that never
// fired on their plain value, even with their own keyword beside it.
// ---------------------------------------------------------------------------

#[test]
fn ratio_patterns_match_before_space_and_full_stop() {
    // `%\b` needed a letter after the `%`, so a ratio in a sentence never
    // matched. Keep one case with a trailing letter to show it still does.
    for (t, sub) in [
        ("Debt-to-income ratio: 43.5% at underwriting.", "DTI Ratio"),
        ("Borrower DTI 43.5%.", "DTI Ratio"),
        ("Loan-to-value ratio: 35.5% at origination.", "LTV Ratio"),
        ("LTV 80.25%", "LTV Ratio"),
        ("LTV 80.25%x", "LTV Ratio"),
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == sub),
            "expected {sub} in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn quebec_hc_matches_the_printed_card_layout() {
    // The card prints `BOUD 8503 1512`; the regex required the letters and
    // digits to touch.
    for t in [
        "RAMQ BOUD 8503 1512 on file.",
        "Carte Soleil BOUD-8503-1512.",
        "RAMQ BOUD85031512",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == "Quebec HC"),
            "expected Quebec HC in {cats:?} for {t:?}"
        );
    }
    // The month/day guard still applies to the spaced layout.
    let cats = categories("RAMQ BOUD 8534 1512");
    assert!(!cats.iter().any(|(s, _)| s == "Quebec HC"), "{cats:?}");
}

#[test]
fn all_digit_run_is_not_a_vin() {
    // A 17-digit SAR filing number passed the VIN check digit by chance
    // (1 in 11) and the VIN rule, at 0.70, shadowed the SAR rule the prose
    // named. Real VINs carry letters.
    let cats = categories("SAR filing number 12345678901234568 submitted to FinCEN.");
    assert!(
        cats.iter().any(|(s, _)| s == "SAR Filing Number"),
        "{cats:?}"
    );
    assert!(!cats.iter().any(|(s, _)| s == "VIN"), "{cats:?}");
    let cats = categories("VIN 1HGCM82633A004352 on the title.");
    assert!(cats.iter().any(|(s, _)| s == "VIN"), "{cats:?}");
}

#[test]
fn named_country_wins_a_cross_border_collision() {
    // A 12-digit run is a Newfoundland MCP number and an Indian Aadhaar
    // alike; Aadhaar's higher format score beat the country the text named.
    let cats = categories("Newfoundland MCP number 987654321012 on file.");
    assert!(cats.iter().any(|(s, _)| s == "Newfoundland HC"), "{cats:?}");
    assert!(!cats.iter().any(|(s, _)| s == "India Aadhaar"), "{cats:?}");

    // With no country named, the stronger format still wins.
    let cats = categories("Reference 987654321012 attached.");
    assert!(
        !cats.iter().any(|(s, _)| s == "Newfoundland HC"),
        "{cats:?}"
    );
}

#[test]
fn keyword_does_not_hand_a_card_to_a_weaker_rule() {
    // "account number" is a PAN keyword; the cross-border rule is for
    // national IDs only, so a Visa stays a Visa.
    let cats = categories("Charge to account number 4532015112830366 today.");
    assert!(cats.iter().any(|(s, _)| s == "Visa"), "{cats:?}");
}

#[test]
fn nested_keyword_still_counts_for_its_own_pattern() {
    // "available balance" is an Account Balance keyword; the "balance" inside
    // it belongs to Balance with Currency Code. A non-overlapping keyword
    // search recorded only the longer one, so the currency amount lost its
    // context.
    for t in [
        "Available balance: USD 12,345.67.",
        "Account balance USD 12,345.67 as of month end.",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter()
                .any(|(s, v)| s == "Balance with Currency Code" && v == "USD 12,345.67"),
            "expected the whole amount in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn decimal_amount_is_not_truncated_by_normalization() {
    // Normalization drops the decimal point (`12,345.67` -> `12,34567`) and
    // the balance rule matched a fragment, `USD 12`, which used to suppress
    // the raw-text pass that finds the whole amount.
    let cats = categories("Total funds transferred: USD 12,345.67.");
    assert!(
        cats.iter()
            .any(|(s, v)| s == "Balance with Currency Code" && v == "USD 12,345.67"),
        "{cats:?}"
    );
}

#[test]
fn bare_business_number_beside_its_keyword() {
    for t in [
        "CRA business number 123456782 on the vendor form.",
        "Business Number (BN): 123 456 782.",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == "Canada BN Root"),
            "expected Canada BN Root in {cats:?} for {t:?}"
        );
    }
    // Check digit fails; no keyword; the RT form keeps its own rule.
    let cats = categories("CRA business number 111222333 on the vendor form.");
    assert!(!cats.iter().any(|(s, _)| s == "Canada BN Root"), "{cats:?}");
    let cats = categories("Reference 123456782 attached.");
    assert!(!cats.iter().any(|(s, _)| s == "Canada BN Root"), "{cats:?}");
    let cats = categories("Business number 123456782RT0001.");
    assert!(cats.iter().any(|(s, _)| s == "Canada BN"), "{cats:?}");
}

#[test]
fn manitoba_dl_uses_the_documented_layout() {
    // `AKKKKAKXX9XX9` (FMCSA Canadian licence reference): name-derived, with
    // `*` padding a short surname. The old `[A-Z]{6}\d{6}` matched none of it.
    for t in [
        "Manitoba driver's licence SMITHJ*AB1CD2 verified by MPI.",
        "Manitoba DL LI***JMAB1CD2",
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == "Manitoba DL"),
            "expected Manitoba DL in {cats:?} for {t:?}"
        );
    }
    let cats = categories("Manitoba DL ETYELZ211962");
    assert!(!cats.iter().any(|(s, _)| s == "Manitoba DL"), "{cats:?}");
}

// ---------------------------------------------------------------------------
// Card-only de-evasion, generalized to check-digit identifiers
// ---------------------------------------------------------------------------

#[test]
fn recovered_check_digit_ids_beside_their_keyword() {
    // Every recovery the alt pass performs (zero padding, letter padding, a
    // base64 tail, rot13 of base64, a value split over JSON fields) used to
    // reach cards only. SIN 130 692 544 and ABA 021000021 are Luhn / ABA
    // valid; each text names the identifier beside the value.
    for (t, want) in [
        (
            "Social insurance number 00000130 692 544 verified.",
            "Canada SIN",
        ),
        (
            "Social insurance number 130 692 54400000 verified.",
            "Canada SIN",
        ),
        (
            "Social insurance number XXXXXXXXXX130 692 544XXXXXXXXXX verified.",
            "Canada SIN",
        ),
        (
            "Social insurance number 130 6OTIgNTQ0 verified.",
            "Canada SIN",
        ),
        (
            "Social insurance number ZGZjVQL5ZvN1AQD= verified.",
            "Canada SIN",
        ),
        (
            r#"Social insurance number {"part1": "130 6", "part2": "92 544"} verified."#,
            "Canada SIN",
        ),
        (
            "Routing number 00000021000021 on the wire.",
            "ABA Routing Number",
        ),
        (
            "ISIN XXXXXXXXXXUS0378331005XXXXXXXXXX: 2-for-1 split.",
            "ISIN",
        ),
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == want),
            "expected {want} in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn recovered_iban_needs_no_keyword() {
    // Two mod-97 check digits vouch for a recovered IBAN as they do for a
    // plain one, which the primary pass accepts with no keyword.
    for t in [
        "Beneficiary account 00000GB82WEST12345698765432.",
        "Beneficiary account GB82WEST123NDU2OTg3NjU0MzI=.",
        r#"Beneficiary account {"part1": "GB82WEST123", "part2": "45698765432"}."#,
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == "IBAN Generic"),
            "expected IBAN Generic in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn recovered_luhn_ids_need_their_keyword() {
    // A single Luhn digit passes one manufactured candidate in ten, so a
    // recovered SIN with no SIN keyword stays quiet...
    let cats = categories("Reference 00000130 692 544 attached.");
    assert!(!cats.iter().any(|(s, _)| s == "Canada SIN"), "{cats:?}");
    // ...and a recovered value that fails its check digit stays quiet even
    // beside the keyword (130 692 545 is not Luhn-valid).
    let cats = categories("Social insurance number 00000130 692 545 verified.");
    assert!(!cats.iter().any(|(s, _)| s == "Canada SIN"), "{cats:?}");
}

#[test]
fn exact_recovery_feeds_shape_only_rules_beside_their_keyword() {
    // No check digit, but each recovery yields the one candidate for the
    // value it restored, and the SSN keyword sits beside it.
    for t in [
        "Social security no 00000742-18-5503 pending.",
        "Social security no XXXXXXXXXX742-18-5503XXXXXXXXXX pending.",
        "Social security no 742-1OC01NTAz pending.",
        r#"Social security no {"part1": "742-1", "part2": "8-5503"} pending."#,
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == "USA SSN"),
            "expected USA SSN in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn guessed_recoveries_do_not_feed_shape_only_rules() {
    // Two trailing zeros are how numbers end, not padding: trimming them is
    // a guess, which only a check digit may confirm.
    let cats = categories("Social security no 742-18-550300 pending.");
    assert!(!cats.iter().any(|(s, _)| s == "USA SSN"), "{cats:?}");
    // Zeros inside a token are not padding either.
    let cats = categories("uae passport: N0003062517");
    assert!(!cats.iter().any(|(s, _)| s == "UAE Passport"), "{cats:?}");
}

#[test]
fn lower_and_mixed_case_identifiers_beside_their_keyword() {
    for (t, want) in [
        (
            "Beneficiary account gb82west12345698765432.",
            "IBAN Generic",
        ),
        (
            "Beneficiary account Gb82WeSt12345698765432.",
            "IBAN Generic",
        ),
        ("ISIN Us0378331005 split 2-for-1.", "ISIN"),
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == want),
            "expected {want} in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn digit_lookalikes_fold_in_short_identifiers() {
    // 130 692 544 and 021000021 with every digit it can spare swapped for a
    // look-alike (І Ʒ Ο б Ƨ Ƽ).
    for (t, want) in [
        (
            "Social insurance number \u{0406}\u{01B7}\u{039F} \u{0431}9\u{01A7} \u{01BC}44 verified.",
            "Canada SIN",
        ),
        (
            "Routing number \u{039F}\u{01A7}\u{0406}\u{039F}\u{039F}\u{039F}\u{039F}\u{01A7}\u{0406} on the wire.",
            "ABA Routing Number",
        ),
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == want),
            "expected {want} in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn everyday_mixed_case_tokens_stay_quiet() {
    for t in [
        "Passport photos ready by 10am; covid19 rules no longer apply.",
        "SSN lookup service v2 deployed on node k8s-prod-3a.",
        "SIN batch job ran in 4m32s on host db01; ISIN feed lag 3h.",
    ] {
        let cats = categories(t);
        assert!(cats.is_empty(), "{cats:?} for {t:?}");
    }
}

#[test]
fn cusip_needs_a_securities_keyword_not_a_generic_one() {
    // "identifier", "position", "holding" and friends used to open the CUSIP
    // gate, so any 9-character run in an ordinary sentence met a 1-in-10
    // check digit: 130 692 544 is a SIN, and passed as a CUSIP.
    for t in [
        "Dear Customer,\n\nYour account identifier is 130 692 544.\n\nRegards",
        "Holding reference 130692544 for the asset transfer.",
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(s, _)| s == "CUSIP"),
            "{cats:?} for {t:?}"
        );
    }
    for t in [
        "Risk exposure report: CUSIP 037833100 position $2.4M.",
        "Trade: CINS G0177J108 purchased, 500 shares.",
    ] {
        let cats = categories(t);
        assert!(cats.iter().any(|(s, _)| s == "CUSIP"), "{cats:?} for {t:?}");
    }
}

#[test]
fn wkn_and_ric_beside_their_keyword() {
    for (t, want) in [
        ("German WKN 865985 — Xetra order entry.", "WKN"),
        ("Wertpapierkennnummer A1EWWW: trade at EUR 82.40.", "WKN"),
        (
            "Reuters RIC AAPL.O — real-time quote on Refinitiv.",
            "Reuters RIC",
        ),
        (
            "Market data subscription: RIC 0005.HK, tick data.",
            "Reuters RIC",
        ),
    ] {
        let cats = categories(t);
        assert!(
            cats.iter().any(|(s, _)| s == want),
            "expected {want} in {cats:?} for {t:?}"
        );
    }
}

#[test]
fn wkn_and_ric_shapes_without_substance_stay_quiet() {
    for t in [
        // Six capitals beside "WKN" but no digit: a word, not a WKN.
        "WKN BUDGET approved.",
        // RIC shape, but the suffix names no exchange.
        "The RIC team met at 9.AM on Friday.",
        "Refinitiv licence renewal for desk A.B costs more.",
        // RIC shape with no keyword.
        "Attach report.TXT and AAPL.O notes.",
    ] {
        let cats = categories(t);
        assert!(
            !cats.iter().any(|(s, _)| s == "WKN" || s == "Reuters RIC"),
            "{cats:?} for {t:?}"
        );
    }
}
