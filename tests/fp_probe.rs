//! Empirical probe for the blind-test FP issue.
//!
//! The blind harness reports ~100% FP rate on checksum-invalid values
//! for credit_card / ssn / sin / iban / phone / ca_ramq categories.
//! This test hard-wires known-invalid values for each category and
//! prints what sub_categories actually fire, so we can see the real
//! root cause instead of trusting a third-party report.
//!
//! Run with `cargo test --test fp_probe -- --nocapture`.

use siphon::scanner::scan_text;

fn probe(label: &str, sample: &str, wrapper: &str) {
    let wrapped = wrapper.replace("{}", sample);
    match scan_text(&wrapped) {
        Ok(matches) => {
            let subs: Vec<String> = matches
                .iter()
                .map(|m| format!("{}/{} [{}]", m.category, m.sub_category, m.text))
                .collect();
            if matches.is_empty() {
                eprintln!("  OK {:<28} {:<28} → (no match)", label, sample);
            } else {
                eprintln!(
                    "  FP {:<28} {:<28} → {} hit(s): {}",
                    label,
                    sample,
                    matches.len(),
                    subs.join(", ")
                );
            }
        }
        Err(e) => eprintln!("  ERR {:<28} {:<24} → {e}", label, sample),
    }
}

#[test]
fn probe_invalid_credit_cards() {
    eprintln!("\n=== Luhn-failing brand-shaped card numbers ===");
    // Each is the canonical "good" test number with the last digit
    // bumped, which always breaks Luhn.
    for s in [
        "4532015112830367", // Visa valid + 1
        "4111111111111112", // Visa test + 1
        "4242424242424243", // Stripe Visa + 1
        "5555555555554445", // MC test + 1
        "5105105105105101", // MC test + 1
        "378282246310006",  // Amex test + 1
        "371449635398432",  // Amex test + 1
        "6011111111111118", // Discover test + 1
    ] {
        probe("invalid-brand", s, "Customer card on file: {} (statement attached)");
    }
}

#[test]
fn probe_invalid_ssns() {
    eprintln!("\n=== Structurally-invalid SSNs ===");
    for s in [
        "000-12-3456", // area 000
        "666-12-3456", // area 666
        "900-12-3456", // area 900+
        "123-00-6789", // group 00
        "123-45-0000", // serial 0000
    ] {
        probe("invalid-ssn", s, "SSN on file: {}");
    }
}

#[test]
fn probe_invalid_ibans() {
    eprintln!("\n=== IBANs with bad mod-97 check digits ===");
    // Real country code but wrong check digits → still structurally
    // IBAN-shaped. A working mod-97 validator would reject all of them.
    for s in [
        "DE89370400440532013001", // valid (control)
        "DE99370400440532013000",
        "GB82WEST12345698765433",
        "FR1420041010050500013M02608",
        "NL39ABNA0417164301",
        "CH9300762011623852958",
    ] {
        probe("iban", s, "Wire to IBAN {} for invoice 7123");
    }
}

#[test]
fn probe_invalid_canada_sins() {
    eprintln!("\n=== Luhn-failing Canada SINs ===");
    // SIN is a 9-digit Luhn number.
    for s in [
        "246-100-002", // valid test SIN (control — starts with 2, passes Luhn)
        "246-100-003", // bumped check digit
        "123-456-789", // sequential → Luhn sum = 47
        "111-111-111", // all ones → Luhn sum = 13 (NB: "111-111-118"
                       // happens to pass Luhn by coincidence, sum = 20)
        "000-000-000", // sentinel — Luhn-valid but rejected by
                       // explicit check; never a real SIN
    ] {
        probe("sin", s, "Social Insurance Number: {}");
    }
}

#[test]
fn probe_invalid_phones() {
    eprintln!("\n=== Structurally-implausible phone numbers ===");
    for s in [
        "+10000000000", // E.164 with all zeros
        "+19999999999", // all nines
        "+15551234567", // plausible US form
        "+441234567",   // too short
        "+19999999",    // too short
    ] {
        probe("phone", s, "Call us at {} for help");
    }
}

#[test]
fn probe_recall_germany_id() {
    eprintln!("\n=== Germany Personalausweis recall ===");
    // Modern Personalausweis is 10 chars: 9 alphanumeric from a
    // restricted set + 1 digit check. The old regex was `{9}`,
    // which couldn't match the 10-char form at all (the trailing
    // \b can't fire mid-word). After the fix, 10-char values
    // should fire.
    // German Personalausweis valid char set is
    // [CFGHJKLMNPRTVWXYZ0-9] — note the exclusion of A, B, D, E, I,
    // O, Q, S, U (to avoid homoglyph confusion between O/0, B/8, etc.).
    // Every test value below must use only those chars or it can't
    // possibly match a real German ID.
    for s in [
        "CFGHJKL123", // 10 chars, modern form
        "T22000129",  // 9 chars (legacy / MRZ)
        "LTJ07Y9N52", // 10 chars, all chars in the restricted set
    ] {
        probe(
            "germany-id",
            s,
            "Personalausweis number on file: {} for customer record",
        );
    }
}

#[test]
fn probe_recall_uk_nin() {
    eprintln!("\n=== UK NIN recall (space-separated form) ===");
    for s in [
        "AB123456C",     // no-separator (was working)
        "AB 12 34 56 C", // space-separated (was missing)
        "AB-12-34-56-C", // dash-separated (also accept)
    ] {
        probe("uk-nin", s, "National Insurance Number: {}");
    }
}

#[test]
fn probe_invalid_ramq() {
    eprintln!("\n=== Quebec RAMQ (health card) ===");
    // RAMQ format: 4 letters + 8 digits, encoding DOB + gender.
    // We don't currently have a RAMQ pattern at all — this should
    // return (no match) for all of them, confirming the gap.
    for s in [
        "ABCD12345678",
        "DUPO99123456",
        "TREF98765432",
    ] {
        probe("ramq", s, "Quebec RAMQ health card: {}");
    }
}

#[test]
fn probe_recall_real_phones() {
    // After the Tier 1 + Tier 2 phone validator lands, real-shape
    // numbers in plausible formats must still match. This is the
    // "don't regress recall" counterpart to probe_invalid_phones.
    eprintln!("\n=== Real-shape phone numbers (must still match) ===");
    for s in [
        "+14155552671",   // US E.164
        "+442079460007",  // UK E.164
        "+33142685300",   // France E.164
        "+4930901820",    // Germany E.164
        "+81312345678",   // Japan E.164
        "415-555-2671",   // Bare US (dashes)
        "(415) 555-2671", // Bare US (parens)
    ] {
        probe("real-phone", s, "Reach me at {} anytime");
    }
}

#[test]
fn probe_recall_gated_bare_ids() {
    // After quality/bare-id-gating, five bare-regex national ID
    // patterns moved from always-run to context-gated. They must
    // still fire when their primary keyword is adjacent, or
    // we've broken recall for real documents containing real
    // IDs. Each row below pairs a plausible ID value with the
    // wrapping sentence a DLP pipeline would realistically see.
    eprintln!("\n=== Bare-ID gated patterns — recall check ===");
    let cases = [
        ("USA Passport Card",
         "C12345678",
         "US passport card number on file: {}"),
        ("Canada Passport",
         "AB123456",
         "Canadian passport {} issued Ottawa"),
        ("Australia Passport",
         "PA1234567",
         "Australian passport number: {}"),
        ("Australia Medicare",
         "2123 45678 1",
         "Medicare card: {}"),
        ("Saudi Arabia National ID",
         "1234567890",
         // Use the country-specific keyword "iqama" rather than
         // the generic "national id", because the generic phrase
         // is registered under 11 different sub_categories and
         // AhoCorasick LeftmostLongest only attributes a hit to
         // the first-registered one (Taiwan National ID at
         // keywords.rs:5852). That shared-keyword bug is a
         // separate architectural fix tracked as a follow-up;
         // the recall path for country-specific keywords is
         // what this commit needs to verify.
         "Iqama / Saudi Arabia ID: {}"),
    ];
    for (expected_sub, value, wrapper) in cases {
        let wrapped = wrapper.replace("{}", value);
        let matches = siphon::scanner::scan_text(&wrapped).unwrap();
        let fired = matches.iter().any(|m| m.sub_category == expected_sub);
        if fired {
            eprintln!("  OK  {:<30} {:<20} fires as expected", expected_sub, value);
        } else {
            let subs: Vec<String> = matches
                .iter()
                .map(|m| format!("{}/{}", m.category, m.sub_category))
                .collect();
            eprintln!(
                "  REGRESS {:<30} {:<20} does NOT fire — got: {}",
                expected_sub,
                value,
                subs.join(", ")
            );
        }
    }
}

#[test]
fn probe_keyword_prefix_shadow_regression() {
    // Regression pin for the AC MatchKind bug: the keyword "personal"
    // (under "Eyes Only") is a prefix of "personalausweis" (under
    // "Germany ID"). With MatchKind::LeftmostFirst, "personal" was
    // added to the AC pattern table first (Eyes Only appears earlier
    // in keywords.rs), so it shadowed every "personalausweis" hit and
    // the Germany ID pattern was filtered out by the AC prefilter —
    // Germany ID was silently undetectable whenever its primary
    // keyword was adjacent. LeftmostLongest prefers the longer
    // overlapping keyword at the same start position, which fixes the
    // whole class of prefix-shadow bugs. This test runs a full scan
    // against the exact scenario and asserts the Germany ID hit
    // survives, so a regression to LeftmostFirst will fail loudly.
    let text = "Personalausweis number on file: CFGHJKL123 for customer record";
    let matches = siphon::scanner::scan_text(text).unwrap();
    let has_germany_id = matches
        .iter()
        .any(|m| m.category == "Europe - Germany" && m.sub_category == "Germany ID");
    assert!(
        has_germany_id,
        "Germany ID pattern must fire when `personalausweis` is in context — \
         regression to LeftmostFirst shadowing suspected. Got: {matches:?}"
    );
}
