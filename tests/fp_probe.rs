//! Empirical probe for the blind-test FP issue.
//!
//! The blind harness reports ~100% FP rate on checksum-invalid values
//! for credit_card / ssn / sin / iban / phone / ca_ramq categories.
//! This test hard-wires known-invalid values for each category and
//! prints what sub_categories actually fire, so we can see the real
//! root cause instead of trusting a third-party report.
//!
//! Run with `cargo test --test fp_probe -- --nocapture`.

use dlpscan::scanner::scan_text;

fn probe(label: &str, sample: &str, wrapper: &str) {
    let wrapped = wrapper.replace("{}", sample);
    match scan_text(&wrapped) {
        Ok(matches) => {
            let subs: Vec<String> = matches
                .iter()
                .map(|m| format!("{}/{}", m.category, m.sub_category))
                .collect();
            if matches.is_empty() {
                eprintln!("  OK {:<28} {:<24} → (no match)", label, sample);
            } else {
                eprintln!(
                    "  FP {:<28} {:<24} → {} hit(s): {}",
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
        "046-454-286", // valid test SIN (control)
        "046-454-287",
        "123-456-789",
        "111-111-118",
        "000-000-000",
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
