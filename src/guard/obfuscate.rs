//! Realistic fake data generators for the Obfuscate action.

use crate::models::Match;
use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::RngExt;
use rand::SeedableRng;
use std::sync::Mutex;

static OBFUSCATION_RNG: Lazy<Mutex<StdRng>> = Lazy::new(|| Mutex::new(rand::make_rng()));

/// Set seed for deterministic obfuscation (for testing/auditing).
pub fn set_obfuscation_seed(seed: u64) {
    tracing::warn!("Obfuscation seed set — output will be deterministic and predictable");
    *OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner()) = StdRng::seed_from_u64(seed);
}

/// Generate realistic fake data for a match based on its category.
///
/// The `OBFUSCATION_RNG` lock is acquired exactly once, here, and every
/// generator borrows it. That is deliberate: the generators used to be split
/// between ones that took an rng and ones that locked internally, so an arm
/// calling the latter first had to `drop` the guard. `std::sync::Mutex` is
/// not reentrant, so forgetting that deadlocked — at runtime, with no
/// compile error, in whichever arm was newest. Passing the rng makes the
/// mistake unrepresentable.
pub fn obfuscate_match(m: &Match) -> String {
    let mut guard = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let rng = &mut *guard;
    // Try sub_category first (most specific), then category
    match m.sub_category.as_str() {
        "Visa" | "MasterCard" | "Amex" | "Discover" | "JCB" | "Diners Club" | "UnionPay" => {
            obfuscate_credit_card(rng, m)
        }
        "Email Address" => obfuscate_email(rng),
        "E.164 Phone Number" | "US Phone Number" | "UK Phone Number" => {
            obfuscate_phone(rng, &m.text)
        }
        "USA SSN" | "USA ITIN" => obfuscate_ssn(rng, &m.text),
        "Canada SIN" => generate_luhn_sin(rng, &m.text),
        "IBAN Generic" => generate_valid_iban(rng, &m.text),
        "IPv4 Address" => obfuscate_ipv4(rng),
        "MAC Address" => obfuscate_mac(rng, &m.text),
        "Australia TFN" => generate_australia_tfn(rng),
        "Australia Medicare" => generate_australia_medicare(rng),
        "ICCID" => generate_iccid(rng),
        "DEA Number" => generate_dea_number(rng),
        "India PAN" => generate_india_pan(rng),
        // "South Africa ID", not "South Africa ID Number": the arm has to
        // spell the sub_category the pattern set actually emits, or it never
        // matches and the value falls through to obfuscate_generic.
        "South Africa ID" => generate_south_africa_id(rng),
        _ => match m.category.as_str() {
            "Credit Card Numbers" | "Primary Account Numbers" => obfuscate_credit_card(rng, m),
            "Generic Secrets"
            | "Cloud Provider Secrets"
            | "Code Platform Secrets"
            | "Payment Service Secrets"
            | "Messaging Service Secrets" => obfuscate_secret(rng, &m.text),
            _ => obfuscate_generic(rng, &m.text),
        },
    }
}

/// Replace all matched spans in text with fake data. Process from end to start.
pub fn obfuscate_matches(text: &str, matches: &[Match]) -> String {
    if matches.is_empty() {
        return text.to_string();
    }
    let mut sorted: Vec<&Match> = matches.iter().collect();
    sorted.sort_by_key(|m| std::cmp::Reverse(m.span.0));
    let mut result = text.to_string();
    for m in sorted {
        let (start, end) = m.span;
        if start < result.len() && end <= result.len() {
            let fake = obfuscate_match(m);
            result.replace_range(start..end, &fake);
        }
    }
    result
}

// ---- Generators ----

fn obfuscate_credit_card(rng: &mut impl RngExt, m: &Match) -> String {
    let clean: String = m.text.chars().filter(|c| c.is_ascii_digit()).collect();
    let length = clean.len().clamp(13, 19);

    let prefix = match m.sub_category.as_str() {
        "Visa" => "4".to_string(),
        "MasterCard" => format!("5{}", rng.random_range(1..=5)),
        "Amex" => format!("3{}", if rng.random_bool(0.5) { "4" } else { "7" }),
        "Discover" => "6011".to_string(),
        "JCB" => "35".to_string(),
        "Diners Club" => "36".to_string(),
        "UnionPay" => "62".to_string(),
        _ => format!("{}", rng.random_range(3..=6)),
    };

    generate_luhn_number(rng, length, &prefix, &m.text)
}

fn generate_luhn_number(
    rng: &mut impl RngExt,
    length: usize,
    prefix: &str,
    original: &str,
) -> String {
    let mut digits: Vec<u8> = prefix.bytes().map(|b| b - b'0').collect();
    while digits.len() < length - 1 {
        digits.push(rng.random_range(0..10));
    }
    // Luhn check digit
    let mut total: u32 = 0;
    for (idx, &d) in digits.iter().rev().enumerate() {
        let mut n = d as u32;
        if idx % 2 == 0 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        total += n;
    }
    let check = ((10 - (total % 10)) % 10) as u8;
    digits.push(check);

    // Reapply original formatting
    let fake_digits: String = digits.iter().map(|d| (d + b'0') as char).collect();
    let mut result = String::new();
    let mut fake_idx = 0;
    for c in original.chars() {
        if c.is_ascii_digit() && fake_idx < fake_digits.len() {
            result.push(fake_digits.chars().nth(fake_idx).unwrap_or('0'));
            fake_idx += 1;
        } else if !c.is_ascii_digit() {
            result.push(c);
        }
    }
    // Append remaining digits if original had fewer formatting chars
    while fake_idx < fake_digits.len() {
        result.push(fake_digits.chars().nth(fake_idx).unwrap_or('0'));
        fake_idx += 1;
    }
    result
}

/// Generate a Luhn-valid Canada SIN (9 digits, first not 0 or 8).
fn generate_luhn_sin(rng: &mut impl RngExt, original: &str) -> String {
    // Valid first digits: 1-9 excluding 8
    let valid_first = [1u8, 2, 3, 4, 5, 6, 7, 9];
    let first = valid_first[rng.random_range(0..valid_first.len())];
    generate_luhn_number(rng, 9, &first.to_string(), original)
}

/// Compute mod-97 of a string where each char is either a digit (0-9)
/// or uppercase letter (A=10..Z=35). Uses 9-digit chunking to avoid
/// overflow on arbitrarily long strings.
fn mod97_str(s: &str) -> u64 {
    let mut remainder: u64 = 0;
    for c in s.chars() {
        let d = if c.is_ascii_digit() {
            (c as u64) - ('0' as u64)
        } else {
            (c as u64) - ('A' as u64) + 10
        };
        if d >= 10 {
            // Two-digit contribution
            remainder = (remainder * 100 + d) % 97;
        } else {
            remainder = (remainder * 10 + d) % 97;
        }
    }
    remainder
}

/// Generate a mod-97 valid IBAN. Preserves the country code and formatting
/// of the original; generates a random BBAN and computes the correct check.
fn generate_valid_iban(rng: &mut impl RngExt, original: &str) -> String {
    // Strip non-alphanumeric to get the canonical form
    let clean: String = original
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    let country = if clean.len() >= 2 && clean[..2].chars().all(|c| c.is_ascii_alphabetic()) {
        clean[..2].to_string()
    } else {
        "DE".to_string()
    };

    // BBAN length = total clean length - 4 (CC + 2-digit check)
    let bban_len = clean.len().saturating_sub(4);
    if bban_len == 0 {
        return original.to_string();
    }

    // Generate all-digit BBAN (passes mod-97; structurally imperfect for
    // alpha-BBAN countries like GB, but sufficient for obfuscation).
    let bban: String = (0..bban_len)
        .map(|_| (b'0' + rng.random_range(0..10)) as char)
        .collect();

    let to_check = format!("{bban}{country}00");
    let remainder = mod97_str(&to_check);
    let check = 98u64.saturating_sub(remainder);
    let check_str = format!("{check:02}");

    let fake_clean = format!("{country}{check_str}{bban}");

    // Reapply original spacing/formatting (spaces every 4 chars is common)
    let mut result = String::new();
    let mut fake_iter = fake_clean.chars();
    for c in original.chars() {
        if c.is_alphanumeric() {
            match fake_iter.next() {
                Some(fc) => result.push(fc),
                None => result.push(c),
            }
        } else {
            result.push(c);
        }
    }
    // Append any remaining fake chars not covered by original length
    for fc in fake_iter {
        result.push(fc);
    }
    result
}

/// Generate a valid Australia Tax File Number (9 digits, mod-11 weighted).
/// Weights: [1,4,3,7,5,8,6,9,10]. Retries until a valid last digit is found.
fn generate_australia_tfn(rng: &mut impl RngExt) -> String {
    loop {
        let weights = [1u32, 4, 3, 7, 5, 8, 6, 9, 10];
        // First 8 digits; first digit must not be 0
        let mut digits = [0u32; 9];
        digits[0] = rng.random_range(1..10);
        for d in &mut digits[1..8] {
            *d = rng.random_range(0..10);
        }
        // Find digit[8] such that full weighted sum ≡ 0 mod 11
        let partial: u32 = digits[..8]
            .iter()
            .zip(weights[..8].iter())
            .map(|(&d, &w)| d * w)
            .sum();
        // partial + d8 * 10 ≡ 0 mod 11 → d8 = (11 - partial%11) % 11 * inv(10) mod 11
        // Simpler: try all digits 0-9
        let mut found = false;
        for d9 in 0u32..10 {
            if (partial + d9 * 10).is_multiple_of(11) {
                digits[8] = d9;
                found = true;
                break;
            }
        }
        if found {
            return digits.iter().map(|d| (b'0' + *d as u8) as char).collect();
        }
        // No valid d9 in 0-9 for this combination — retry
    }
}

/// Generate a valid Australia Medicare number (10 digits).
/// Weights [1,3,7,9,1,3,7,9] over first 8 digits; digit 9 = check digit;
/// digit 10 = the individual reference number, 1-9 — one per person on the
/// card, so it is chosen at random rather than fixed at 1.
fn generate_australia_medicare(rng: &mut impl RngExt) -> String {
    let weights = [1u32, 3, 7, 9, 1, 3, 7, 9];
    let mut digits = [0u32; 10];
    // First digit: 2-6
    digits[0] = rng.random_range(2..7);
    for d in &mut digits[1..8] {
        *d = rng.random_range(0..10);
    }
    let check: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum::<u32>()
        % 10;
    digits[8] = check;
    digits[9] = rng.random_range(1..10); // IRN: 1-9
    digits.iter().map(|d| (b'0' + *d as u8) as char).collect()
}

/// Generate a Luhn-valid ICCID (19 digits starting with "89").
fn generate_iccid(rng: &mut impl RngExt) -> String {
    // Use a placeholder original of the right length for formatting
    let placeholder: String = "0".repeat(19);
    generate_luhn_number(rng, 19, "89", &placeholder)
}

/// Generate a valid DEA registration number.
/// Format: L1 L2 D1 D2 D3 D4 D5 D6 D7 where D7 = (D1+D3+D5 + 2*(D2+D4+D6)) % 10.
fn generate_dea_number(rng: &mut impl RngExt) -> String {
    let valid_first = b"ABCDEFGHJKLMPRX";
    let l1 = valid_first[rng.random_range(0..valid_first.len())] as char;
    let l2 = (b'A' + rng.random_range(0..26u8)) as char;
    let mut d = [0u8; 7];
    for di in &mut d[..6] {
        *di = rng.random_range(0..10);
    }
    let odd_sum = d[0] as u32 + d[2] as u32 + d[4] as u32;
    let even_sum = d[1] as u32 + d[3] as u32 + d[5] as u32;
    d[6] = ((odd_sum + 2 * even_sum) % 10) as u8;
    let digits: String = d.iter().map(|&b| (b'0' + b) as char).collect();
    format!("{l1}{l2}{digits}")
}

/// Generate a structurally valid India PAN (10 chars: LLLPL####L).
/// No checksum algorithm is published; this is format-only.
fn generate_india_pan(rng: &mut impl RngExt) -> String {
    let entity_types = b"PCHBGAJLFT";
    let mut chars = [' '; 10];
    // First 3: random uppercase
    for c in &mut chars[..3] {
        *c = (b'A' + rng.random_range(0..26u8)) as char;
    }
    // 4th: entity type
    chars[3] = entity_types[rng.random_range(0..entity_types.len())] as char;
    // 5th: random uppercase (initial of surname)
    chars[4] = (b'A' + rng.random_range(0..26u8)) as char;
    // 6-9: 4 digits
    for c in &mut chars[5..9] {
        *c = (b'0' + rng.random_range(0..10u8)) as char;
    }
    // 10th: random uppercase
    chars[9] = (b'A' + rng.random_range(0..26u8)) as char;
    chars.iter().collect()
}

/// Generate a Luhn-valid South Africa ID number (13 digits).
/// Embeds a plausible DOB (YYMMDD), random sequence, citizenship 0/1, field 8.
fn generate_south_africa_id(rng: &mut impl RngExt) -> String {
    let yy = rng.random_range(0..100u8);
    let mm = rng.random_range(1..13u8);
    let dd = rng.random_range(1..29u8); // 1-28 is always a valid day
    let seq: u16 = rng.random_range(0..10000);
    let citizenship: u8 = rng.random_range(0..2);
    // Build first 12 digits as the prefix
    let prefix = format!("{:02}{:02}{:02}{:04}{}8", yy, mm, dd, seq, citizenship);
    let placeholder: String = "0".repeat(13);
    generate_luhn_number(rng, 13, &prefix, &placeholder)
}

fn obfuscate_email(rng: &mut impl RngExt) -> String {
    let user: String = (0..8)
        .map(|_| (b'a' + rng.random_range(0..26)) as char)
        .collect();
    let domains = ["example.net", "example.org", "test.invalid", "sample.test"];
    let domain = domains[rng.random_range(0..domains.len())];
    format!("{user}@{domain}")
}

fn obfuscate_phone(rng: &mut impl RngExt, original: &str) -> String {
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                (b'0' + rng.random_range(0..10)) as char
            } else {
                c
            }
        })
        .collect()
}

fn obfuscate_ssn(rng: &mut impl RngExt, original: &str) -> String {
    obfuscate_phone(rng, original) // Same algorithm: replace digits, keep format
}

fn obfuscate_ipv4(rng: &mut impl RngExt) -> String {
    format!(
        "{}.{}.{}.{}",
        rng.random_range(10..224),
        rng.random_range(0..256),
        rng.random_range(0..256),
        rng.random_range(1..255)
    )
}

fn obfuscate_mac(rng: &mut impl RngExt, original: &str) -> String {
    let delim = if original.contains(':') { ':' } else { '-' };
    let octets: Vec<String> = (0..6)
        .map(|_| format!("{:02x}", rng.random_range(0..256u16)))
        .collect();
    octets.join(&delim.to_string())
}

fn obfuscate_secret(rng: &mut impl RngExt, original: &str) -> String {
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    original
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                charset[rng.random_range(0..charset.len())]
            } else {
                c
            }
        })
        .collect()
}

fn obfuscate_generic(rng: &mut impl RngExt, original: &str) -> String {
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                (b'0' + rng.random_range(0..10)) as char
            } else if c.is_ascii_uppercase() {
                (b'A' + rng.random_range(0..26)) as char
            } else if c.is_ascii_lowercase() {
                (b'a' + rng.random_range(0..26)) as char
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::{
        is_luhn_valid, is_valid_australia_medicare, is_valid_australia_tfn, is_valid_canada_sin,
        is_valid_dea_number, is_valid_iban, is_valid_iccid, is_valid_india_pan,
        is_valid_south_africa_id,
    };

    /// A local, seeded generator.
    ///
    /// The helpers all take their rng now, so a test does not have to touch
    /// the process-wide `OBFUSCATION_RNG` — which also means these tests no
    /// longer perturb each other when cargo runs them in parallel.
    fn seeded(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed) // DevSkim: ignore DS148264
    }

    #[test]
    fn test_obfuscate_email() {
        let email = obfuscate_email(&mut seeded(42));
        assert!(email.contains('@'));
        assert!(email.len() > 5);
    }

    #[test]
    fn test_obfuscate_ssn_preserves_format() {
        let fake = obfuscate_phone(&mut seeded(42), "123-45-6789");
        assert_eq!(fake.len(), 11);
        assert_eq!(fake.chars().nth(3), Some('-'));
        assert_eq!(fake.chars().nth(6), Some('-'));
    }

    #[test]
    fn test_obfuscate_ipv4() {
        let ip = obfuscate_ipv4(&mut seeded(42));
        assert_eq!(ip.split('.').count(), 4);
    }

    #[test]
    fn test_obfuscate_credit_card_luhn() {
        let m = Match {
            text: "4111-1111-1111-1111".to_string(),
            category: "Credit Card Numbers".to_string(),
            sub_category: "Visa".to_string(),
            has_context: false,
            confidence: 0.8,
            span: (0, 19),
            context_required: false,
            metadata: std::collections::HashMap::new(),
        };
        let fake = obfuscate_credit_card(&mut seeded(42), &m);
        assert!(fake.starts_with('4')); // Visa prefix
                                        // Verify Luhn on digits only
        let digits: String = fake.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(is_luhn_valid(&digits));
    }

    #[test]
    fn test_deterministic_seed() {
        // Verify determinism using a local RNG to avoid parallel test interference
        use rand::SeedableRng;
        let mut rng_a = StdRng::seed_from_u64(123);
        let mut rng_b = StdRng::seed_from_u64(123);
        let a: u64 = rng_a.random();
        let b: u64 = rng_b.random();
        assert_eq!(a, b);
    }

    #[test]
    fn test_generate_luhn_sin_valid() {
        let mut rng = seeded(1);
        for _ in 0..20 {
            let sin = generate_luhn_sin(&mut rng, "000-000-000");
            let digits: String = sin.chars().filter(|c| c.is_ascii_digit()).collect();
            assert!(
                is_valid_canada_sin(&digits),
                "generated SIN {sin:?} is not valid"
            );
            // First digit must not be 0 or 8
            let first = digits.chars().next().unwrap();
            assert!(first != '0' && first != '8', "invalid first digit: {first}");
        }
    }

    #[test]
    fn test_generate_valid_iban() {
        // DE IBAN: 22 chars
        let fake = generate_valid_iban(&mut seeded(2), "DE89370400440532013000");
        let clean: String = fake.chars().filter(|c| c.is_alphanumeric()).collect();
        // Omit the generated value from the panic message — CodeQL would flag it as
        // cleartext logging of sensitive data (the function handles real IBANs in prod).
        assert!(is_valid_iban(&clean), "generated IBAN is not valid");
    }

    #[test]
    fn test_generate_australia_tfn_valid() {
        let mut rng = seeded(3);
        for _ in 0..20 {
            let tfn = generate_australia_tfn(&mut rng);
            assert!(is_valid_australia_tfn(&tfn), "generated TFN is not valid");
        }
    }

    #[test]
    fn test_generate_australia_medicare_valid() {
        let mut rng = seeded(4);
        for _ in 0..20 {
            let mc = generate_australia_medicare(&mut rng);
            assert!(
                is_valid_australia_medicare(&mc),
                "generated Medicare number is not valid"
            );
        }
    }

    #[test]
    fn test_generate_iccid_valid() {
        let mut rng = seeded(5);
        for _ in 0..20 {
            let iccid = generate_iccid(&mut rng);
            assert!(is_valid_iccid(&iccid), "generated ICCID is not valid");
            assert!(iccid.starts_with("89"), "ICCID must start with 89");
        }
    }

    #[test]
    fn test_generate_dea_number_valid() {
        let mut rng = seeded(6);
        for _ in 0..20 {
            let dea = generate_dea_number(&mut rng);
            assert!(
                is_valid_dea_number(&dea),
                "generated DEA number is not valid"
            );
        }
    }

    #[test]
    fn test_generate_india_pan_valid() {
        let mut rng = seeded(7);
        for _ in 0..20 {
            let pan = generate_india_pan(&mut rng);
            assert!(is_valid_india_pan(&pan), "generated India PAN is not valid");
        }
    }

    /// Every string `obfuscate_match` dispatches on must be a name the
    /// pattern set actually emits.
    ///
    /// The generators are selected by string equality on
    /// `Match::sub_category` (falling back to `category`), so an arm naming
    /// something no pattern produces is dead code that looks alive: the value
    /// falls through to `obfuscate_generic` and the check-digit-correct
    /// generator never runs. That is what happened to South Africa ID, whose
    /// arm read "South Africa ID Number" while the pattern emits "South
    /// Africa ID".
    ///
    /// The per-generator tests below cannot catch this — they call the
    /// generators directly, which proves the arithmetic and nothing about
    /// whether anything reaches it. Neither can a hand-maintained list of the
    /// arms, which is just the same typo written twice. So the arms are read
    /// out of this file's own source: no duplication to drift, and a new arm
    /// is covered the moment it is written.
    #[test]
    fn every_dispatch_arm_names_something_the_scanner_emits() {
        use siphon_core::patterns::PATTERNS;

        let known: std::collections::HashSet<&str> = PATTERNS
            .iter()
            .flat_map(|p| [p.sub_category, p.category])
            .collect();

        let source = include_str!("obfuscate.rs");
        let body_start = source
            .find("pub fn obfuscate_match")
            .expect("obfuscate_match must exist");
        // Ends at the next item at column 0 after the function.
        let body = &source[body_start..];
        let body_end = body[1..].find("\n}\n").map(|i| i + 2).unwrap_or(body.len());
        let body = &body[..body_end];

        // Every string literal in that function is an arm pattern — a
        // sub_category or a category. There are no other literals in it.
        // Comments are dropped first, or a comment that quotes a name (such
        // as the one above the South Africa arm, which cites the old spelling
        // to explain the fix) would read as an arm.
        let mut unknown: Vec<String> = Vec::new();
        for line in body.lines() {
            let mut in_string = false;
            let mut code_end = line.len();
            let bytes = line.as_bytes();
            let mut i = 0;
            while i + 1 <= bytes.len() {
                match bytes[i] {
                    b'"' => in_string = !in_string,
                    b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                        code_end = i;
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            let code = &line[..code_end];

            let mut rest = code;
            while let Some(open) = rest.find('"') {
                rest = &rest[open + 1..];
                let Some(close) = rest.find('"') else { break };
                let lit = &rest[..close];
                rest = &rest[close + 1..];
                if !lit.is_empty() && !known.contains(lit) {
                    unknown.push(lit.to_string());
                }
            }
        }

        assert!(
            unknown.is_empty(),
            "these obfuscate_match arms name nothing the scanner emits, so they \
             never run and the value falls through to obfuscate_generic: {unknown:?}"
        );
    }

    /// The generator is reached through `obfuscate_match`, not just callable.
    ///
    /// Round-trips the value the scanner itself produces: scan a real SA ID,
    /// hand the resulting Match to the obfuscator, and require the output to
    /// still be a valid SA ID. Before the arm was corrected this produced
    /// random digits from `obfuscate_generic`, which the validator rejects.
    #[test]
    fn south_africa_id_is_reached_through_dispatch() {
        use siphon_core::scanner::{scan_text_with_config, ScanConfig};

        let cfg = ScanConfig {
            min_confidence: 0.0,
            ..Default::default()
        };
        let found = scan_text_with_config("id number: 8001015009087", &cfg)
            .expect("scan")
            .into_iter()
            .find(|m| m.sub_category == "South Africa ID")
            .expect("the scanner should report a South Africa ID here");

        set_obfuscation_seed(11);
        for _ in 0..20 {
            let fake = obfuscate_match(&found);
            assert!(
                is_valid_south_africa_id(&fake),
                "dispatch produced {fake:?}, which is not a valid South Africa ID \
                 — the arm is not reaching the generator"
            );
        }
    }

    #[test]
    fn test_generate_south_africa_id_valid() {
        let mut rng = seeded(8);
        for _ in 0..20 {
            let id = generate_south_africa_id(&mut rng);
            assert!(
                is_valid_south_africa_id(&id),
                "generated SA ID {id:?} is not valid"
            );
        }
    }

    #[test]
    fn test_mod97_str_known_value() {
        // DE89370400440532013000 is a known valid German IBAN.
        // IBAN check: rearrange first 4 chars to end, compute mod97 → must equal 1.
        // Rearranged: "370400440532013000DE89"
        // D=13, E=14 expand inline in the chunked computation.
        assert_eq!(mod97_str("370400440532013000DE89"), 1);
    }
}
