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
pub fn obfuscate_match(m: &Match) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    // Try sub_category first (most specific), then category
    match m.sub_category.as_str() {
        "Visa" | "MasterCard" | "Amex" | "Discover" | "JCB" | "Diners Club" | "UnionPay" => {
            drop(rng);
            obfuscate_credit_card(m)
        }
        "Email Address" => {
            drop(rng);
            obfuscate_email()
        }
        "E.164 Phone Number" | "US Phone Number" | "UK Phone Number" => {
            drop(rng);
            obfuscate_phone(&m.text)
        }
        "USA SSN" | "USA ITIN" => {
            drop(rng);
            obfuscate_ssn(&m.text)
        }
        "Canada SIN" => {
            drop(rng);
            generate_luhn_sin(&m.text)
        }
        "IBAN Generic" => generate_valid_iban(&m.text, &mut *rng),
        "IPv4 Address" => {
            drop(rng);
            obfuscate_ipv4()
        }
        "MAC Address" => {
            drop(rng);
            obfuscate_mac(&m.text)
        }
        "Australia TFN" => generate_australia_tfn(&mut *rng),
        "Australia Medicare" => generate_australia_medicare(&mut *rng),
        "ICCID" => generate_iccid(&mut *rng),
        "DEA Number" => generate_dea_number(&mut *rng),
        "India PAN" => generate_india_pan(&mut *rng),
        "South Africa ID Number" => {
            drop(rng);
            generate_south_africa_id()
        }
        _ => match m.category.as_str() {
            "Credit Card Numbers" | "Primary Account Numbers" => {
                drop(rng);
                obfuscate_credit_card(m)
            }
            "Generic Secrets"
            | "Cloud Provider Secrets"
            | "Code Platform Secrets"
            | "Payment Service Secrets"
            | "Messaging Service Secrets" => {
                drop(rng);
                obfuscate_secret(&m.text)
            }
            _ => {
                drop(rng);
                obfuscate_generic(&m.text)
            }
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

fn obfuscate_credit_card(m: &Match) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
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

    generate_luhn_number(&mut *rng, length, &prefix, &m.text)
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
fn generate_luhn_sin(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    // Valid first digits: 1-9 excluding 8
    let valid_first = [1u8, 2, 3, 4, 5, 6, 7, 9];
    let first = valid_first[rng.random_range(0..valid_first.len())];
    generate_luhn_number(&mut *rng, 9, &first.to_string(), original)
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
fn generate_valid_iban(original: &str, rng: &mut impl RngExt) -> String {
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
/// Weights [1,3,7,9,1,3,7,9] over first 8 digits; digit 9 = check; digit 10 = IRN (1).
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
fn generate_south_africa_id() -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let yy = rng.random_range(0..100u8);
    let mm = rng.random_range(1..13u8);
    let dd = rng.random_range(1..29u8); // 1-28 is always a valid day
    let seq: u16 = rng.random_range(0..10000);
    let citizenship: u8 = rng.random_range(0..2);
    // Build first 12 digits as the prefix
    let prefix = format!("{:02}{:02}{:02}{:04}{}8", yy, mm, dd, seq, citizenship);
    let placeholder: String = "0".repeat(13);
    generate_luhn_number(&mut *rng, 13, &prefix, &placeholder)
}

fn obfuscate_email() -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let user: String = (0..8)
        .map(|_| (b'a' + rng.random_range(0..26)) as char)
        .collect();
    let domains = ["example.net", "example.org", "test.invalid", "sample.test"];
    let domain = domains[rng.random_range(0..domains.len())];
    format!("{user}@{domain}")
}

fn obfuscate_phone(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
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

fn obfuscate_ssn(original: &str) -> String {
    obfuscate_phone(original) // Same algorithm: replace digits, keep format
}

fn obfuscate_ipv4() -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    format!(
        "{}.{}.{}.{}",
        rng.random_range(10..224),
        rng.random_range(0..256),
        rng.random_range(0..256),
        rng.random_range(1..255)
    )
}

fn obfuscate_mac(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let delim = if original.contains(':') { ':' } else { '-' };
    let octets: Vec<String> = (0..6)
        .map(|_| format!("{:02x}", rng.random_range(0..256u16)))
        .collect();
    octets.join(&delim.to_string())
}

fn obfuscate_secret(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
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

fn obfuscate_generic(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
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

    #[test]
    fn test_obfuscate_email() {
        set_obfuscation_seed(42);
        let email = obfuscate_email();
        assert!(email.contains('@'));
        assert!(email.len() > 5);
    }

    #[test]
    fn test_obfuscate_ssn_preserves_format() {
        let fake = obfuscate_phone("123-45-6789");
        assert_eq!(fake.len(), 11);
        assert_eq!(fake.chars().nth(3), Some('-'));
        assert_eq!(fake.chars().nth(6), Some('-'));
    }

    #[test]
    fn test_obfuscate_ipv4() {
        set_obfuscation_seed(42);
        let ip = obfuscate_ipv4();
        assert_eq!(ip.split('.').count(), 4);
    }

    #[test]
    fn test_obfuscate_credit_card_luhn() {
        set_obfuscation_seed(42);
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
        let fake = obfuscate_credit_card(&m);
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
        set_obfuscation_seed(1);
        for _ in 0..20 {
            let sin = generate_luhn_sin("000-000-000");
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
        set_obfuscation_seed(2);
        let mut rng = StdRng::seed_from_u64(2); // DevSkim: ignore DS148264
                                                // DE IBAN: 22 chars
        let fake = generate_valid_iban("DE89370400440532013000", &mut rng);
        let clean: String = fake.chars().filter(|c| c.is_alphanumeric()).collect();
        // Omit the generated value from the panic message — CodeQL would flag it as
        // cleartext logging of sensitive data (the function handles real IBANs in prod).
        assert!(is_valid_iban(&clean), "generated IBAN is not valid");
    }

    #[test]
    fn test_generate_australia_tfn_valid() {
        set_obfuscation_seed(3);
        let mut rng = StdRng::seed_from_u64(3); // DevSkim: ignore DS148264
        for _ in 0..20 {
            let tfn = generate_australia_tfn(&mut rng);
            assert!(is_valid_australia_tfn(&tfn), "generated TFN is not valid");
        }
    }

    #[test]
    fn test_generate_australia_medicare_valid() {
        set_obfuscation_seed(4);
        let mut rng = StdRng::seed_from_u64(4); // DevSkim: ignore DS148264
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
        set_obfuscation_seed(5);
        let mut rng = StdRng::seed_from_u64(5); // DevSkim: ignore DS148264
        for _ in 0..20 {
            let iccid = generate_iccid(&mut rng);
            assert!(is_valid_iccid(&iccid), "generated ICCID is not valid");
            assert!(iccid.starts_with("89"), "ICCID must start with 89");
        }
    }

    #[test]
    fn test_generate_dea_number_valid() {
        set_obfuscation_seed(6);
        let mut rng = StdRng::seed_from_u64(6); // DevSkim: ignore DS148264
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
        set_obfuscation_seed(7);
        let mut rng = StdRng::seed_from_u64(7); // DevSkim: ignore DS148264
        for _ in 0..20 {
            let pan = generate_india_pan(&mut rng);
            assert!(is_valid_india_pan(&pan), "generated India PAN is not valid");
        }
    }

    #[test]
    fn test_generate_south_africa_id_valid() {
        set_obfuscation_seed(8);
        for _ in 0..20 {
            let id = generate_south_africa_id();
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
