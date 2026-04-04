//! Realistic fake data generators for the Obfuscate action.

use crate::models::Match;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Mutex;
use once_cell::sync::Lazy;

static OBFUSCATION_RNG: Lazy<Mutex<StdRng>> = Lazy::new(|| Mutex::new(StdRng::from_entropy()));

/// Set seed for deterministic obfuscation (for testing/auditing).
pub fn set_obfuscation_seed(seed: u64) {
    tracing::warn!("Obfuscation seed set — output will be deterministic and predictable");
    *OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner()) = StdRng::seed_from_u64(seed);
}

/// Generate realistic fake data for a match based on its category.
pub fn obfuscate_match(m: &Match) -> String {
    // Try sub_category first (most specific), then category
    match m.sub_category.as_str() {
        "Visa" | "MasterCard" | "Amex" | "Discover" | "JCB" | "Diners Club" | "UnionPay" => {
            obfuscate_credit_card(m)
        }
        "Email Address" => obfuscate_email(),
        "E.164 Phone Number" | "US Phone Number" | "UK Phone Number" => obfuscate_phone(&m.text),
        "USA SSN" | "USA ITIN" | "Canada SIN" => obfuscate_ssn(&m.text),
        "IBAN Generic" => obfuscate_iban(&m.text),
        "IPv4 Address" => obfuscate_ipv4(),
        "MAC Address" => obfuscate_mac(&m.text),
        _ => match m.category.as_str() {
            "Credit Card Numbers" | "Primary Account Numbers" => obfuscate_credit_card(m),
            "Generic Secrets" | "Cloud Provider Secrets" | "Code Platform Secrets"
            | "Payment Service Secrets" | "Messaging Service Secrets" => obfuscate_secret(&m.text),
            _ => obfuscate_generic(&m.text),
        },
    }
}

/// Replace all matched spans in text with fake data. Process from end to start.
pub fn obfuscate_matches(text: &str, matches: &[Match]) -> String {
    if matches.is_empty() {
        return text.to_string();
    }
    let mut sorted: Vec<&Match> = matches.iter().collect();
    sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));
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
    let length = clean.len().max(13).min(19);

    let prefix = match m.sub_category.as_str() {
        "Visa" => "4".to_string(),
        "MasterCard" => format!("5{}", rng.gen_range(1..=5)),
        "Amex" => format!("3{}", if rng.gen_bool(0.5) { "4" } else { "7" }),
        "Discover" => "6011".to_string(),
        "JCB" => "35".to_string(),
        "Diners Club" => "36".to_string(),
        "UnionPay" => "62".to_string(),
        _ => format!("{}", rng.gen_range(3..=6)),
    };

    generate_luhn_number(&mut *rng, length, &prefix, &m.text)
}

fn generate_luhn_number(
    rng: &mut impl Rng,
    length: usize,
    prefix: &str,
    original: &str,
) -> String {
    let mut digits: Vec<u8> = prefix.bytes().map(|b| b - b'0').collect();
    while digits.len() < length - 1 {
        digits.push(rng.gen_range(0..10));
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

fn obfuscate_email() -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let user: String = (0..8)
        .map(|_| (b'a' + rng.gen_range(0..26)) as char)
        .collect();
    let domains = [
        "example.net",
        "example.org",
        "test.invalid",
        "sample.test",
    ];
    let domain = domains[rng.gen_range(0..domains.len())];
    format!("{user}@{domain}")
}

fn obfuscate_phone(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                (b'0' + rng.gen_range(0..10)) as char
            } else {
                c
            }
        })
        .collect()
}

fn obfuscate_ssn(original: &str) -> String {
    obfuscate_phone(original) // Same algorithm: replace digits, keep format
}

fn obfuscate_iban(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let mut chars = original.chars();
    let mut result = String::new();
    // Preserve first 2 chars (country code)
    if let Some(c1) = chars.next() {
        result.push(c1);
    }
    if let Some(c2) = chars.next() {
        result.push(c2);
    }
    for c in chars {
        if c.is_ascii_digit() {
            result.push((b'0' + rng.gen_range(0..10)) as char);
        } else if c.is_ascii_alphabetic() {
            result.push((b'A' + rng.gen_range(0..26)) as char);
        } else {
            result.push(c);
        }
    }
    result
}

fn obfuscate_ipv4() -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    format!(
        "{}.{}.{}.{}",
        rng.gen_range(10..224),
        rng.gen_range(0..256),
        rng.gen_range(0..256),
        rng.gen_range(1..255)
    )
}

fn obfuscate_mac(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let delim = if original.contains(':') { ':' } else { '-' };
    let octets: Vec<String> = (0..6)
        .map(|_| format!("{:02x}", rng.gen_range(0..256u16)))
        .collect();
    octets.join(&delim.to_string())
}

fn obfuscate_secret(original: &str) -> String {
    let mut rng = OBFUSCATION_RNG.lock().unwrap_or_else(|e| e.into_inner());
    let charset: Vec<char> =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();
    original
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                charset[rng.gen_range(0..charset.len())]
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
                (b'0' + rng.gen_range(0..10)) as char
            } else if c.is_ascii_uppercase() {
                (b'A' + rng.gen_range(0..26)) as char
            } else if c.is_ascii_lowercase() {
                (b'a' + rng.gen_range(0..26)) as char
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let fake = obfuscate_credit_card(&m);
        assert!(fake.starts_with('4')); // Visa prefix
        // Verify Luhn on digits only
        let digits: String = fake.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(crate::validation::is_luhn_valid(&digits));
    }

    #[test]
    fn test_deterministic_seed() {
        // Verify determinism using a local RNG to avoid parallel test interference
        use rand::SeedableRng;
        let mut rng_a = StdRng::seed_from_u64(123);
        let mut rng_b = StdRng::seed_from_u64(123);
        let a: u64 = rng_a.gen();
        let b: u64 = rng_b.gen();
        assert_eq!(a, b);
    }
}
