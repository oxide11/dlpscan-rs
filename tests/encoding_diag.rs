//! Encoding bypass diagnostic.
//! Generates correct encoded forms of a known PAN, then tests detection.
//! Run: cargo test --test encoding_diag -- --nocapture

use base64::{engine::general_purpose, Engine};
use siphon_core::scanner::scan_text;

const PAN: &str = "4532015112830366"; // valid Luhn Visa

fn detects_cc(text: &str) -> bool {
    let m = scan_text(text).unwrap_or_default();
    m.iter().any(|m| {
        m.category.contains("Credit Card") || m.sub_category == "Visa" || m.sub_category == "PAN"
    })
}

fn base32hex_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0u8;
    for &b in input {
        bits = (bits << 8) | b as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            out.push(ALPHA[((bits >> bit_count) & 0x1F) as usize] as char);
        }
    }
    if bit_count > 0 {
        out.push(ALPHA[((bits << (5 - bit_count)) & 0x1F) as usize] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn base32_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0u8;
    for &b in input {
        bits = (bits << 8) | b as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            out.push(ALPHA[((bits >> bit_count) & 0x1F) as usize] as char);
        }
    }
    if bit_count > 0 {
        out.push(ALPHA[((bits << (5 - bit_count)) & 0x1F) as usize] as char);
    }
    // Pad to multiple of 8
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn hex_encode(input: &[u8]) -> String {
    input.iter().map(|b| format!("{:02x}", b)).collect()
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn percent_encode_all(s: &str) -> String {
    s.bytes().map(|b| format!("%{:02X}", b)).collect()
}

fn percent_encode_digits(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_digit() {
                format!("%{:02X}", c as u8)
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[test]
fn encoding_variant_matrix() {
    let pan_bytes = PAN.as_bytes();

    let b64_std = general_purpose::STANDARD.encode(pan_bytes);
    let b64_no_pad = b64_std.trim_end_matches('=').to_string();
    // URL-safe base64: replace + with - and / with _
    let b64_url = general_purpose::URL_SAFE.encode(pan_bytes);
    // Double base64: base64 of the base64 string
    let b64_double = general_purpose::STANDARD.encode(b64_std.as_bytes());
    // base64 with MIME line break (76 chars per line, CRLF) — PAN b64 is 24 chars so no break; use artificial split
    let b64_mime_split = format!("{}\r\n{}", &b64_std[..12], &b64_std[12..]);

    let b32_std = base32_encode(pan_bytes);
    let b32_no_pad = b32_std.trim_end_matches('=').to_string();
    let b32_lower = b32_std.to_lowercase();
    let b32hex = base32hex_encode(pan_bytes);
    let b32hex_lower = b32hex.to_lowercase();

    let hex_lower = hex_encode(pan_bytes);
    let hex_upper = hex_encode(pan_bytes).to_uppercase();
    let hex_0x = format!("0x{}", hex_lower);
    let hex_escaped: String = pan_bytes.iter().map(|b| format!("\\x{:02x}", b)).collect();
    let hex_spaced: String = pan_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    // ROT13 of the PAN: digits unchanged, but test the function
    let rot13_pan = rot13(PAN);

    // URL encoding
    let url_full = percent_encode_all(PAN);
    let url_partial = percent_encode_digits(PAN);
    // Double URL encoding (%XX → %25XX)
    let url_double: String = percent_encode_all(PAN).replace('%', "%25");

    // Chained
    let b64_of_rot13 = general_purpose::STANDARD.encode(rot13(PAN).as_bytes());
    let b64_of_hex = general_purpose::STANDARD.encode(hex_lower.as_bytes());
    let hex_of_b64 = hex_encode(b64_std.as_bytes());
    let rot13_of_b64 = rot13(&b64_std);
    let url_of_b64: String = b64_std
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '+' || c == '/' || c == '=' {
                format!("%{:02X}", c as u8)
            } else {
                c.to_string()
            }
        })
        .collect();

    let cases: &[(&str, &str)] = &[
        ("b64_standard", &b64_std),
        ("b64_no_padding", &b64_no_pad),
        ("b64_urlsafe", &b64_url),
        ("b64_double", &b64_double),
        ("b64_mime_split", &b64_mime_split),
        ("b32_standard", &b32_std),
        ("b32_no_padding", &b32_no_pad),
        ("b32_lowercase", &b32_lower),
        ("b32hex_upper", &b32hex),
        ("b32hex_lower", &b32hex_lower),
        ("hex_lowercase", &hex_lower),
        ("hex_uppercase", &hex_upper),
        ("hex_0x_prefix", &hex_0x),
        ("hex_escaped", &hex_escaped),
        ("hex_spaced", &hex_spaced),
        ("rot13_of_pan", &rot13_pan),
        ("url_pct_full", &url_full),
        ("url_pct_digits", &url_partial),
        ("url_double", &url_double),
        ("b64_of_rot13", &b64_of_rot13),
        ("b64_of_hex", &b64_of_hex),
        ("hex_of_b64", &hex_of_b64),
        ("rot13_of_b64", &rot13_of_b64),
        ("url_of_b64", &url_of_b64),
    ];

    println!("\n=== Encoding Bypass Diagnostic ===");
    println!("PAN under test: {}", PAN);
    println!();

    let mut pass = 0usize;
    let mut fail_list = Vec::new();

    for (name, payload) in cases {
        let detected = detects_cc(payload);
        let status = if detected { "DETECT ✓" } else { "BYPASS ✗" };
        println!(
            "{:<22} {:<65} {}",
            name,
            &payload[..payload.len().min(65)],
            status
        );
        if detected {
            pass += 1;
        } else {
            fail_list.push(*name);
        }
    }

    let total = cases.len();
    let fail_count = fail_list.len();
    let bypass_pct = (fail_count as f64 / total as f64) * 100.0;
    println!();
    println!(
        "Result: {}/{} detected ({:.1}% bypass rate)",
        pass, total, bypass_pct
    );
    if !fail_list.is_empty() {
        println!("Bypassed variants: {:?}", fail_list);
    }

    // Fail the test if any bypass remains — remove this assert to just run as a report
    if !fail_list.is_empty() {
        panic!(
            "{} encoding variants bypass detection (bypass rate: {:.1}%): {:?}",
            fail_count, bypass_pct, fail_list
        );
    }
}
