//! Input validation and Luhn card number checking.

use crate::errors::DlpError;

/// Maximum input size (10 MB).
pub const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Validate scanner input text.
pub fn validate_text_input(text: &str) -> crate::Result<()> {
    if text.is_empty() {
        return Err(DlpError::EmptyInput);
    }
    if text.len() > MAX_INPUT_SIZE {
        return Err(DlpError::InputTooLarge {
            size: text.len(),
            max: MAX_INPUT_SIZE,
        });
    }
    Ok(())
}

/// Validate a credit-card number using the Luhn algorithm.
pub fn is_luhn_valid(card_number: &str) -> bool {
    let digits: Vec<u32> = card_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Minimum 12 digits for valid card numbers; reject trivial sequences
    if digits.len() < 12 {
        return false;
    }

    // Reject all-same-digit sequences (e.g., "0000000000000000")
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    let total: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    total % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        assert!(is_luhn_valid("4532015112830366"));
        assert!(is_luhn_valid("4532-0151-1283-0366"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!is_luhn_valid("1234567890123456"));
    }

    #[test]
    fn test_luhn_empty() {
        assert!(!is_luhn_valid(""));
    }

    #[test]
    fn test_validate_empty() {
        assert!(matches!(validate_text_input(""), Err(DlpError::EmptyInput)));
    }

    #[test]
    fn test_validate_normal() {
        assert!(validate_text_input("hello world").is_ok());
    }

    #[test]
    fn test_luhn_rejects_short() {
        // Less than 12 digits should fail
        assert!(!is_luhn_valid("123456789")); // 9 digits
        assert!(!is_luhn_valid("12345678901")); // 11 digits
    }

    #[test]
    fn test_luhn_accepts_12_plus() {
        // 16-digit valid Visa
        assert!(is_luhn_valid("4532015112830366"));
    }

    #[test]
    fn test_luhn_rejects_all_zeros() {
        assert!(!is_luhn_valid("0000000000000000"));
        assert!(!is_luhn_valid("000000000000"));
    }

    #[test]
    fn test_luhn_rejects_all_same_digit() {
        assert!(!is_luhn_valid("1111111111111111"));
        assert!(!is_luhn_valid("5555555555555555"));
        assert!(!is_luhn_valid("9999999999999999"));
    }
}
