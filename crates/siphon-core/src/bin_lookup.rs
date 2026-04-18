//! BIN (Bank Identification Number) lookup for credit card validation and enrichment.
//!
//! Provides O(1) lookup of the first 6 digits of a credit card number against
//! a database of 374k+ known BINs. Returns issuing brand, card type, and country.
//!
//! Requires the `bin-data` feature flag (embeds ~3MB of BIN data at compile time).

/// BIN lookup result with card metadata.
#[derive(Debug, Clone)]
pub struct BinInfo {
    /// 6-digit BIN prefix.
    pub bin: u32,
    /// Card brand (Visa, MasterCard, etc.).
    pub brand: &'static str,
    /// Card type (Credit, Debit, Charge Card).
    pub card_type: &'static str,
    /// ISO 3166-1 alpha-2 country code of the issuing bank.
    pub country_code: String,
}

const BRAND_NAMES: &[&str] = &[
    "Visa",                      // 0
    "MasterCard",                // 1
    "American Express",          // 2
    "Discover",                  // 3
    "JCB",                       // 4
    "Diners Club International", // 5
    "Maestro",                   // 6
    "China Union Pay",           // 7
    "EBT",                       // 8
    "Private Label",             // 9
    "RuPay",                     // 10
    "MIR",                       // 11
    "EFTPOS",                    // 12
    "Verve",                     // 13
    "UATP",                      // 14
    "Other",                     // 15
];

const TYPE_NAMES: &[&str] = &[
    "Credit",      // 0
    "Debit",       // 1
    "Charge Card", // 2
    "Unknown",     // 3
];

/// Embedded BIN database (compiled in when `bin-data` feature is enabled).
#[cfg(feature = "bin-data")]
static BIN_DATA: &[u8] = include_bytes!("../data/bin-list.bin");

/// Parsed BIN lookup table (lazy-initialized on first use).
#[cfg(feature = "bin-data")]
static BIN_TABLE: once_cell::sync::Lazy<Vec<(u32, u8, u8, [u8; 2])>> =
    once_cell::sync::Lazy::new(|| {
        let data = BIN_DATA;
        if data.len() < 4 {
            return Vec::new();
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut table = Vec::with_capacity(count);
        let mut offset = 4;
        for _ in 0..count {
            if offset + 8 > data.len() {
                break;
            }
            let bin = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let brand = data[offset + 4];
            let card_type = data[offset + 5];
            let country = [data[offset + 6], data[offset + 7]];
            table.push((bin, brand, card_type, country));
            offset += 8;
        }
        table
    });

/// Look up a BIN (first 6 digits of a card number) in the database.
///
/// Returns `Some(BinInfo)` if the BIN is found, `None` otherwise.
/// The input can be a full card number or just the 6-digit prefix.
#[cfg(feature = "bin-data")]
pub fn lookup(card_number: &str) -> Option<BinInfo> {
    let digits: String = card_number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 6 {
        return None;
    }
    let bin_str = &digits[..6];
    let bin: u32 = bin_str.parse().ok()?;

    // Binary search on sorted table
    let table = &*BIN_TABLE;
    let idx = table.binary_search_by_key(&bin, |entry| entry.0).ok()?;
    let (_, brand_id, type_id, country_bytes) = &table[idx];

    let brand = BRAND_NAMES.get(*brand_id as usize).unwrap_or(&"Other");
    let card_type = TYPE_NAMES.get(*type_id as usize).unwrap_or(&"Unknown");
    let country_code = String::from_utf8_lossy(country_bytes)
        .trim_end_matches('\0')
        .to_string();

    Some(BinInfo {
        bin,
        brand,
        card_type,
        country_code,
    })
}

/// Check if a BIN exists in the database (fast boolean check).
#[cfg(feature = "bin-data")]
pub fn is_known_bin(card_number: &str) -> bool {
    lookup(card_number).is_some()
}

/// Get the total number of BINs in the database.
#[cfg(feature = "bin-data")]
pub fn bin_count() -> usize {
    BIN_TABLE.len()
}

/// Stub implementations when bin-data feature is not enabled.
#[cfg(not(feature = "bin-data"))]
pub fn lookup(_card_number: &str) -> Option<BinInfo> {
    None
}

#[cfg(not(feature = "bin-data"))]
pub fn is_known_bin(_card_number: &str) -> bool {
    false // Can't validate without data
}

#[cfg(not(feature = "bin-data"))]
pub fn bin_count() -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_bin_table_loads() {
        assert!(bin_count() > 300_000, "Should have 300k+ BINs loaded");
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_visa() {
        // 453201 is a known Visa BIN (Citibank)
        let result = lookup("4532015112830366");
        assert!(result.is_some(), "Should find Visa BIN 453201");
        let info = result.unwrap();
        assert_eq!(info.brand, "Visa");
        assert!(!info.country_code.is_empty());
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_unknown_bin() {
        // 000000 is not a real BIN
        assert!(lookup("000000").is_none());
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_with_separators() {
        // Should work with dashes/spaces
        let result = lookup("4532-0151-1283-0366");
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_too_short() {
        assert!(lookup("123").is_none());
    }
}
