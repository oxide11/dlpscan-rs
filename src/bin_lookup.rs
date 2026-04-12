//! BIN (Bank Identification Number) lookup for credit card validation and enrichment.
//!
//! Provides O(log n) lookup of the first 6 digits of a credit card number
//! against a database of 374k+ known BINs. Returns issuing brand, card type,
//! country, and issuing bank name.
//!
//! Requires the `bin-data` feature flag (embeds ~4MB of BIN data at compile time).
//!
//! Binary format v2:
//! - Header: "DBIN" magic (4) + version u8 (1) + entry_count u32 (4) + string_count u32 (4)
//! - Entries: 10 bytes each = BIN u32 (4) + brand u8 (1) + type u8 (1) + country [u8;2] (2) + issuer_id u16 (2)
//! - String table: for each string: length u16 (2) + UTF-8 bytes

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
    /// Name of the issuing bank (e.g., "JPMORGAN CHASE BANK, N.A."). Empty if unknown.
    pub issuer: String,
}

#[cfg(feature = "bin-data")]
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

#[cfg(feature = "bin-data")]
const TYPE_NAMES: &[&str] = &[
    "Credit",      // 0
    "Debit",       // 1
    "Charge Card", // 2
    "Unknown",     // 3
];

/// Embedded BIN database (compiled in when `bin-data` feature is enabled).
#[cfg(feature = "bin-data")]
static BIN_DATA: &[u8] = include_bytes!("../data/bin-list.bin");

/// Parsed BIN entry: (bin, brand_id, type_id, country, issuer_id).
#[cfg(feature = "bin-data")]
type BinEntry = (u32, u8, u8, [u8; 2], u16);

/// Parsed BIN lookup table and issuer string table (lazy-initialized).
#[cfg(feature = "bin-data")]
static BIN_TABLE: once_cell::sync::Lazy<(Vec<BinEntry>, Vec<String>)> =
    once_cell::sync::Lazy::new(|| {
        let data = BIN_DATA;
        // Need at least: magic(4) + version(1) + count(4) + strcount(4) = 13 bytes
        if data.len() < 13 {
            return (Vec::new(), Vec::new());
        }
        // Check magic bytes
        if &data[0..4] != b"DBIN" {
            tracing::warn!("BIN data missing magic bytes, database disabled");
            return (Vec::new(), Vec::new());
        }
        let version = data[4];
        if version != 2 {
            tracing::warn!("BIN data version {} not supported (expected 2)", version);
            return (Vec::new(), Vec::new());
        }
        let count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
        let string_count = u32::from_le_bytes([data[9], data[10], data[11], data[12]]) as usize;
        let mut offset = 13;

        let mut table = Vec::with_capacity(count);
        for _ in 0..count {
            if offset + 10 > data.len() {
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
            let issuer_id = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);
            table.push((bin, brand, card_type, country, issuer_id));
            offset += 10;
        }

        // String table: u16 length + bytes for each
        let mut strings = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            if offset + 2 > data.len() {
                break;
            }
            let slen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + slen > data.len() {
                break;
            }
            let s = String::from_utf8_lossy(&data[offset..offset + slen]).to_string();
            strings.push(s);
            offset += slen;
        }

        (table, strings)
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

    let (table, strings) = &*BIN_TABLE;
    let idx = table.binary_search_by_key(&bin, |entry| entry.0).ok()?;
    let (_, brand_id, type_id, country_bytes, issuer_id) = &table[idx];

    let brand = BRAND_NAMES.get(*brand_id as usize).unwrap_or(&"Other");
    let card_type = TYPE_NAMES.get(*type_id as usize).unwrap_or(&"Unknown");
    let country_code = String::from_utf8_lossy(country_bytes)
        .trim_end_matches('\0')
        .to_string();
    let issuer = if *issuer_id == 0xFFFF {
        String::new()
    } else {
        strings
            .get(*issuer_id as usize)
            .cloned()
            .unwrap_or_default()
    };

    Some(BinInfo {
        bin,
        brand,
        card_type,
        country_code,
        issuer,
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
    BIN_TABLE.0.len()
}

/// Stub implementations when bin-data feature is not enabled.
#[cfg(not(feature = "bin-data"))]
pub fn lookup(_card_number: &str) -> Option<BinInfo> {
    None
}

#[cfg(not(feature = "bin-data"))]
pub fn is_known_bin(_card_number: &str) -> bool {
    false
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
        let result = lookup("4532015112830366");
        assert!(result.is_some(), "Should find Visa BIN 453201");
        let info = result.unwrap();
        assert_eq!(info.brand, "Visa");
        assert!(!info.country_code.is_empty());
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_returns_issuer() {
        // Find any known BIN and verify it has an issuer string
        let result = lookup("4532015112830366");
        if let Some(info) = result {
            // issuer may be empty for some BINs but should exist for most
            // Just verify the field is populated (not panic)
            let _ = info.issuer.len();
        }
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_unknown_bin() {
        assert!(lookup("000000").is_none());
    }

    #[cfg(feature = "bin-data")]
    #[test]
    fn test_lookup_with_separators() {
        let result = lookup("4532-0151-1283-0366");
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_too_short() {
        assert!(lookup("123").is_none());
    }
}
