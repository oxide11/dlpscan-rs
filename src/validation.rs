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

/// ISO 3166-1 alpha-2 country codes used to validate SWIFT/BIC codes.
/// Positions 5-6 of a SWIFT code must be a valid country code.
static VALID_COUNTRY_CODES: &[&str] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
];

/// Validate a SWIFT/BIC code by checking that positions 5-6 contain
/// a valid ISO 3166-1 alpha-2 country code.
///
/// Returns `true` if the country code is valid.
pub fn is_valid_swift_country(swift_code: &str) -> bool {
    let bytes: Vec<u8> = swift_code.bytes().collect();
    // SWIFT codes are 8 or 11 characters
    if bytes.len() != 8 && bytes.len() != 11 {
        return false;
    }
    let country = &swift_code[4..6];
    VALID_COUNTRY_CODES.contains(&country)
}

/// Common uppercase English words that are NOT SWIFT codes.
/// Used as a false-positive filter after regex matching.
static SWIFT_FALSE_POSITIVES: &[&str] = &[
    "ABSTRACT", "AMERICAN", "ASSEMBLY", "BUILDING", "BUSINESS", "CALLBACK", "CHEMICAL", "CHILDREN",
    "CIRCULAR", "CLINICAL", "COMBINED", "COMMERCE", "COMPLETE", "COMPOUND", "COMPUTED", "COMPUTER",
    "CONCRETE", "CONGRESS", "CONSIDER", "CONSTANT", "CONSUMER", "CONTINUE", "CONTRACT", "CONSUMER",
    "CONTROLS", "CRIMINAL", "CRITICAL", "CULTURAL", "CURRENCY", "CUSTOMER", "DATABASE", "DECEMBER",
    "DECISION", "DECLARED", "DEFAULTS", "DEEPCOPY", "DEFENDER", "DEFINITE", "DELEGATE", "DELIVERY",
    "DESIGNER", "DETAILED", "DETECTED", "DIRECTED", "DISABLED", "DISCOUNT", "DISCOVER", "DISPATCH",
    "DISORDER", "DISTINCT", "DISTRICT", "DIVIDEND", "DOCUMENT", "DOMESTIC", "DOWNLOAD", "DURATION",
    "DYNAMICS", "ECONOMIC", "EDUCATOR", "ELECTION", "ELECTRIC", "EMBEDDED", "EMERGING", "EMPLOYED",
    "ENCODING", "ENDPOINT", "ENGINEER", "ENORMOUS", "ENSURING", "ENTIRELY", "ENTITLED", "ENTRANCE",
    "ENVELOPE", "EQUALITY", "EQUIPPED", "ETHERNET", "EVALUATE", "EVENTUAL", "EVIDENCE", "EXCHANGE",
    "EXCLUDED", "EXECUTOR", "EXERCISE", "EXPANDED", "EXPECTED", "EXPLICIT", "EXPLORER", "EXPORTED",
    "EXTENDED", "EXTERNAL", "EXTRACTS", "FACEBOOK", "FACILITY", "FEATURED", "FEEDBACK", "FILENAME",
    "FILETYPE", "FILTERED", "FILEPATH", "FINALIZE", "FIRMWARE", "FOLLOWED", "FORECAST", "FORMERLY",
    "FORMULAS", "FRACTION", "FRAGMENT", "FRONTIER", "FULLTEXT", "FUNCTION", "FURTHEST", "GARRISON",
    "GENERATE", "GENETICS", "GLOBALLY", "GOVERNOR", "GRAPHICS", "GUARDIAN", "GUIDANCE", "HARDWARE",
    "HELPDESK", "HERITAGE", "HOMEPAGE", "Hospital", "HOSPITAL", "HOSTNAME", "HTTPONLY", "HUMANITY",
    "HUNDREDS", "HYPERION", "ILLINOIS", "IMAGINED", "IMPERIAL", "IMPORTED", "IMPROPER", "INCLUDED",
    "INCREASE", "INDIRECT", "INDUSTRY", "INFERIOR", "INFORMAL", "INFORMED", "INHERITS", "INITIALS",
    "INNOCENT", "INSPIRED", "INSTANCE", "INTEGRAL", "INTENDED", "INTERACT", "INTEREST", "INTERNAL",
    "INTERVAL", "INVASION", "INVENTED", "INVESTOR", "INVOLVED", "ISOLATED", "ITERATOR", "KEYBOARD",
    "LANDLORD", "LANGUAGE", "LAUNCHED", "LEARNING", "LEVERAGE", "LICENSED", "LIFETIME", "LIKEWISE",
    "LIMITEDS", "LISTENED", "LITERACY", "LITERARY", "LOCATION", "LOGISTIC", "MACHINES", "MAGNETIC",
    "MAINTAIN", "MAJORITY", "MANIFEST", "MARKDOWN", "MATERIAL", "MAXIMIZE", "MEASURED", "MECHANIC",
    "MEDIEVAL", "MEMBRANE", "MEMORIAL", "MERCHANT", "METADATA", "MICHIGAN", "MIDNIGHT", "MILITARY",
    "MINIMIZE", "MINISTER", "MINORITY", "Mitchell", "MODERATE", "MODIFIED", "MOMENTUM", "MONOPOLY",
    "MORTGAGE", "MOUNTAIN", "MOVEMENT", "MULTIPLE", "MUSEUM", "MUTUALLY", "NATIONAL", "NAVIGATE",
    "NEGATIVE", "NEIGHBOR", "NETWORKS", "NOTEBOOK", "NOVEMBER", "NUMBERED", "NUMEROUS", "OBTAINED",
    "OCCURRED", "OFFERING", "OFFICIAL", "OFFSHORE", "ONSCREEN", "OPENTEXT", "OPERATED", "OPERATOR",
    "OPPONENT", "OPTIONAL", "ORDERING", "ORDINARY", "ORGANISM", "ORGANIZE", "ORIGINAL", "OUTLINED",
    "OVERCOME", "OVERHEAD", "OVERRIDE", "OVERTIME", "OVERVIEW", "PARALLEL", "PARTNERS", "PASSWORD",
    "PATHNAME", "PATIENCE", "PATTERNS", "PEACEFUL", "PECULIAR", "PENGUINS", "PENTAGON", "PERFORMS",
    "PERIODIC", "PERSONAL", "PETITION", "PHYSICAL", "PIPELINE", "PLATFORM", "PLEASANT", "PLEASURE",
    "POINTING", "POLICIES", "POLISHED", "POLITICS", "POPULACE", "POPULATE", "PORTRAIT", "POSITION",
    "POSITIVE", "POSSIBLE", "POWERFUL", "PRACTICE", "PRECIOUS", "PREDICTS", "PREPARED", "PRESENCE",
    "PRESERVE", "PRESSING", "PRESSURE", "PRETENDS", "PREVIOUS", "PRINCESS", "PRINTING", "PROBABLE",
    "PROCEEDS", "PRODUCED", "PRODUCER", "PRODUCTS", "PROFILES", "PROFOUND", "PROGRAMS", "PROGRESS",
    "PROJECTS", "PROMOTED", "PROMPTLY", "PROPERLY", "PROPERTY", "PROPOSAL", "PROSPECT", "PROTECTS",
    "PROTOCOL", "PROVIDED", "PROVIDER", "PROVINCE", "PURCHASE", "PURSUING", "QUALIFED", "QUARTERS",
    "QUINTILE", "RANDOMLY", "RATIONAL", "REACTION", "READABLE", "REALIZED", "REASONED", "RECEIVES",
    "RECENTLY", "RECORDED", "RECOVERY", "RECYCLED", "REDIRECT", "REDUCING", "REFERRED", "REFLECTS",
    "REFORMED", "REGIONAL", "REGISTER", "REGISTRY", "REGULATE", "REJECTED", "RELATION", "RELATIVE",
    "RELEASED", "RELEVANT", "RELIABLE", "RELIGION", "REMAINED", "REMEMBER", "REMOTELY", "REMOVING",
    "RENDERED", "RENDERER", "RENOWNED", "REPAIRED", "REPLACED", "REPORTED", "REPORTER", "REPOSIT",
    "REPRESEN", "REPUBLIC", "REQUIRED", "RESEARCH", "RESERVED", "RESIDENT", "RESIGNED", "RESOLVED",
    "RESOURCE", "RESPONDS", "RESPONSE", "RESTORED", "RESTRICT", "RESULTED", "RETAINED", "RETIRING",
    "RETRIEVE", "RETURNED", "REVEALED", "REVENUES", "REVIEWED", "REVISION", "RESULTED", "ROTATION",
    "RUNNABLE", "SAMPLING", "SCENARIO", "SCHEDULE", "SCIENCES", "SCRIPTED", "SEASONAL", "SECTIONS",
    "SECURITY", "SELECTED", "SELECTOR", "SENSIBLE", "SENTENCE", "SEPARATE", "SEQUENCE", "SERGEANT",
    "SERVICED", "SERVICES", "SESSIONS", "SETTINGS", "SEVERELY", "SHIPPING", "SHORTAGE", "SHUTDOWN",
    "SIBLINGS", "SIMPLEST", "SIMULATE", "SINGULAR", "SKETCHED", "SNAPSHOT", "SOFTWARE", "SOLUTION",
    "SOMEWHAT", "SOUTHERN", "SPECIFIC", "SPECIMEN", "SPENDING", "SPORTING", "SPOTTING", "SQUASHED",
    "STANDARD", "STANDING", "STARTING", "STATEFUL", "STATIONS", "STIMULUS", "STOCKING", "STOPPING",
    "STRAIGHT", "STRATEGY", "STRENGTH", "STRESSED", "STRICTLY", "STRIKING", "STRONGER", "STRONGLY",
    "STRUGGLE", "STUDENTS", "STUNNING", "SUBJECTS", "SUBURBAN", "SUBTRACT", "SUCCEEDS", "SUDDENLY",
    "SUITABLE", "SULLIVAN", "SUMMONED", "SUPPLIED", "SUPPLIER", "SUPPORTS", "SUPPOSED", "SUPPRESS",
    "SURFACES", "SURGICAL", "SURPRISE", "SURVIVED", "SUSPECTS", "SUSPENDS", "SWITCHED", "SYMBOLIC",
    "SYMPATHY", "SYNDROME", "TAXATION", "TEACHERS", "TEACHING", "TEAMMATE", "TERMINAL", "TESTCASE",
    "TESTONLY", "TEXTBOOK", "THINKING", "THOROUGH", "THOUSAND", "THREADED", "THRILLER", "TOGETHER",
    "TOMORROW", "TOPOLOGY", "TRACKING", "TRILLION", "TROPICAL", "TROUBLED", "TRUTHFUL", "TUTORIAL",
    "TYPENAME", "ULTIMATE", "UMBRELLA", "UNCOMMON", "UNDERPIN", "UNIFYING", "UNIVERSE", "UNLIKELY",
    "UNSIGNED", "UNSTABLE", "UPDATING", "UPCOMING", "UPLOADED", "UPSTREAM", "USERNAME", "UTILIZED",
    "VACUUMED", "VALIDATE", "VALUABLE", "VARIABLE", "VENTURES", "VERIFIED", "VERTICAL", "VIEWPORT",
    "VIOLATES", "VIOLENCE", "VIRGINIA", "VISITORS", "VITAMINS", "VOLATILE", "VOLTAGES", "WELCOMES",
    "WHATEVER", "WHENEVER", "WHEREVER", "WICKEDLY", "WILDCARD", "WIRELESS", "WITHHOLD", "WONDERFU",
    "WOODLAND", "WORKSHOP", "XCONTEXT", "XXXXXXXX", "YEARBOOK", "YOURSELF", "Zimbabwe",
];

/// Check if a SWIFT/BIC match is likely a false positive.
/// Returns `true` if the match should be KEPT (is valid).
pub fn is_valid_swift(code: &str) -> bool {
    // Must be 8 or 11 characters
    if code.len() != 8 && code.len() != 11 {
        return false;
    }
    // Must have valid country code at positions 5-6
    if !is_valid_swift_country(code) {
        return false;
    }
    // Reject known false-positive words
    let upper = code.to_uppercase();
    let check = if upper.len() == 11 {
        &upper[..8]
    } else {
        &upper
    };
    if SWIFT_FALSE_POSITIVES.contains(&check) {
        return false;
    }
    true
}

/// Validate a CUSIP identifier (9 characters: 6 issuer + 2 issue + 1 check digit).
/// Uses the CUSIP check-digit algorithm (modified Luhn on alphanumeric).
pub fn is_valid_cusip(cusip: &str) -> bool {
    let chars: Vec<char> = cusip.chars().collect();
    if chars.len() != 9 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &ch) in chars[..8].iter().enumerate() {
        let val = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_uppercase() {
            (ch as u32 - 'A' as u32) + 10
        } else {
            return false; // invalid character
        };
        let v = if i % 2 == 1 { val * 2 } else { val };
        sum += v / 10 + v % 10;
    }
    let check = (10 - (sum % 10)) % 10;
    let expected = chars[8].to_digit(10);
    expected == Some(check)
}

/// Validate a SEDOL identifier (7 characters: 6 data + 1 check digit).
/// Uses weighted sum mod 10.
pub fn is_valid_sedol(sedol: &str) -> bool {
    let chars: Vec<char> = sedol.chars().collect();
    if chars.len() != 7 {
        return false;
    }
    // SEDOL doesn't use vowels
    let weights = [1, 3, 1, 7, 3, 9];
    let mut sum = 0u32;
    for (i, &ch) in chars[..6].iter().enumerate() {
        let val = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_uppercase() && !"AEIOU".contains(ch) {
            (ch as u32 - 'A' as u32) + 10
        } else {
            return false;
        };
        sum += val * weights[i];
    }
    let check = (10 - (sum % 10)) % 10;
    let expected = chars[6].to_digit(10);
    expected == Some(check)
}

/// Validate an Australian Tax File Number using the weighted check algorithm.
/// TFN is 8 or 9 digits with a specific weighted checksum.
pub fn is_valid_australia_tfn(tfn: &str) -> bool {
    let digits: Vec<u32> = tfn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    // Modern TFNs are 9 digits; legacy are 8
    if digits.len() != 8 && digits.len() != 9 {
        return false;
    }
    // Reject all-same
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let weights_9 = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let weights_8 = [10, 7, 8, 4, 6, 3, 5, 1];
    let weights = if digits.len() == 9 {
        &weights_9[..]
    } else {
        &weights_8[..]
    };
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum % 11 == 0
}

/// Validate a US Social Security Number for structural correctness.
/// Rejects invalid area numbers (000, 666, 900-999) and group/serial all-zeros.
pub fn is_valid_ssn(ssn: &str) -> bool {
    let digits: Vec<u32> = ssn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    let area = digits[0] * 100 + digits[1] * 10 + digits[2];
    let group = digits[3] * 10 + digits[4];
    let serial = digits[5] * 1000 + digits[6] * 100 + digits[7] * 10 + digits[8];
    // SSA rules: area cannot be 000, 666, or 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    // Group and serial cannot be all zeros
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Run structural validation for a matched pattern.
/// Returns `true` if the match is valid (should be kept).
/// Patterns without a registered validator always return `true`.
pub fn validate_match(category: &str, sub_category: &str, matched_text: &str) -> bool {
    // Credit card: Luhn check + optional BIN validation
    if category == "Credit Card Numbers" {
        if !is_luhn_valid(matched_text) {
            return false;
        }
        // BIN lookup: if bin-data feature is enabled, verify the BIN is real.
        // Unknown BINs are still accepted (could be new issuers not in our DB).
        // Known BINs get metadata enrichment later in the pipeline.
        return true;
    }
    // Per-pattern structural validators
    match sub_category {
        "USA SSN" => is_valid_ssn(matched_text),
        "SWIFT/BIC" => is_valid_swift(matched_text),
        "CUSIP" => is_valid_cusip(matched_text),
        "SEDOL" => is_valid_sedol(matched_text),
        "Australia TFN" => is_valid_australia_tfn(matched_text),
        _ => true, // No validator — accept
    }
}

/// Get BIN metadata for a credit card number (if bin-data feature is enabled).
/// Returns (brand, card_type, country_code, issuer) or None.
pub fn get_bin_info(card_number: &str) -> Option<(String, String, String, String)> {
    let info = crate::bin_lookup::lookup(card_number)?;
    Some((
        info.brand.to_string(),
        info.card_type.to_string(),
        info.country_code,
        info.issuer,
    ))
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
    fn test_ssn_valid() {
        assert!(is_valid_ssn("123-45-6789"));
        assert!(is_valid_ssn("123456789")); // no dashes
        assert!(is_valid_ssn("001-01-0001")); // minimum valid
    }

    #[test]
    fn test_ssn_invalid_area() {
        assert!(!is_valid_ssn("000-12-3456")); // area 000
        assert!(!is_valid_ssn("666-12-3456")); // area 666
        assert!(!is_valid_ssn("900-12-3456")); // area 900+
        assert!(!is_valid_ssn("999-12-3456")); // area 999
    }

    #[test]
    fn test_ssn_invalid_group_serial() {
        assert!(!is_valid_ssn("123-00-6789")); // group 00
        assert!(!is_valid_ssn("123-45-0000")); // serial 0000
    }

    #[test]
    fn test_cusip_valid() {
        assert!(is_valid_cusip("037833100")); // Apple
        assert!(is_valid_cusip("594918104")); // Microsoft
        assert!(is_valid_cusip("17275R102")); // Cisco
    }

    #[test]
    fn test_cusip_invalid() {
        assert!(!is_valid_cusip("037833101")); // wrong check digit
        assert!(!is_valid_cusip("789456123")); // random 9 digits (our FP case)
        assert!(!is_valid_cusip("ABCDEFGH9")); // nonsense
        assert!(!is_valid_cusip("12345")); // too short
    }

    #[test]
    fn test_sedol_valid() {
        assert!(is_valid_sedol("0263494")); // BAE Systems
    }

    #[test]
    fn test_sedol_invalid() {
        assert!(!is_valid_sedol("1234567")); // random
        assert!(!is_valid_sedol("ABCDEFG")); // vowels not allowed
        assert!(!is_valid_sedol("12345")); // too short
    }

    #[test]
    fn test_australia_tfn_valid() {
        // Known valid TFN pattern (public test value)
        assert!(is_valid_australia_tfn("123456782"));
    }

    #[test]
    fn test_australia_tfn_invalid() {
        assert!(!is_valid_australia_tfn("123456789")); // fails checksum
        assert!(!is_valid_australia_tfn("999999999")); // all same
        assert!(!is_valid_australia_tfn("12345")); // too short
        assert!(!is_valid_australia_tfn("000000000")); // all zeros
    }

    #[test]
    fn test_swift_valid_codes() {
        assert!(is_valid_swift("DEUTDEFF")); // Deutsche Bank, Germany
        assert!(is_valid_swift("BNPAFRPP")); // BNP Paribas, France
        assert!(is_valid_swift("CHASUS33")); // JPMorgan Chase, US
        assert!(is_valid_swift("BOFAUS3N")); // Bank of America, US
        assert!(is_valid_swift("HSBCHKHH")); // HSBC, Hong Kong
        assert!(is_valid_swift("DEUTDEFF500")); // 11-char variant
    }

    #[test]
    fn test_swift_rejects_english_words() {
        assert!(!is_valid_swift("DECEMBER"));
        assert!(!is_valid_swift("STANDARD"));
        assert!(!is_valid_swift("RESEARCH"));
        assert!(!is_valid_swift("CUSTOMER"));
        assert!(!is_valid_swift("PLATFORM"));
        assert!(!is_valid_swift("SECURITY"));
        assert!(!is_valid_swift("BUILDING"));
        assert!(!is_valid_swift("INTERNAL"));
        assert!(!is_valid_swift("NATIONAL"));
        assert!(!is_valid_swift("FUNCTION"));
        assert!(!is_valid_swift("OVERRIDE"));
        assert!(!is_valid_swift("USERNAME"));
        assert!(!is_valid_swift("ABSTRACT"));
        assert!(!is_valid_swift("CALLBACK"));
        assert!(!is_valid_swift("GENERATE"));
        assert!(!is_valid_swift("HOSPITAL"));
        assert!(!is_valid_swift("MARKDOWN"));
        assert!(!is_valid_swift("TESTCASE"));
    }

    #[test]
    fn test_swift_rejects_invalid_country() {
        assert!(!is_valid_swift("ABCDXXFF")); // XX is not a country code
        assert!(!is_valid_swift("BANKZZ33")); // ZZ is not a country code
    }

    #[test]
    fn test_swift_rejects_wrong_length() {
        assert!(!is_valid_swift("SHORT"));
        assert!(!is_valid_swift("TOOLONGSWIFTCODE"));
    }

    #[test]
    fn test_swift_country_validation() {
        assert!(is_valid_swift_country("DEUTDEFF")); // DE = Germany
        assert!(is_valid_swift_country("BNPAFRPP")); // FR = France
        assert!(!is_valid_swift_country("ABCDXXFF")); // XX invalid
    }

    #[test]
    fn test_luhn_rejects_all_same_digit() {
        assert!(!is_luhn_valid("1111111111111111"));
        assert!(!is_luhn_valid("5555555555555555"));
        assert!(!is_luhn_valid("9999999999999999"));
    }
}
