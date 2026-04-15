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

/// Valid IBAN lengths by ISO 13616 country code. Rejects anything
/// outside this table so `XX99...` with a fake country code can't
/// pass validation even when the mod-97 check happens to equal 1.
static IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24), ("AE", 23), ("AL", 28), ("AT", 20), ("AZ", 28),
    ("BA", 20), ("BE", 16), ("BG", 22), ("BH", 22), ("BR", 29),
    ("BY", 28), ("CH", 21), ("CR", 22), ("CY", 28), ("CZ", 24),
    ("DE", 22), ("DK", 18), ("DO", 28), ("EE", 20), ("EG", 29),
    ("ES", 24), ("FI", 18), ("FO", 18), ("FR", 27), ("GB", 22),
    ("GE", 22), ("GI", 23), ("GL", 18), ("GR", 27), ("GT", 28),
    ("HR", 21), ("HU", 28), ("IE", 22), ("IL", 23), ("IQ", 23),
    ("IS", 26), ("IT", 27), ("JO", 30), ("KW", 30), ("KZ", 20),
    ("LB", 28), ("LC", 32), ("LI", 21), ("LT", 20), ("LU", 20),
    ("LV", 21), ("LY", 25), ("MC", 27), ("MD", 24), ("ME", 22),
    ("MK", 19), ("MR", 27), ("MT", 31), ("MU", 30), ("NL", 18),
    ("NO", 15), ("PK", 24), ("PL", 28), ("PS", 29), ("PT", 25),
    ("QA", 29), ("RO", 24), ("RS", 22), ("SA", 24), ("SC", 31),
    ("SD", 18), ("SE", 24), ("SI", 19), ("SK", 24), ("SM", 27),
    ("ST", 25), ("SV", 28), ("TL", 23), ("TN", 24), ("TR", 26),
    ("UA", 29), ("VA", 22), ("VG", 24), ("XK", 20),
];

/// Validate an IBAN (International Bank Account Number) using the
/// ISO 13616 mod-97 check. IBANs are written as
/// `CC KK BBAN` where CC is the country code, KK is the 2-digit
/// check, and BBAN is the country-specific basic account number.
///
/// Algorithm:
///   1. Strip spaces.
///   2. Reject lengths that don't match the per-country ISO table.
///   3. Move the first 4 characters to the end.
///   4. Replace each letter with a 2-digit number (A=10, B=11, ..., Z=35).
///   5. Compute the resulting big integer mod 97; valid iff result == 1.
///
/// Returns `true` if the IBAN is structurally valid.
pub fn is_valid_iban(iban: &str) -> bool {
    // Strip spaces and non-ASCII. IBANs are uppercase ASCII only.
    let compact: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = compact.as_bytes();
    if bytes.len() < 15 || bytes.len() > 34 {
        return false;
    }
    // First two chars must be ASCII letters; next two must be digits.
    if !bytes[0].is_ascii_alphabetic()
        || !bytes[1].is_ascii_alphabetic()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
    {
        return false;
    }
    // Country-specific length gate. Reject unknown country codes
    // outright — "XX99..." is not a real IBAN no matter what the
    // check digit computes to.
    let country = &compact[..2];
    let expected_len = match IBAN_LENGTHS.iter().find(|(cc, _)| *cc == country) {
        Some((_, len)) => *len,
        None => return false,
    };
    if compact.len() != expected_len {
        return false;
    }
    // The remaining characters must be ASCII alphanumeric.
    for &b in &bytes[4..] {
        if !b.is_ascii_alphanumeric() {
            return false;
        }
    }
    // Rearrange: move first 4 chars to the end, then convert letters
    // to digits (A=10..Z=35).
    let rearranged: String = compact[4..]
        .chars()
        .chain(compact[..4].chars())
        .collect();
    let mut numeric = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if let Some(d) = c.to_digit(10) {
            numeric.push_str(&d.to_string());
        } else if c.is_ascii_uppercase() {
            numeric.push_str(&(c as u32 - 'A' as u32 + 10).to_string());
        } else {
            return false;
        }
    }
    // Mod 97 via running remainder — avoids big-integer math.
    // We process digits left-to-right; at each step,
    //   remainder = (remainder * 10 + next_digit) mod 97
    let mut remainder: u32 = 0;
    for c in numeric.chars() {
        let d = c.to_digit(10).unwrap_or(0);
        remainder = (remainder * 10 + d) % 97;
    }
    remainder == 1
}

/// Validate a Canadian Social Insurance Number using the Luhn check.
/// SINs are 9 digits (often formatted `123-456-789`) and use the
/// standard Luhn algorithm. Also rejects the all-zeros sentinel
/// which Luhn accepts but which is never a real SIN.
pub fn is_valid_canada_sin(sin: &str) -> bool {
    let digits: Vec<u32> = sin
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    if digits.iter().all(|&d| d == 0) {
        return false;
    }
    // Standard Luhn on 9 digits.
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Validate an ISIN (International Securities Identification Number)
/// check digit. ISINs are 12 characters: 2 letters (country code) +
/// 9 alphanumeric + 1 digit. The check digit is computed by the
/// Luhn algorithm applied to the numeric expansion of the first 11
/// characters (letters A=10..Z=35 expand to 2 digits each).
pub fn is_valid_isin(isin: &str) -> bool {
    let chars: Vec<char> = isin.chars().collect();
    if chars.len() != 12 {
        return false;
    }
    // First two must be letters; last must be a digit.
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return false;
    }
    if !chars[11].is_ascii_digit() {
        return false;
    }
    // Expand first 11 chars to their numeric representation.
    let mut digits = Vec::with_capacity(22);
    for &c in &chars[..11] {
        if let Some(d) = c.to_digit(10) {
            digits.push(d);
        } else if c.is_ascii_uppercase() {
            let v = c as u32 - 'A' as u32 + 10;
            digits.push(v / 10);
            digits.push(v % 10);
        } else {
            return false;
        }
    }
    // Luhn on the expanded digits, with the check digit at chars[11].
    // Standard Luhn processes from right to left doubling every
    // other digit starting with the rightmost (the check digit).
    // We append the check digit and compute a 0 remainder.
    digits.push(chars[11].to_digit(10).unwrap());
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Structural sanity check for a phone number. Extracts the digits
/// from a matched phone string and rejects implausible variants:
///
///   * Fewer than 8 or more than 15 digits total.
///   * All digits the same (e.g. `+10000000000`, `+19999999999`) —
///     test-data noise, never a real phone.
///
/// This is intentionally conservative: it's a "reject garbage that
/// the regex let through" gate, not a "this is a valid number in
/// country X" gate. Real numbering-plan validation would need a
/// country-by-country table that we don't ship.
pub fn is_plausible_phone(phone: &str) -> bool {
    let digits: Vec<u32> = phone
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    // E.164 is technically 7-15 digits, but 7-digit international
    // numbers are an edge case that doesn't justify the FP volume
    // that the loose minimum lets through. 8 is a safer floor.
    if digits.len() < 8 || digits.len() > 15 {
        return false;
    }
    // All-same-digit sentinels: 000..., 111..., ..., 999...
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Reject runs of the same digit long enough to dominate the
    // number — e.g. +10000000000 has a leading 1 plus ten zeros,
    // which the all-same check misses but is still obvious noise.
    // Count the longest same-digit run; if it's >= digits.len() - 1,
    // treat the number as non-plausible.
    let mut longest_run = 1usize;
    let mut current_run = 1usize;
    for pair in digits.windows(2) {
        if pair[0] == pair[1] {
            current_run += 1;
            if current_run > longest_run {
                longest_run = current_run;
            }
        } else {
            current_run = 1;
        }
    }
    if longest_run >= digits.len().saturating_sub(1) {
        return false;
    }
    true
}

/// ITU-T E.164 country calling codes with per-country national-
/// significant-number length bounds.
///
/// Each entry is `(country_code, min_nsn, max_nsn)`. The country
/// code is a 1-, 2-, or 3-digit prefix. `min_nsn` and `max_nsn`
/// are the inclusive bounds on the number of digits AFTER the
/// country code. Bounds are taken from the ITU-T E.164 national
/// numbering plans reference and are deliberately conservative:
/// when a country allows a wide range of NSN lengths we store the
/// full range (e.g. Australia 5..=15, which is technically loose
/// but prevents false negatives on every Australian dial form).
/// For countries with strict fixed lengths (NANP exactly 10,
/// France exactly 9) we store tight bounds.
///
/// Note on NANP (country code "1"): this single entry covers the
/// US, Canada, and the Caribbean territories that share the code.
/// Per-NPA validation (reject service codes, N11, etc.) is handled
/// separately by `is_valid_nanp_npa` so that a `+1...` number
/// passes only if BOTH the length check and the NPA check succeed.
///
/// Refresh: the ITU publishes updates to this table through
/// E.164 Annex A/B. New country codes appear every few years; the
/// most recent additions (2023-2024 timeframe) are included
/// below. A yearly review against the current E.164 annexes is a
/// reasonable maintenance cadence.
static E164_COUNTRY_CODES: &[(&str, u8, u8)] = &[
    // 1-digit
    ("1", 10, 10),    // NANP (US/CA/Caribbean) — exactly 10
    ("7", 10, 10),    // Russia, Kazakhstan
    // 2-digit
    ("20", 9, 10),    ("27", 9, 9),     ("30", 10, 10),   ("31", 9, 9),
    ("32", 8, 9),     ("33", 9, 9),     ("34", 9, 9),     ("36", 8, 9),
    ("39", 9, 11),    ("40", 9, 9),     ("41", 9, 9),     ("43", 10, 13),
    ("44", 9, 10),    ("45", 8, 8),     ("46", 7, 13),    ("47", 8, 8),
    ("48", 9, 9),     ("49", 7, 13),    ("51", 9, 11),    ("52", 10, 11),
    ("53", 6, 8),     ("54", 10, 11),   ("55", 10, 11),   ("56", 9, 9),
    ("57", 10, 10),   ("58", 10, 10),   ("60", 7, 10),    ("61", 5, 15),
    ("62", 7, 12),    ("63", 8, 10),    ("64", 3, 10),    ("65", 8, 8),
    ("66", 8, 9),     ("81", 9, 10),    ("82", 9, 11),    ("84", 9, 10),
    ("86", 5, 13),    ("90", 10, 10),   ("91", 10, 10),   ("92", 9, 10),
    ("93", 9, 9),     ("94", 9, 9),     ("95", 8, 10),    ("98", 10, 10),
    // 3-digit: Africa
    ("211", 9, 9),    ("212", 9, 9),    ("213", 9, 9),    ("216", 8, 8),
    ("218", 9, 10),   ("220", 7, 7),    ("221", 9, 9),    ("222", 8, 8),
    ("223", 8, 8),    ("224", 9, 9),    ("225", 10, 10),  ("226", 8, 8),
    ("227", 8, 8),    ("228", 8, 8),    ("229", 8, 8),    ("230", 7, 8),
    ("231", 7, 8),    ("232", 8, 8),    ("233", 9, 9),    ("234", 8, 10),
    ("235", 8, 8),    ("236", 8, 8),    ("237", 9, 9),    ("238", 7, 7),
    ("239", 7, 7),    ("240", 9, 9),    ("241", 7, 8),    ("242", 9, 9),
    ("243", 9, 9),    ("244", 9, 9),    ("245", 7, 7),    ("246", 7, 7),
    ("247", 4, 4),    ("248", 7, 7),    ("249", 9, 9),    ("250", 9, 9),
    ("251", 9, 9),    ("252", 7, 9),    ("253", 8, 8),    ("254", 9, 10),
    ("255", 9, 9),    ("256", 9, 9),    ("257", 8, 8),    ("258", 9, 9),
    ("260", 9, 9),    ("261", 9, 10),   ("262", 9, 9),    ("263", 9, 10),
    ("264", 8, 9),    ("265", 9, 9),    ("266", 8, 8),    ("267", 7, 8),
    ("268", 8, 8),    ("269", 7, 7),    ("290", 4, 4),    ("291", 7, 7),
    ("297", 7, 7),    ("298", 6, 6),    ("299", 6, 6),
    // 3-digit: Europe
    ("350", 8, 8),    ("351", 9, 11),   ("352", 8, 11),   ("353", 7, 11),
    ("354", 7, 9),    ("355", 8, 9),    ("356", 8, 8),    ("357", 8, 11),
    ("358", 5, 12),   ("359", 8, 9),    ("370", 8, 8),    ("371", 8, 8),
    ("372", 7, 10),   ("373", 8, 8),    ("374", 8, 8),    ("375", 9, 10),
    ("376", 6, 9),    ("377", 8, 9),    ("378", 6, 10),   ("379", 6, 10),
    ("380", 9, 9),    ("381", 8, 10),   ("382", 8, 8),    ("383", 8, 9),
    ("385", 8, 12),   ("386", 8, 8),    ("387", 8, 8),    ("389", 8, 8),
    ("420", 9, 9),    ("421", 9, 9),    ("423", 7, 13),
    // 3-digit: Latin America + Caribbean non-NANP
    ("500", 5, 5),    ("501", 7, 7),    ("502", 8, 8),    ("503", 8, 11),
    ("504", 8, 8),    ("505", 8, 8),    ("506", 8, 8),    ("507", 7, 8),
    ("508", 6, 6),    ("509", 8, 9),    ("590", 9, 9),    ("591", 8, 9),
    ("592", 7, 7),    ("593", 8, 9),    ("594", 9, 9),    ("595", 9, 9),
    ("596", 9, 9),    ("597", 6, 7),    ("598", 7, 8),    ("599", 7, 8),
    // 3-digit: Oceania + Asia (670-692)
    ("670", 7, 8),    ("672", 5, 6),    ("673", 7, 7),    ("674", 7, 7),
    ("675", 7, 8),    ("676", 5, 7),    ("677", 5, 7),    ("678", 5, 7),
    ("679", 7, 7),    ("680", 7, 7),    ("681", 6, 6),    ("682", 5, 5),
    ("683", 4, 4),    ("685", 5, 7),    ("686", 5, 8),    ("687", 6, 6),
    ("688", 5, 6),    ("689", 6, 6),    ("690", 4, 4),    ("691", 7, 7),
    ("692", 7, 7),
    // 3-digit: East Asia + South Asia
    ("850", 8, 13),   ("852", 4, 9),    ("853", 7, 8),    ("855", 8, 9),
    ("856", 8, 10),   ("880", 6, 10),   ("886", 8, 9),
    // 3-digit: Middle East + Central Asia
    ("960", 7, 7),    ("961", 7, 8),    ("962", 8, 9),    ("963", 8, 9),
    ("964", 9, 10),   ("965", 7, 8),    ("966", 8, 9),    ("967", 6, 9),
    ("968", 7, 8),    ("970", 8, 9),    ("971", 8, 9),    ("972", 8, 9),
    ("973", 8, 8),    ("974", 7, 8),    ("975", 7, 8),    ("976", 7, 8),
    ("977", 9, 10),   ("992", 9, 9),    ("993", 8, 8),    ("994", 8, 9),
    ("995", 9, 9),    ("996", 9, 9),    ("998", 9, 9),
    // Special services (non-geographic)
    ("800", 8, 8),    // Universal International Freephone
    ("808", 8, 8),    // Shared-cost
    ("870", 9, 9),    // Inmarsat
    ("878", 12, 12),  // UPT
    ("881", 8, 12),   // GMSS (satellite)
    ("882", 5, 13),   // International networks
    ("883", 9, 15),   // International networks
    ("888", 11, 11),  // ITU-T reserved
];

/// Validate that a 3-digit NANP area code (NPA) is a structurally
/// plausible subscriber prefix. Rules:
///
///   * First digit MUST be 2-9 (0 and 1 are trunk prefixes and
///     can never appear as the first digit of an NPA).
///   * Second and third digits must be ASCII digits.
///   * Must not be an N11 service code (211, 311, 411, 511, 611,
///     711, 811, 911) — those are reserved for dial-able services
///     and never appear as subscriber area codes.
///
/// This is a structural check rather than a lookup against the
/// complete NANPA assignment table. The structural rule catches
/// `000`, `1XX`, and `X11` reliably (which covers the blind-test
/// cases like `+10000000000` and `+1911...`) and has zero refresh
/// burden. A hardcoded 370-entry set would need yearly updates
/// and would produce false NEGATIVES for any newly-assigned NPA
/// until the data was refreshed, which is a worse failure mode
/// for a DLP scanner than "accepts some plausible-looking
/// unassigned NPAs". Note that all-three-same NPAs like `888`
/// (toll-free), `777`, `222`, and `333` are deliberately NOT
/// rejected here — `888` is a real toll-free assignment and some
/// of the others are used for non-geographic services. The
/// obvious-bogus `+19999999999` pattern gets caught by the
/// `is_plausible_phone` all-same-digit sentinel, not by the NPA.
pub fn is_valid_nanp_npa(npa: &str) -> bool {
    let bytes = npa.as_bytes();
    if bytes.len() != 3 {
        return false;
    }
    if !(b'2'..=b'9').contains(&bytes[0]) {
        return false;
    }
    if !bytes[1].is_ascii_digit() || !bytes[2].is_ascii_digit() {
        return false;
    }
    // N11 service codes.
    if bytes[1] == b'1' && bytes[2] == b'1' {
        return false;
    }
    true
}

/// Validate an E.164 phone number: must start with `+`, must have
/// a recognised country code, and the national-significant-number
/// length must fall within the country-specific bounds published
/// in E.164 Annex A/B. For NANP (`+1...`), additionally validates
/// the 3-digit NPA (area code) via `is_valid_nanp_npa`.
///
/// Accepts formatted input — spaces, dashes, dots, parentheses —
/// because the regex captures may include them.
///
/// Rejects:
///   * Missing `+` prefix.
///   * Unrecognised country codes.
///   * NSN length outside the country's published range.
///   * `+1` numbers with obviously-bogus NPAs (000-class, N11,
///     all-same-digit).
///   * Inputs that also fail `is_plausible_phone` (all-same-
///     digit / near-all-same-digit sentinels).
pub fn is_valid_e164_phone(phone: &str) -> bool {
    // E.164 literally requires the `+` prefix.
    if !phone.contains('+') {
        return false;
    }
    // Still apply the plausibility gate — catches all-same-digit
    // and near-all-same sentinels that the country-code check
    // would otherwise let through (`+15555555555` has a valid
    // length but is noise).
    if !is_plausible_phone(phone) {
        return false;
    }
    // Extract the ASCII digits.
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 7 || digits.len() > 15 {
        return false;
    }
    // Country code may be 1, 2, or 3 digits — try longest first so
    // `"1441..."` (Bermuda via NANP) matches `"1"` not `"144"` if
    // `"144"` is in the table by coincidence.
    for cc_len in [3usize, 2, 1] {
        if digits.len() < cc_len {
            continue;
        }
        let cc = &digits[..cc_len];
        let nsn = &digits[cc_len..];
        if let Some(&(_, min, max)) = E164_COUNTRY_CODES.iter().find(|(c, _, _)| *c == cc) {
            if nsn.len() < min as usize || nsn.len() > max as usize {
                // Length doesn't fit this CC's bounds. Try a
                // longer CC (on the first iteration there isn't
                // one, but in general this handles overlapping
                // prefixes by falling through to the shorter
                // alternative — e.g. a hypothetical 3-digit CC
                // that also starts with a valid 2-digit CC.)
                continue;
            }
            // NANP: delegate to is_valid_us_phone so the
            // exchange-code check (digits 4-6 of NSN must start
            // 2-9, and cannot be N11) also runs. That's the gate
            // that catches `+19990000000` — NPA 999 passes the
            // structural NPA check, but exchange 000 has first
            // digit 0 and fails.
            if cc == "1" {
                return is_valid_us_phone(nsn);
            }
            return true;
        }
    }
    false
}

/// Validate a US Phone Number (NANP format without requiring an
/// explicit `+1` prefix). Accepts:
///
///   * 10 raw digits → validated as a NANP NPA + exchange + subscriber.
///   * 11 digits starting with `1` → strip the leading `1` and
///     validate the remaining 10 as NANP.
///   * Any formatting (dashes, dots, spaces, parentheses).
///
/// Rejects anything else, including:
///   * Numbers where the NPA fails `is_valid_nanp_npa`.
///   * Numbers where the exchange code (digits 4-6, "NXX") has an
///     invalid first digit — NANP exchange codes also require the
///     first digit to be 2-9.
///   * All-same / near-all-same digit sentinels
///     (via `is_plausible_phone`).
pub fn is_valid_us_phone(phone: &str) -> bool {
    if !is_plausible_phone(phone) {
        return false;
    }
    let mut digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 11 && digits.starts_with('1') {
        digits.remove(0);
    }
    if digits.len() != 10 {
        return false;
    }
    // NPA: positions 0-2.
    if !is_valid_nanp_npa(&digits[..3]) {
        return false;
    }
    // Exchange code (NXX): positions 3-5. First digit must be 2-9.
    let exchange = digits.as_bytes();
    if !(b'2'..=b'9').contains(&exchange[3]) {
        return false;
    }
    // Exchange cannot be N11 either.
    if exchange[4] == b'1' && exchange[5] == b'1' {
        return false;
    }
    true
}

/// Validate a German Tax ID (Steuer-Identifikationsnummer) using
/// the ISO 7064 MOD 11,10 check digit. The Steuer-ID is an 11-digit
/// number assigned by the Bundeszentralamt für Steuern; positions
/// 1-10 carry the identifying payload and position 11 is the check
/// digit. Without this validator, the pattern `\b\d{11}\b` matches
/// every 11-digit invoice number, account reference, timestamp, or
/// phone-number-adjacent sequence in a document.
///
/// ISO 7064 MOD 11,10 algorithm:
///   product = 10
///   for d in digits[0..10]:
///       sum = (d + product) % 10
///       if sum == 0 { sum = 10 }
///       product = (sum * 2) % 11
///   check = (11 - product) % 10
///   valid iff digits[10] == check
pub fn is_valid_germany_tax_id(tax_id: &str) -> bool {
    let digits: Vec<u32> = tax_id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    // Reject all-same-digit sentinels — Luhn-style garbage gate.
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut product: u32 = 10;
    for &d in &digits[..10] {
        let mut sum = (d + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    digits[10] == check
}

/// Validate a Chilean RUT/RUN (Rol Único Tributario / Rol Único
/// Nacional) check digit. The RUT is 7-8 digits of payload + 1
/// check character (0-9 or K). The check is a weighted sum mod 11
/// using weights [2, 3, 4, 5, 6, 7] cycling from the rightmost
/// payload digit.
///
/// Algorithm:
///   sum = Σ (digits[i] × weight[i % 6])
///   remainder = 11 - (sum % 11)
///   check = "0" if remainder == 11 else "K" if remainder == 10 else digit(remainder)
pub fn is_valid_chile_rut(rut: &str) -> bool {
    // Strip separators and find the check character.
    let compact: String = rut
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if compact.len() < 8 || compact.len() > 9 {
        return false;
    }
    let bytes = compact.as_bytes();
    let check_char = bytes[bytes.len() - 1].to_ascii_uppercase();
    if !check_char.is_ascii_digit() && check_char != b'K' {
        return false;
    }
    // Payload digits are the first n-1 chars — must all be digits.
    let payload: &[u8] = &bytes[..bytes.len() - 1];
    if !payload.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Reject trivial sequences.
    if payload.iter().all(|&b| b == payload[0]) {
        return false;
    }
    // Weighted sum, weights cycle 2..=7 from the rightmost digit.
    let mut sum: u32 = 0;
    for (i, &b) in payload.iter().rev().enumerate() {
        let d = (b - b'0') as u32;
        let weight = 2 + (i % 6) as u32;
        sum += d * weight;
    }
    let remainder = 11 - (sum % 11);
    let expected: u8 = match remainder {
        11 => b'0',
        10 => b'K',
        n => b'0' + n as u8,
    };
    check_char == expected
}

/// Validate a MICR (Magnetic Ink Character Recognition) line. Real
/// MICR lines — the machine-readable strip at the bottom of a check
/// — are delimited by MICR symbols that don't exist in ordinary
/// text: `⑈` (U+2448 = on-us), `⑇` (U+2447 = dash), `⑆` (U+2446 =
/// transit / routing), `⑉` (U+2449 = amount). The regex already
/// matches the character pattern, but the control characters are
/// optional in the regex — which means any 19-to-32-digit sequence
/// with internal whitespace passes the shape check. IBANs, invoice
/// ledgers, and log lines repeatedly false-positive on this.
///
/// Require at least one MICR control character to be present in
/// the matched substring. That's the cheapest correct-by-spec gate:
/// a real check MICR line has at least three delimiters (transit,
/// account, amount); accepting one is still conservative but
/// decisively rules out "long digit run" false positives.
pub fn is_valid_micr_line(micr: &str) -> bool {
    micr.chars()
        .any(|c| matches!(c, '\u{2446}' | '\u{2447}' | '\u{2448}' | '\u{2449}'))
}

/// Validate a Quebec RAMQ health card number (a.k.a. "Quebec HC")
/// using its embedded date-of-birth + gender encoding. RAMQ format
/// is 4 letters (name initials) followed by 8 digits split as
/// `YY MM DD NN`: 2-digit year, 2-digit month (gender-encoded),
/// 2-digit day, and a 2-digit sequence number.
///
/// The MM field encodes gender by offsetting the month for female
/// cardholders:
///   * male:   01 .. 12
///   * female: 51 .. 62
///
/// DD is the day of birth (01..31). YY is the 2-digit year, which
/// we don't constrain beyond "must be numeric."
///
/// This is not a true mod-N checksum — RAMQ doesn't publish one —
/// but it's a strong structural gate: the odds of a random
/// 4-letter-+-8-digit string having a valid month-encoded gender
/// AND a valid day of month are under 5%, which is enough to
/// eliminate the bulk of FPs on this pattern.
pub fn is_valid_quebec_hc(hc: &str) -> bool {
    let compact: String = hc.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let bytes = compact.as_bytes();
    if bytes.len() != 12 {
        return false;
    }
    // First 4 must be uppercase letters.
    if !bytes[..4].iter().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    // Last 8 must be digits.
    if !bytes[4..].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let digits: Vec<u32> = bytes[4..]
        .iter()
        .map(|&b| (b - b'0') as u32)
        .collect();
    let month = digits[2] * 10 + digits[3];
    let day = digits[4] * 10 + digits[5];
    // Month: 01..12 male, 51..62 female.
    let month_ok = (1..=12).contains(&month) || (51..=62).contains(&month);
    if !month_ok {
        return false;
    }
    // Day: 01..31.
    if !(1..=31).contains(&day) {
        return false;
    }
    true
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
        // IBAN — ISO 13616 mod-97 check. Before wiring this, every
        // structurally IBAN-shaped string (country code + 2 digits +
        // 11-30 alphanumeric) was accepted regardless of whether the
        // check digits were consistent. Real IBANs now pass, forged
        // check digits no longer fire.
        "IBAN Generic" => is_valid_iban(matched_text),
        // Canadian SIN — 9 digits, standard Luhn. Without this, every
        // 9-digit sequence near a SIN keyword was flagged as a SIN,
        // including obvious sentinels like 000-000-000.
        "Canada SIN" => is_valid_canada_sin(matched_text),
        // ISIN — modified Luhn on the alphanumeric expansion of
        // positions 1-11 against the digit check at position 12.
        // This closes a nasty category of RAMQ / random-alphanum
        // FPs where a 2-letter-then-10-alphanum string was being
        // labeled as a security identifier with no structural check.
        "ISIN" => is_valid_isin(matched_text),
        // Phone validation is country-code-aware:
        //
        //   * E.164 Phone Number → full ITU country-code table +
        //     per-country NSN length bounds + (for +1) NANP area
        //     code validation.
        //   * US Phone Number → NANP NPA + exchange-code check,
        //     with an optional `1` country-code prefix.
        //   * UK Phone Number → structural sanity gate (the regex
        //     itself encodes most of the UK numbering plan;
        //     is_plausible_phone rules out the obvious-garbage
        //     cases that slip through).
        //
        // Each branch also applies is_plausible_phone internally
        // as a first-line garbage filter.
        "E.164 Phone Number" => is_valid_e164_phone(matched_text),
        "US Phone Number" => is_valid_us_phone(matched_text),
        "UK Phone Number" => is_plausible_phone(matched_text),
        // Germany Steuer-ID — 11 digits with an ISO 7064 MOD 11,10
        // check. Without this, `\b\d{11}\b` fires on every 11-digit
        // invoice number, timestamp, or phone sequence in a
        // document and Germany Tax ID is in CRITICAL_ALWAYS_RUN so
        // the AC prefilter can't save us.
        "Germany Tax ID" => is_valid_germany_tax_id(matched_text),
        // Chilean RUT/RUN — 8-9 chars with a mod-11 check digit
        // (can be 0-9 or K). Similar story: always-run, no context
        // gate, bare digit regex — the checksum is the only real
        // discipline the pattern has.
        "Chile RUN/RUT" => is_valid_chile_rut(matched_text),
        // MICR check line — require at least one MICR control char
        // (U+2446..U+2449) to be present. Without that, the regex
        // happily matches any 19-to-32-digit sequence with internal
        // whitespace, which IBANs and long digit runs trip on
        // constantly.
        "MICR Line" => is_valid_micr_line(matched_text),
        // Quebec RAMQ health card — structural month + day gate.
        // Checks the embedded birth month (01..12 male, 51..62
        // female) and day (01..31) encoding. Not a full checksum
        // but enough to eliminate random 4-letter-8-digit strings.
        "Quebec HC" => is_valid_quebec_hc(matched_text),
        // PAN lives under the "Primary Account Numbers" category, NOT
        // "Credit Card Numbers", so the early-return above doesn't catch
        // it. The PAN regex is `\b\d{4}[sep?]\d{4}[sep?]\d{4}[sep?]\d{1,7}\b`
        // which fires on any 16-19 digit sequence (with or without
        // common group separators) — including invoice numbers,
        // sequential test data, and SKU runs. Without a Luhn check
        // the sub_category produces a false positive on every such
        // sequence, and PAN is in CRITICAL_ALWAYS_RUN so it executes
        // on every scan regardless of context. Apply Luhn here so
        // PAN matches the precision floor of the brand-specific
        // sub_categories above.
        //
        // `Masked PAN` is deliberately not Luhn-checked: only 8 of
        // its 16 characters are digits (the middle 8 are X/x/*),
        // which is below the Luhn function's 12-digit minimum, so
        // adding it here would silently drop every legitimate
        // masked-PAN match.
        "PAN" => is_luhn_valid(matched_text),
        // IMEI is a 15-digit device identifier with a Luhn check digit.
        // Without this validator the pattern happily matches any 15-digit
        // sequence, including Luhn-failing 15-digit credit card numbers
        // (Amex) that were correctly rejected by the brand-specific
        // pre-validator. Those rejections bubble up as IMEI hits because
        // IMEI is next-most-specific at the same digit length, and the
        // blind-test harness surfaced this as "100% credit card FP rate."
        // Luhn-gating IMEI closes that door cleanly — real IMEIs still
        // pass, forged/invoice-shaped 15-digit numbers don't.
        //
        // IMEISV (16 digits) intentionally has NO Luhn validator here.
        // IMEISV replaces the IMEI check digit with a 2-digit Software
        // Version field, so the 16-digit form has no built-in checksum.
        // Instead, IMEISV is switched to context_required = true (see
        // `is_context_required` in src/models.rs) so it only fires when
        // an IMEISV keyword is within 50 characters. That gate is what
        // stops 16-digit invoice numbers and Luhn-failing 16-digit card
        // numbers from being reported as device identifiers.
        "IMEI" => is_luhn_valid(matched_text),
        _ => true, // No validator — accept
    }
}

/// Get BIN metadata for a credit card number (if bin-data feature is enabled).
/// Returns (brand, card_type, country_code) or None.
pub fn get_bin_info(card_number: &str) -> Option<(String, String, String)> {
    let info = crate::bin_lookup::lookup(card_number)?;
    Some((
        info.brand.to_string(),
        info.card_type.to_string(),
        info.country_code,
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
    fn test_validate_match_pan_luhn_gates_invoice_numbers() {
        // Regression: the PAN sub_category lives under the
        // "Primary Account Numbers" category, so the early-return
        // Luhn check at the top of validate_match (which is keyed on
        // the "Credit Card Numbers" category) does not fire for it.
        // Without an explicit case in the per-sub_category match
        // arm, every Luhn-failing 16-digit invoice number was
        // accepted as a PAN. The detection-quality harness surfaced
        // three such false positives on the negatives corpus.
        //
        // After the fix, validate_match must reject Luhn-failing
        // sequences and accept Luhn-valid PANs.
        let cat = "Primary Account Numbers";
        // Three invoice-shaped numbers that fail Luhn — must be rejected.
        // Note: 1111222233334444 is *not* in this set despite looking
        // similar; it happens to be Luhn-valid by coincidence (sum 60).
        // We use 1234567890123456 instead, which is the canonical
        // Luhn-failing 16-digit example used elsewhere in this file.
        assert!(!validate_match(cat, "PAN", "1234567812345678"));
        assert!(!validate_match(cat, "PAN", "1234567890123456"));
        assert!(!validate_match(cat, "PAN", "9999888877776666"));
        // Sanity: 1111222233334444 IS Luhn-valid — the validator
        // must accept it. This pins the gotcha so a future
        // contributor doesn't "fix" the corpus by reverting to it.
        assert!(validate_match(cat, "PAN", "1111222233334444"));
        // Stripe's documented Luhn-valid test PAN — must be accepted.
        assert!(validate_match(cat, "PAN", "4242424242424242"));
        // A real-shape Luhn-valid 16-digit number — must be accepted.
        assert!(validate_match(cat, "PAN", "4532015112830366"));
    }

    #[test]
    fn test_germany_tax_id_valid() {
        // 47036892816 — hand-verified ISO 7064 MOD 11,10 trace,
        // check digit computes to 6 exactly.
        assert!(is_valid_germany_tax_id("47036892816"));
        // 12345678903 — also hand-verified, check digit 3.
        assert!(is_valid_germany_tax_id("12345678903"));
    }

    #[test]
    fn test_germany_tax_id_invalid() {
        // Bumped check digit on a known-valid input.
        assert!(!is_valid_germany_tax_id("47036892817"));
        assert!(!is_valid_germany_tax_id("12345678904"));
        // Sequential shape that isn't a valid check digit.
        assert!(!is_valid_germany_tax_id("12345678901"));
        assert!(!is_valid_germany_tax_id("98765432101"));
        // All-same sentinels.
        assert!(!is_valid_germany_tax_id("11111111111"));
        assert!(!is_valid_germany_tax_id("00000000000"));
        // Wrong length.
        assert!(!is_valid_germany_tax_id("1234567890"));
        assert!(!is_valid_germany_tax_id("123456789012"));
    }

    #[test]
    fn test_chile_rut_valid() {
        // Hand-verified values (weights 2..=7 cycling from rightmost).
        // 12345678-5: sum=138, 138%11=6, 11-6=5 ✓
        assert!(is_valid_chile_rut("12345678-5"));
        // Dotted form should also work.
        assert!(is_valid_chile_rut("12.345.678-5"));
        // 1234567-4: sum=106, 106%11=7, 11-7=4 ✓ (7-digit payload)
        assert!(is_valid_chile_rut("1234567-4"));
        // 1000019-K: sum=23, 23%11=1, 11-1=10 → K ✓ (exercises the
        // K-verifier branch).
        assert!(is_valid_chile_rut("1000019-K"));
        // Mixed case K.
        assert!(is_valid_chile_rut("1000019-k"));
    }

    #[test]
    fn test_chile_rut_invalid() {
        // Bumped verifier digit on a known-valid input.
        assert!(!is_valid_chile_rut("12345678-6"));
        assert!(!is_valid_chile_rut("1234567-5"));
        // Wrong K vs digit mapping.
        assert!(!is_valid_chile_rut("1000019-0"));
        // Sentinel: all-same-digit payload rejected before checksum.
        assert!(!is_valid_chile_rut("11111111-1"));
        assert!(!is_valid_chile_rut("00000000-0"));
        // Too short / too long.
        assert!(!is_valid_chile_rut("1234-5"));
        assert!(!is_valid_chile_rut("1234567890-1"));
        // Non-alphanumeric only separators (should strip) — but if
        // the resulting compact is still the wrong shape, reject.
        assert!(!is_valid_chile_rut("abc"));
    }

    #[test]
    fn test_micr_line_valid() {
        // Real MICR strings include the U+2446..U+2449 control
        // characters. Only one is required for the gate; real
        // check MICR has at least three.
        assert!(is_valid_micr_line("\u{2446}123456789\u{2446}\u{2448}1234567\u{2448}\u{2449}0000001000\u{2449}"));
        // Minimal case: just the transit symbol around a routing
        // number.
        assert!(is_valid_micr_line("\u{2446}021000021\u{2446}"));
    }

    #[test]
    fn test_micr_line_invalid() {
        // Long digit run with no MICR symbols — this is exactly
        // the "IBAN interior" / "invoice ledger" case that was
        // false-positiving before the gate.
        assert!(!is_valid_micr_line("89370400440532013000"));
        assert!(!is_valid_micr_line("021000021 1234567 0000001000"));
        // Empty / whitespace-only.
        assert!(!is_valid_micr_line(""));
    }

    #[test]
    fn test_quebec_hc_valid() {
        // TREM 89 07 15 32 — Tremblay, 1989, July 15, seq 32 (male).
        assert!(is_valid_quebec_hc("TREM89071532"));
        // DUPO 90 55 12 04 — Dupont, 1990, female May (55=05+50),
        // day 12, seq 04.
        assert!(is_valid_quebec_hc("DUPO90551204"));
        // NORD 72 52 31 11 — December 31 female (52=02+50 no wait
        // 52=02+50=Feb-female, day 31 — Feb 31 is technically
        // invalid but our gate doesn't check month-specific days).
        //
        // Actually let's use a truly valid one: NORD 72 12 25 11 —
        // 1972, December 25, male.
        assert!(is_valid_quebec_hc("NORD72122511"));
    }

    #[test]
    fn test_quebec_hc_invalid() {
        // Month 13 → invalid (not male 01-12, not female 51-62).
        assert!(!is_valid_quebec_hc("TREM89131532"));
        // Month 40 → invalid (in the dead zone 13-50).
        assert!(!is_valid_quebec_hc("TREM89401532"));
        // Day 32 → invalid.
        assert!(!is_valid_quebec_hc("TREM89073232"));
        // Day 00 → invalid.
        assert!(!is_valid_quebec_hc("TREM89070032"));
        // Random 4-letter-8-digit — the ISIN-shadow case. The
        // literal "ABCD12345678": month = 34, rejected.
        assert!(!is_valid_quebec_hc("ABCD12345678"));
        // DUPO99123456 — year 99, month 12, day 34: day invalid.
        assert!(!is_valid_quebec_hc("DUPO99123456"));
        // TREF98765432 — year 98, month 76: rejected.
        assert!(!is_valid_quebec_hc("TREF98765432"));
        // Wrong shape: too few chars.
        assert!(!is_valid_quebec_hc("TRE8907153"));
        // Wrong shape: lowercase letters.
        assert!(!is_valid_quebec_hc("trem89071532"));
    }

    #[test]
    fn test_nanp_npa_valid() {
        // Geographic NPAs — first digit 2-9, not N11, not triple.
        assert!(is_valid_nanp_npa("212")); // NYC
        assert!(is_valid_nanp_npa("415")); // SF
        assert!(is_valid_nanp_npa("310")); // LA
        assert!(is_valid_nanp_npa("416")); // Toronto
        assert!(is_valid_nanp_npa("441")); // Bermuda
        // Non-geographic but assigned.
        assert!(is_valid_nanp_npa("800")); // toll-free
        assert!(is_valid_nanp_npa("888")); // toll-free
        assert!(is_valid_nanp_npa("900")); // premium-rate
    }

    #[test]
    fn test_nanp_npa_invalid() {
        // First digit 0 or 1 — never valid.
        assert!(!is_valid_nanp_npa("012"));
        assert!(!is_valid_nanp_npa("100"));
        assert!(!is_valid_nanp_npa("199"));
        // N11 service codes.
        assert!(!is_valid_nanp_npa("211"));
        assert!(!is_valid_nanp_npa("311"));
        assert!(!is_valid_nanp_npa("411"));
        assert!(!is_valid_nanp_npa("511"));
        assert!(!is_valid_nanp_npa("611"));
        assert!(!is_valid_nanp_npa("711"));
        assert!(!is_valid_nanp_npa("811"));
        assert!(!is_valid_nanp_npa("911"));
        // Wrong length.
        assert!(!is_valid_nanp_npa("41"));
        assert!(!is_valid_nanp_npa("4155"));
        // Non-digit.
        assert!(!is_valid_nanp_npa("4A5"));
    }

    #[test]
    fn test_e164_phone_valid() {
        // NANP: +1 + 10 digits, valid NPA.
        assert!(is_valid_e164_phone("+14155552671"));
        assert!(is_valid_e164_phone("+12125551234"));
        assert!(is_valid_e164_phone("+14165551234")); // Toronto
        // UK: +44 + 9-10 digits.
        assert!(is_valid_e164_phone("+442079460007"));  // Landline: 10
        assert!(is_valid_e164_phone("+447912345678"));  // Mobile: 10
        // Germany: +49 + 7-13.
        assert!(is_valid_e164_phone("+4930901820"));
        // France: +33 + exactly 9.
        assert!(is_valid_e164_phone("+33142685300"));
        // Japan: +81 + 9-10.
        assert!(is_valid_e164_phone("+81312345678"));
        // Australia: wide length range allowed.
        assert!(is_valid_e164_phone("+61293744000"));
        // 3-digit country code: Ireland.
        assert!(is_valid_e164_phone("+35314123456"));
        // With formatting — regex can leave dashes/spaces.
        assert!(is_valid_e164_phone("+1 (415) 555-2671"));
    }

    #[test]
    fn test_e164_phone_invalid() {
        // Missing +.
        assert!(!is_valid_e164_phone("14155552671"));
        // Unknown country code — neither 999, 99, nor 9 are in
        // the E.164 table, so every fallback prefix fails.
        assert!(!is_valid_e164_phone("+99912345678"));
        // All-same-digit sentinels.
        assert!(!is_valid_e164_phone("+10000000000"));
        assert!(!is_valid_e164_phone("+19999999999"));
        // +1 with an invalid NPA.
        assert!(!is_valid_e164_phone("+11111111111")); // NPA 111
        assert!(!is_valid_e164_phone("+19110000000")); // NPA 911 (N11)
        assert!(!is_valid_e164_phone("+19990000000")); // NPA 999 (triple)
        // +44 with too-short NSN (UK min 9).
        assert!(!is_valid_e164_phone("+441234567"));
        // +33 with NSN length 7 (France requires exactly 9).
        assert!(!is_valid_e164_phone("+331234567"));
        // +1 with too-short NSN (NANP requires exactly 10).
        assert!(!is_valid_e164_phone("+1415555267"));
        // Total too short.
        assert!(!is_valid_e164_phone("+123456"));
        // Total too long.
        assert!(!is_valid_e164_phone("+1234567890123456"));
    }

    #[test]
    fn test_us_phone_valid() {
        // Bare 10-digit NANP.
        assert!(is_valid_us_phone("4155552671"));
        assert!(is_valid_us_phone("(415) 555-2671"));
        assert!(is_valid_us_phone("415-555-2671"));
        assert!(is_valid_us_phone("415.555.2671"));
        // 11-digit with leading 1.
        assert!(is_valid_us_phone("14155552671"));
        assert!(is_valid_us_phone("1-415-555-2671"));
    }

    #[test]
    fn test_us_phone_invalid() {
        // Invalid NPA.
        assert!(!is_valid_us_phone("0155552671"));  // NPA 015
        assert!(!is_valid_us_phone("9115552671"));  // NPA 911 (N11)
        // Invalid exchange code (first digit 0 or 1).
        assert!(!is_valid_us_phone("4150555267"));  // exchange 055
        assert!(!is_valid_us_phone("4151555267"));  // exchange 155
        // N11 exchange.
        assert!(!is_valid_us_phone("4152115555")); // exchange 211
        // All-same garbage.
        assert!(!is_valid_us_phone("0000000000"));
        assert!(!is_valid_us_phone("9999999999"));
        // Wrong length.
        assert!(!is_valid_us_phone("415555267"));
        assert!(!is_valid_us_phone("41555526710"));
    }

    #[test]
    fn test_plausible_phone_valid() {
        // Real US number with country code.
        assert!(is_plausible_phone("+14155552671"));
        // Real UK number.
        assert!(is_plausible_phone("+442079460007"));
        // Without country code, just 10 digits.
        assert!(is_plausible_phone("4155552671"));
        // With formatting.
        assert!(is_plausible_phone("+1 (415) 555-2671"));
        // Minimum-length (8 digits).
        assert!(is_plausible_phone("12345678"));
    }

    #[test]
    fn test_plausible_phone_invalid() {
        // All-same-digit sentinels.
        assert!(!is_plausible_phone("+10000000000"));
        assert!(!is_plausible_phone("+19999999999"));
        assert!(!is_plausible_phone("0000000000"));
        // Long run of the same digit with one outlier — the
        // "+1 then ten zeros" shape the blind harness surfaced.
        // digits.len() == 11, longest_run == 10 (of 0s), and
        // 10 >= 11 - 1, so it's rejected.
        assert!(!is_plausible_phone("+11111111119"));
        // Too short.
        assert!(!is_plausible_phone("1234567"));
        assert!(!is_plausible_phone("+441234"));
        // Too long.
        assert!(!is_plausible_phone("1234567890123456"));
    }

    #[test]
    fn test_iban_valid() {
        // Canonical test IBANs from the ISO 13616 examples. Each of
        // these passes the mod-97 check and matches its country's
        // expected length.
        assert!(is_valid_iban("DE89370400440532013000"));
        assert!(is_valid_iban("GB82WEST12345698765432"));
        assert!(is_valid_iban("FR1420041010050500013M02606"));
        assert!(is_valid_iban("NL91ABNA0417164300"));
        assert!(is_valid_iban("CH9300762011623852957"));
        assert!(is_valid_iban("BE68539007547034"));
        // Spaces are allowed — most real-world IBANs are written
        // with 4-char groups.
        assert!(is_valid_iban("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn test_iban_invalid() {
        // Bumped last digit → mod-97 fails.
        assert!(!is_valid_iban("DE89370400440532013001"));
        assert!(!is_valid_iban("GB82WEST12345698765433"));
        assert!(!is_valid_iban("FR1420041010050500013M02607"));
        // Unknown country code — XX is not in the ISO table.
        assert!(!is_valid_iban("XX82WEST12345698765432"));
        // Wrong length for country (DE is 22, this is 21).
        assert!(!is_valid_iban("DE8937040044053201300"));
        // Too short to be any IBAN.
        assert!(!is_valid_iban("DE89"));
        // Non-alphanumeric in the BBAN.
        assert!(!is_valid_iban("DE89370400440532.13000"));
    }

    #[test]
    fn test_canada_sin_valid() {
        // 046-454-286 is a commonly-published Luhn-valid test SIN.
        assert!(is_valid_canada_sin("046-454-286"));
        assert!(is_valid_canada_sin("046454286"));
    }

    #[test]
    fn test_canada_sin_invalid() {
        // Bumped check digit.
        assert!(!is_valid_canada_sin("046-454-287"));
        // Sequential digits — sum = 47, fails Luhn.
        assert!(!is_valid_canada_sin("123-456-789"));
        // All-ones sequence — sum = 13, fails Luhn. (Don't use
        // 111-111-118: that one happens to pass Luhn by coincidence,
        // sum = 20.)
        assert!(!is_valid_canada_sin("111-111-111"));
        // Sentinel all-zeros — passes Luhn arithmetically but we
        // reject it explicitly because no real SIN is all zeros.
        assert!(!is_valid_canada_sin("000-000-000"));
        // Wrong digit count.
        assert!(!is_valid_canada_sin("12345678"));
        assert!(!is_valid_canada_sin("1234567890"));
    }

    #[test]
    fn test_isin_valid() {
        // Published ISIN test values with correct Luhn check digits.
        assert!(is_valid_isin("US0378331005")); // Apple
        assert!(is_valid_isin("US5949181045")); // Microsoft
        assert!(is_valid_isin("GB0002634946")); // BAE Systems
        assert!(is_valid_isin("DE000BASF111")); // BASF
    }

    #[test]
    fn test_isin_invalid() {
        // Wrong check digit.
        assert!(!is_valid_isin("US0378331006"));
        // RAMQ-shaped "4 letters + 8 digits" — used to fire the ISIN
        // pattern at runtime because the pattern had no checksum.
        assert!(!is_valid_isin("ABCD12345678"));
        assert!(!is_valid_isin("DUPO99123456"));
        assert!(!is_valid_isin("TREF98765432"));
        // Wrong length.
        assert!(!is_valid_isin("US037833100"));
        assert!(!is_valid_isin("US03783310055"));
        // Final char not a digit.
        assert!(!is_valid_isin("US037833100X"));
    }

    #[test]
    fn test_validate_match_imei_luhn_gates_invoice_numbers() {
        // Regression: before this change the IMEI sub_category had no
        // validator registered, so any 15-digit sequence that also
        // matched the IMEI regex was accepted. That included Luhn-
        // failing Amex-shaped card numbers (also 15 digits), which
        // showed up in the blind-test report as "100% credit card
        // false positives." After the fix, validate_match must run
        // Luhn on IMEI exactly like PAN.
        let cat = "Device Identifiers";
        // Amex test numbers bumped by 1 → Luhn-invalid → must reject.
        assert!(!validate_match(cat, "IMEI", "378282246310006"));
        assert!(!validate_match(cat, "IMEI", "371449635398432"));
        // Invoice-shaped 15-digit numbers that happen to fail Luhn.
        assert!(!validate_match(cat, "IMEI", "123456789012345"));
        // Real-shape Luhn-valid IMEI — must accept.
        // IMEI 490154203237518 is a common test value that passes Luhn.
        assert!(validate_match(cat, "IMEI", "490154203237518"));
    }

    #[test]
    fn test_validate_match_masked_pan_not_luhn_checked() {
        // Masked PAN deliberately bypasses Luhn — only 8 of its
        // characters are digits, which is below is_luhn_valid's
        // 12-digit floor. If we ever extend the validator to cover
        // Masked PAN we must also relax the digit-count gate or add
        // a separate masked-card validator. This test pins the
        // current behaviour so that change is intentional.
        let cat = "Primary Account Numbers";
        assert!(validate_match(cat, "Masked PAN", "4242XXXXXXXX1234"));
        assert!(validate_match(cat, "Masked PAN", "4242********1234"));
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
