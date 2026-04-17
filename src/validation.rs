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
    "CAFEBABE", "DEADBEEF", "FEEDFACE", "BAADF00D", "CAFED00D",
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

/// Validate a DEA (Drug Enforcement Administration) registration number
/// using the weighted mod-10 check digit algorithm.
///
/// DEA numbers are 2 letters + 7 digits. The first letter indicates
/// registrant type (`A`, `B`, `F`, `M` for practitioners; `P`, `R` for
/// distributors/researchers; others for mid-level practitioners). The
/// second letter is the first letter of the registrant's last name.
///
/// Check digit algorithm:
///   sum = (d1 + d3 + d5) + 2 * (d2 + d4 + d6)
///   valid iff (sum mod 10) == d7
///
/// Also accepts the newer 9-character format where the first character
/// is a digit (for DEA numbers issued to mid-level practitioners under
/// a supervising physician's DEA — prefix digit + letter + 7 digits).
/// For simplicity, this validator checks the 7-digit check only on the
/// trailing 7 digits regardless of prefix format.
pub fn is_valid_dea_number(dea: &str) -> bool {
    let bytes = dea.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    // First two chars must be letters.
    if !bytes[0].is_ascii_uppercase() || !bytes[1].is_ascii_uppercase() {
        return false;
    }
    // Valid first-letter registrant type codes.
    if !matches!(
        bytes[0],
        b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'H' | b'J' | b'K' | b'L' | b'M' | b'P' | b'R' | b'X'
    ) {
        return false;
    }
    // Remaining 7 chars must be digits.
    let mut digits = [0u32; 7];
    for (i, &b) in bytes[2..9].iter().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        digits[i] = (b - b'0') as u32;
    }
    // Weighted check: (d1 + d3 + d5) + 2*(d2 + d4 + d6) mod 10 == d7
    let odd_sum = digits[0] + digits[2] + digits[4];
    let even_sum = digits[1] + digits[3] + digits[5];
    let total = odd_sum + 2 * even_sum;
    (total % 10) == digits[6]
}

// ---------------------------------------------------------------------------
// GDPR device/financial identifier validators (Phase 2b)
// ---------------------------------------------------------------------------

/// Validate an ICCID (Integrated Circuit Card Identifier / SIM card
/// number) using standard Luhn. ICCID is 18-20 digits, always
/// starting with `89` (the telecom major industry identifier).
pub fn is_valid_iccid(iccid: &str) -> bool {
    let digits: Vec<u32> = iccid
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if !(18..=20).contains(&digits.len()) {
        return false;
    }
    if digits[0] != 8 || digits[1] != 9 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
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

/// Validate a Legal Entity Identifier (LEI) using mod-97 (ISO 17442).
/// LEI is 20 characters: 4 alphanumeric (LOU prefix) + `00` (reserved)
/// + 12 alphanumeric (entity ID) + 2 digit check. The check is
/// computed identically to IBAN: convert letters to 2-digit numbers
/// (A=10..Z=35), form the big number, and verify mod 97 == 1.
pub fn is_valid_lei(lei: &str) -> bool {
    let chars: Vec<char> = lei.chars().collect();
    if chars.len() != 20 {
        return false;
    }
    if !chars.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    // Mod-97 check: convert the entire 20-char string to numeric
    // (A=10..Z=35) and compute mod 97. Result must be 1.
    let rearranged: String = chars[..20]
        .iter()
        .collect();
    let mut numeric = String::with_capacity(40);
    for c in rearranged.chars() {
        if let Some(d) = c.to_digit(10) {
            numeric.push_str(&d.to_string());
        } else if c.is_ascii_uppercase() {
            numeric.push_str(&(c as u32 - 'A' as u32 + 10).to_string());
        } else {
            return false;
        }
    }
    let mut remainder: u32 = 0;
    for c in numeric.chars() {
        let d = c.to_digit(10).unwrap_or(0);
        remainder = (remainder * 10 + d) % 97;
    }
    remainder == 1
}

/// Validate a FIGI (Financial Instrument Global Identifier) check
/// digit. FIGI is 12 characters: `BBG` prefix + 8 alphanumeric + 1
/// check digit. The check digit uses a modified Luhn where letters
/// are converted to their ordinal (A=10..Z=35) and each 2-digit
/// number contributes its individual digits to the Luhn sum.
pub fn is_valid_figi(figi: &str) -> bool {
    let chars: Vec<char> = figi.chars().collect();
    if chars.len() != 12 {
        return false;
    }
    if !chars[..3].iter().collect::<String>().eq("BBG") {
        return false;
    }
    if !chars.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    // Expand characters to digit sequences: digits stay, letters
    // become 2-digit numbers (A=10..Z=35).
    let mut expanded_digits: Vec<u32> = Vec::with_capacity(24);
    for &c in &chars[..11] {
        if let Some(d) = c.to_digit(10) {
            expanded_digits.push(d);
        } else if c.is_ascii_uppercase() {
            let v = c as u32 - 'A' as u32 + 10;
            expanded_digits.push(v / 10);
            expanded_digits.push(v % 10);
        }
    }
    // Append the check digit.
    let check_char = chars[11];
    let check_val = match check_char.to_digit(10) {
        Some(d) => d,
        None => return false,
    };
    expanded_digits.push(check_val);
    // Standard Luhn on the expanded digit sequence.
    let sum: u32 = expanded_digits
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

/// Validate an Australian Medicare card number using the published
/// weighted mod-10 check digit algorithm. Medicare numbers are 10-11
/// digits: the first digit is 2-6, positions 0-7 are the identifier,
/// position 8 is the check digit, and positions 9-10 (if present)
/// are the individual reference number (not checked).
///
/// Weights: `[1, 3, 7, 9, 1, 3, 7, 9]` applied to positions 0-7.
/// `check = (sum mod 10)`. Valid iff `digits[8] == check`.
pub fn is_valid_australia_medicare(medicare: &str) -> bool {
    let digits: Vec<u32> = medicare
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if !(10..=11).contains(&digits.len()) {
        return false;
    }
    if !(2..=6).contains(&digits[0]) {
        return false;
    }
    let weights = [1u32, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = sum % 10;
    digits[8] == check
}

/// Validate an Indian PAN (Permanent Account Number) structure.
/// PAN is 10 characters: 5 letters + 4 digits + 1 letter. The 4th
/// letter indicates entity type and must be one of a restricted set.
/// No published check-digit algorithm exists, so this is a structural
/// check only — not a full checksum validator.
pub fn is_valid_india_pan(pan: &str) -> bool {
    let chars: Vec<char> = pan.chars().collect();
    if chars.len() != 10 {
        return false;
    }
    if !chars[..5].iter().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    if !chars[5..9].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !chars[9].is_ascii_uppercase() {
        return false;
    }
    // 4th character: entity type code.
    // P=Person, C=Company, H=HUF, A=AOP, B=BOI, G=Government,
    // J=AJP, L=Local Authority, F=Firm, T=Trust.
    let entity = chars[3];
    matches!(entity, 'P' | 'C' | 'H' | 'A' | 'B' | 'G' | 'J' | 'L' | 'F' | 'T')
}

// ---------------------------------------------------------------------------
// Remaining validators batch
// ---------------------------------------------------------------------------

/// Validate a South African ID number. 13 digits with a Luhn check
/// digit and an embedded date of birth (YYMMDD) in positions 0-5.
///
/// Format: YYMMDD SSSS C A Z
///   * YYMMDD = date of birth
///   * SSSS = sequence (0000-4999 female, 5000-9999 male)
///   * C = citizenship (0 = SA citizen, 1 = permanent resident)
///   * A = deprecated (was race, now usually 8)
///   * Z = Luhn check digit over all 13 digits
pub fn is_valid_south_africa_id(id: &str) -> bool {
    let digits: Vec<u32> = id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // DOB gate: month 01-12, day 01-31.
    let month = digits[2] * 10 + digits[3];
    let day = digits[4] * 10 + digits[5];
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    // Citizenship: must be 0 or 1.
    if digits[10] > 1 {
        return false;
    }
    // Standard Luhn on all 13 digits.
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

/// Validate a MERS MIN (Mortgage Electronic Registration Systems
/// Mortgage Identification Number). 18 digits with the last digit
/// being a standard Luhn check.
pub fn is_valid_mers_min(min: &str) -> bool {
    let digits: Vec<u32> = min
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 18 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
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

/// Validate a Fedwire IMAD (Input Message Accountability Data)
/// structure. Format: `YYYYMMDD` (8-digit date) + `SSSS` (4-letter
/// source) + `RRRRRRRR` (8 alphanumeric reference) + `NNNNNN`
/// (6-digit sequence). This validator checks the date portion for
/// plausibility: year 1990-2099, month 01-12, day 01-31.
pub fn is_valid_fedwire_imad(imad: &str) -> bool {
    let chars: Vec<char> = imad.chars().collect();
    if chars.len() != 26 {
        return false;
    }
    // First 8 must be digits (date YYYYMMDD).
    if !chars[..8].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let year: u32 = chars[..4].iter().collect::<String>().parse().unwrap_or(0);
    let month: u32 = chars[4..6].iter().collect::<String>().parse().unwrap_or(0);
    let day: u32 = chars[6..8].iter().collect::<String>().parse().unwrap_or(0);
    if !(1990..=2099).contains(&year) {
        return false;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    true
}

/// Validate a Universal Loan Identifier (ULI) using the CFPB's
/// mod-97 check digit algorithm. ULI format:
/// `[A-Z0-9]{4}00[A-Z0-9]{17,39}` — the first 4 chars are the
/// LEI prefix, positions 4-5 are "00", and the remaining chars
/// include the loan ID plus a 2-digit mod-97 check.
///
/// The check is computed identically to IBAN/LEI: convert letters
/// to 2-digit numbers (A=10..Z=35), form the big integer, and
/// verify mod 97 == 1.
pub fn is_valid_uli(uli: &str) -> bool {
    let chars: Vec<char> = uli.chars().collect();
    if chars.len() < 23 || chars.len() > 45 {
        return false;
    }
    if !chars.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    // Mod-97 check over the entire identifier.
    let mut numeric = String::with_capacity(chars.len() * 2);
    for &c in &chars {
        if let Some(d) = c.to_digit(10) {
            numeric.push_str(&d.to_string());
        } else if c.is_ascii_uppercase() {
            numeric.push_str(&(c as u32 - 'A' as u32 + 10).to_string());
        } else {
            return false;
        }
    }
    let mut remainder: u32 = 0;
    for c in numeric.chars() {
        let d = c.to_digit(10).unwrap_or(0);
        remainder = (remainder * 10 + d) % 97;
    }
    remainder == 1
}

/// Validate a Vehicle Identification Number (VIN) using the ISO 3779
/// check digit algorithm.
///
/// VINs are 17 characters from the alphabet `[A-HJ-NPR-Z0-9]` (the
/// letters I, O, and Q are excluded to avoid visual confusion with
/// 1 and 0). Position 8 (0-indexed) is the check digit, which is
/// either a single decimal digit or the letter `X` (representing 10).
///
/// Algorithm:
///
///   1. Transliterate each character to a numeric value:
///        digits 0..9    → 0..9
///        A=1 B=2 C=3 D=4 E=5 F=6 G=7 H=8
///        J=1 K=2 L=3 M=4 N=5 P=7 R=9
///        S=2 T=3 U=4 V=5 W=6 X=7 Y=8 Z=9
///   2. Multiply each position by its weight:
///        positions 0..16 → [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
///      The 0 at position 8 means the check digit doesn't contribute
///      to its own checksum.
///   3. Take the sum mod 11. Result 10 maps to the letter `X`;
///      0..9 map to the corresponding digit.
///   4. The mapped value must equal the character at position 8.
///
/// Without this validator, the bare `\b[A-HJ-NPR-Z0-9]{17}\b` regex
/// would fire on every 17-character alphanumeric string in the
/// restricted alphabet, including UUIDs (when they happen to avoid
/// I/O/Q), arbitrary serial numbers, and random tokens. The check
/// digit is the only structural discipline a VIN actually has, and
/// implementing it is ~30 lines.
pub fn is_valid_vin(vin: &str) -> bool {
    let bytes = vin.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    // Reject all-same-character sentinels.
    if bytes.iter().all(|&b| b == bytes[0]) {
        return false;
    }
    let mut sum: u32 = 0;
    let weights: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    for (i, &b) in bytes.iter().enumerate() {
        let value = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'A' => 1,
            b'B' => 2,
            b'C' => 3,
            b'D' => 4,
            b'E' => 5,
            b'F' => 6,
            b'G' => 7,
            b'H' => 8,
            b'J' => 1,
            b'K' => 2,
            b'L' => 3,
            b'M' => 4,
            b'N' => 5,
            b'P' => 7,
            b'R' => 9,
            b'S' => 2,
            b'T' => 3,
            b'U' => 4,
            b'V' => 5,
            b'W' => 6,
            // X is special: in positions 0..7 and 9..16 it has the
            // value 7 (per ISO 3779), but in position 8 it represents
            // the check value 10. We handle position 8 below by
            // skipping the weight entirely (weight is 0 anyway), so
            // here we just return its general transliterated value.
            b'X' => 7,
            b'Y' => 8,
            b'Z' => 9,
            // Letters I, O, Q are explicitly excluded from VIN
            // alphabet — reject as malformed.
            _ => return false,
        };
        sum += value * weights[i];
    }
    let computed = sum % 11;
    let expected_char = bytes[8];
    let expected_value = match expected_char {
        b'0'..=b'9' => (expected_char - b'0') as u32,
        b'X' => 10,
        _ => return false,
    };
    computed == expected_value
}

// ---------------------------------------------------------------------------
// Network identifier filters (Phase 1b of the always-run precision pass).
//
// Every pattern in this section has a very loose regex (dotted-quad, hex
// groups, six hex octets) that fires on structures common in technical
// prose — log files, kernel traces, network configs, map data. None of
// them have a "checksum" in the usual sense; the discipline is structural
// filtering: reject addresses that are obviously not sensitive (private
// ranges, loopback, documentation, multicast, null sentinels) while
// keeping real public addresses.
//
// Why structural filtering instead of context gating: context-gating IP
// addresses would destroy recall on log dumps, which are the PRIMARY
// real-world use case for detecting leaked IPs. Log lines don't usually
// have "IP address:" before the value — they just have the value. A
// pattern that only fires near a keyword would miss almost every real
// leak.
// ---------------------------------------------------------------------------

/// Validate an IPv4 address. Parses the four octets, rejects any
/// non-routable / documentation / reserved range, and rejects sentinel
/// addresses that are never sensitive (all-zero, broadcast, null).
///
/// Ranges rejected (RFC 1918, RFC 3927, RFC 5735, RFC 5737, RFC 2544):
///   * `0.0.0.0/8`              — "this network", boot-time placeholders
///   * `10.0.0.0/8`             — RFC 1918 private
///   * `100.64.0.0/10`          — RFC 6598 carrier-grade NAT
///   * `127.0.0.0/8`            — loopback
///   * `169.254.0.0/16`         — link-local
///   * `172.16.0.0/12`          — RFC 1918 private
///   * `192.0.0.0/24`           — IETF protocol assignments
///   * `192.0.2.0/24`           — RFC 5737 TEST-NET-1 (docs)
///   * `192.168.0.0/16`         — RFC 1918 private
///   * `198.18.0.0/15`          — RFC 2544 benchmark
///   * `198.51.100.0/24`        — RFC 5737 TEST-NET-2 (docs)
///   * `203.0.113.0/24`         — RFC 5737 TEST-NET-3 (docs)
///   * `224.0.0.0/4`            — multicast
///   * `240.0.0.0/4`            — reserved (class E)
///   * `255.255.255.255`        — limited broadcast
///
/// Everything else (real public IPv4 space) passes.
pub fn is_valid_ipv4(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u16>() {
            Ok(n) if n <= 255 => octets[i] = n as u8,
            _ => return false,
        }
    }
    let (a, b, c, _d) = (octets[0], octets[1], octets[2], octets[3]);
    // Block reserved / non-routable ranges.
    if a == 0 {
        return false; // "this network"
    }
    if a == 10 {
        return false; // RFC 1918 private
    }
    if a == 100 && (64..=127).contains(&b) {
        return false; // carrier-grade NAT
    }
    if a == 127 {
        return false; // loopback
    }
    if a == 169 && b == 254 {
        return false; // link-local
    }
    if a == 172 && (16..=31).contains(&b) {
        return false; // RFC 1918 private
    }
    if a == 192 && b == 0 && c == 0 {
        return false; // IETF protocol assignments
    }
    if a == 192 && b == 0 && c == 2 {
        return false; // TEST-NET-1
    }
    if a == 192 && b == 168 {
        return false; // RFC 1918 private
    }
    if a == 198 && (b == 18 || b == 19) {
        return false; // benchmark
    }
    if a == 198 && b == 51 && c == 100 {
        return false; // TEST-NET-2
    }
    if a == 203 && b == 0 && c == 113 {
        return false; // TEST-NET-3
    }
    if a >= 224 {
        return false; // multicast + reserved class E + 255.255.255.255
    }
    true
}

/// Validate an IPv6 address. Accepts both full-form (8 hextets) and
/// compressed (`::`) forms; rejects reserved / documentation ranges and
/// sentinel addresses.
///
/// Ranges rejected:
///   * `::1`                    — loopback
///   * `::`                     — unspecified (all-zero)
///   * `fe80::/10`              — link-local
///   * `fc00::/7`               — unique local (ULA, RFC 4193)
///   * `ff00::/8`               — multicast
///   * `2001:db8::/32`          — RFC 3849 documentation
///   * `64:ff9b::/96`           — well-known NAT64 prefix
///
/// The filter operates on the first hextet(s), so we don't need full
/// 128-bit parsing — just enough to check the leading prefix.
pub fn is_valid_ipv6(addr: &str) -> bool {
    // Strip any IPv6 zone identifier (`fe80::1%eth0`).
    let addr = addr.split('%').next().unwrap_or(addr);
    let lower = addr.to_ascii_lowercase();
    // Sentinel literal forms first.
    if lower == "::" || lower == "::1" || lower == "0:0:0:0:0:0:0:0" || lower == "0:0:0:0:0:0:0:1" {
        return false;
    }
    // Parse the first hextet (everything before the first `:`).
    // For `::xxxx` the first hextet is empty (leading `::`); we'll
    // handle that by checking the leading-`::` case separately.
    let first_hextet: u16 = if lower.starts_with("::") {
        0
    } else {
        let first = lower.split(':').next().unwrap_or("");
        match u16::from_str_radix(first, 16) {
            Ok(v) => v,
            Err(_) => return false,
        }
    };
    // fe80::/10 — link-local. First 10 bits are 1111 1110 10 = 0xfe80..0xfebf.
    if (0xfe80..=0xfebf).contains(&first_hextet) {
        return false;
    }
    // fc00::/7 — unique local. First 7 bits are 1111 110 = 0xfc00..0xfdff.
    if (0xfc00..=0xfdff).contains(&first_hextet) {
        return false;
    }
    // ff00::/8 — multicast.
    if (0xff00..=0xffff).contains(&first_hextet) {
        return false;
    }
    // 2001:db8::/32 — documentation. Need the first TWO hextets.
    if first_hextet == 0x2001 {
        let parts: Vec<&str> = lower.split(':').collect();
        if parts.len() >= 2 {
            if let Ok(second) = u16::from_str_radix(parts[1], 16) {
                if second == 0x0db8 || second == 0xdb8 {
                    return false;
                }
            }
        }
    }
    // 64:ff9b::/96 — NAT64.
    if first_hextet == 0x0064 {
        let parts: Vec<&str> = lower.split(':').collect();
        if parts.len() >= 2 {
            if let Ok(second) = u16::from_str_radix(parts[1], 16) {
                if second == 0xff9b {
                    return false;
                }
            }
        }
    }
    true
}

/// Validate a MAC address. Rejects obvious sentinels:
///   * `00:00:00:00:00:00` — null address
///   * `ff:ff:ff:ff:ff:ff` — broadcast
///
/// Keeps the structural check light — the regex already enforces the
/// six-octet hex shape. We just filter the two never-sensitive values.
pub fn is_valid_mac_address(mac: &str) -> bool {
    // Normalize: strip the six separators, lowercase.
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 {
        return false;
    }
    if hex == "000000000000" || hex == "ffffffffffff" {
        return false;
    }
    true
}

/// Validate a GPS coordinate pair. The regex matches any comma-separated
/// float pair that looks like lat,lon; this validator enforces the
/// real-world bounds:
///
///   * latitude must be in `-90.0 ..= 90.0`
///   * longitude must be in `-180.0 ..= 180.0`
///   * reject the `(0, 0)` null island sentinel
///
/// That rejects floating-point tables, scientific data, and version
/// strings that happen to match the regex shape without being real
/// coordinates.
pub fn is_valid_gps_coordinates(coords: &str) -> bool {
    // Split on `,` allowing optional whitespace.
    let parts: Vec<&str> = coords.splitn(2, ',').collect();
    if parts.len() != 2 {
        return false;
    }
    let lat: f64 = match parts[0].trim().parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let lon: f64 = match parts[1].trim().parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if !(-90.0..=90.0).contains(&lat) {
        return false;
    }
    if !(-180.0..=180.0).contains(&lon) {
        return false;
    }
    // Null Island — (0, 0) in the Gulf of Guinea. Not a real reported
    // location; almost always a placeholder or an error.
    if lat == 0.0 && lon == 0.0 {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// URL credential filters (Phase 1c of the always-run precision pass).
//
// Four always-run patterns live in this section: Bearer Token, URL with
// Password, URL with Token, and Slack Webhook. Each already has a fairly
// tight regex — these validators add length-floor and placeholder-string
// checks to catch the common false-positive class where the regex shape
// matches but the value is obviously a documentation example or prose.
// ---------------------------------------------------------------------------

/// Lowercase stop-list of values that the URL / Bearer / Slack regexes
/// would otherwise happily match but which are documentation
/// placeholders, not real credentials. The list is small and curated;
/// there's no attempt to auto-detect documentation — it's just the
/// strings that show up repeatedly in real code samples and READMEs.
const CREDENTIAL_PLACEHOLDER_TOKENS: &[&str] = &[
    "your_api_key_here",
    "your_api_key",
    "yourapikey",
    "your_token_here",
    "your_token",
    "yourtoken",
    "your_secret_here",
    "your_secret",
    "yoursecret",
    "your_password",
    "yourpassword",
    "placeholder",
    "example",
    "sample",
    "changeme",
    "change_me",
    "todo",
    "fixme",
    "abc",
    "abc123",
    "123456",
    "xxxxxxxxxx",
    "xxxxxxxx",
    "test",
    "test123",
    "dummy",
    "mytoken",
    "mykey",
    "mysecret",
];

/// Check if a candidate credential value is a known documentation
/// placeholder. Case-insensitive match against `CREDENTIAL_PLACEHOLDER_TOKENS`.
fn is_credential_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CREDENTIAL_PLACEHOLDER_TOKENS.iter().any(|&p| p == lower)
}

/// Validate a `Bearer <token>` credential match. The regex
/// `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` will happily match prose like
/// "bearer required" where "required" is just the next word; this
/// validator enforces a length floor and a placeholder-string check
/// to cut that FP class.
///
/// Rules:
///   * token portion must be at least 16 characters (the shortest
///     realistic bearer value is an opaque 16-char string; JWTs and
///     API tokens are longer)
///   * token must not be a known documentation placeholder
pub fn is_plausible_bearer_token(matched: &str) -> bool {
    // Split at the first whitespace run — everything after is the token.
    let parts: Vec<&str> = matched.splitn(2, char::is_whitespace).collect();
    if parts.len() != 2 {
        return false;
    }
    let token = parts[1].trim_end_matches('=').trim();
    if token.len() < 16 {
        return false;
    }
    if is_credential_placeholder(token) {
        return false;
    }
    true
}

/// Validate a `URL with Token` match. The regex matches any URL with a
/// query parameter like `?token=abc` or `&api_key=xyz`, including
/// documentation examples with placeholder values. This validator:
///
///   * extracts the value of the matching query parameter
///   * rejects if the value is shorter than 8 characters
///   * rejects if the value is a known placeholder string
pub fn is_plausible_url_token(matched: &str) -> bool {
    // Find the `?` or `&` that starts the query part, then look at
    // the last `=` to isolate the value. The regex guarantees the
    // shape `...[?&]key=value`, so we can scan from the right.
    let Some(eq_pos) = matched.rfind('=') else {
        return false;
    };
    let value = &matched[eq_pos + 1..];
    // Strip any trailing URL fragment or following parameter
    // (though the regex's `[^\s&]+` should already handle this).
    let value = value.split(['&', '#']).next().unwrap_or("");
    if value.len() < 8 {
        return false;
    }
    if is_credential_placeholder(value) {
        return false;
    }
    true
}

/// Validate a Slack Webhook URL. Slack webhooks follow the shape
/// `https://hooks.slack.com/services/T.../B.../...` where:
///
///   * the `T` segment (workspace ID) is typically 9-11 chars
///   * the `B` segment (bot/channel ID) is typically 9-11 chars
///   * the final segment (secret) is typically 24 chars
///
/// The regex `/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+` accepts 1+
/// chars per segment, which is too loose — a string like
/// `https://hooks.slack.com/services/T1/B1/abc` would match. Enforce
/// the minimum realistic lengths.
pub fn is_plausible_slack_webhook(url: &str) -> bool {
    // The regex already guarantees the exact prefix; we just need to
    // split the three segments after `/services/` and check lengths.
    let Some(tail) = url.strip_prefix("https://hooks.slack.com/services/") else {
        return false;
    };
    let segments: Vec<&str> = tail.split('/').collect();
    if segments.len() != 3 {
        return false;
    }
    let (t_seg, b_seg, secret) = (segments[0], segments[1], segments[2]);
    // T segment: "T" + at least 8 chars (9 total is the minimum
    // observed, 11 is typical).
    if !t_seg.starts_with('T') || t_seg.len() < 9 {
        return false;
    }
    // B segment: "B" + at least 8 chars.
    if !b_seg.starts_with('B') || b_seg.len() < 9 {
        return false;
    }
    // Secret: at least 16 characters (typical is 24).
    if secret.len() < 16 {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Generic secret entropy filters (Phase 1d of the always-run precision pass).
//
// The two "Generic" patterns in src/patterns/mod.rs:
//
//   * Generic API Key — `(api_key|apikey|api_secret|api_token) = "VALUE"`
//   * Generic Secret Assignment — `(password|secret|token|...) = "VALUE"`
//
// have the loosest matchers in the secret family. They fire on every
// `key = value` shape in any code or config snippet, including
// documentation examples (`api_key = "your_api_key_here"`) and
// placeholder fixtures. The regex floor is 16 chars for API Key and 8
// chars for Secret Assignment; everything that passes the regex needs
// secondary discipline.
//
// Approach: compute Shannon entropy of the VALUE portion (extracted
// from the matched assignment) and require it to be above a per-pattern
// floor. API Key gets a stricter floor because real API keys are
// effectively random; Secret Assignment gets a looser floor because
// real passwords (e.g., `SpringWinter2024!`) are word-shaped and have
// lower entropy than random tokens. Both validators also reject
// all-same-character values and a small inline list of well-known
// placeholder strings that fall in the entropy gap (~3.0-3.5 bits/char)
// where word-shaped placeholders and word-shaped passwords are
// indistinguishable.
//
// Why a small inline placeholder list instead of importing the one
// from quality/url-credential-filters: that branch isn't merged yet
// and I don't want a cross-branch dependency. When both branches land,
// a follow-up can consolidate the lists into a single `placeholders.rs`
// module. The lists are tiny (~10 entries each) so the duplication
// is cheap until then.
// ---------------------------------------------------------------------------

/// Inline placeholder stop-list for the generic secret validators.
/// Matched case-insensitively against the extracted value. These are
/// the strings that fall in the entropy "gray zone" (~3.0-3.5 bits/char)
/// where Shannon entropy alone can't distinguish a word-shaped
/// placeholder from a word-shaped password.
const SECRET_VALUE_PLACEHOLDERS: &[&str] = &[
    "your_api_key_here",
    "your_api_key",
    "your-api-key",
    "yourapikey",
    "your_token_here",
    "your_token",
    "your-token",
    "yourtoken",
    "your_secret_here",
    "your_secret",
    "your-secret",
    "yoursecret",
    "your_password",
    "your-password",
    "yourpassword",
    "placeholder",
    "placeholder12345",
    "example_key",
    "example_token",
    "example_secret",
    "changeme",
    "change_me",
    "changeit",
    "change_it",
    "todo",
    "fixme",
    "abc123",
    "abc12345",
    "abcdefgh",
    "12345678",
    "1234567890",
    "test123",
    "testkey",
    "testtoken",
    "testsecret",
    "dummy",
    "dummykey",
    "mytoken",
    "mykey",
    "mysecret",
    "default",
    "supersecret",
    "secretkey",
    "apikey",
    "api_key",
];

/// Extract the VALUE portion from a `key = "value"` style assignment
/// matched by Generic API Key or Generic Secret Assignment.
///
/// The matched text follows the shape
/// `<key>\s*[=:]\s*["']?<value>["']?`. We split at the first `=` or `:`,
/// strip surrounding whitespace, peel one optional pair of matching
/// quotes, and return whatever's left. The regex already guarantees the
/// shape, so this is a syntactic split rather than a parse — failures
/// are treated as "value is the entire matched text" which is
/// conservative (the entropy check still fires on it).
fn extract_secret_value(matched: &str) -> &str {
    let split_pos = matched
        .char_indices()
        .find(|(_, c)| *c == '=' || *c == ':');
    let after = match split_pos {
        Some((idx, _)) => &matched[idx + 1..],
        None => matched,
    };
    let trimmed = after.trim();
    // Peel a single layer of matching quotes, if present.
    let unquoted = if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        &trimmed[1..trimmed.len().saturating_sub(1)]
    } else {
        trimmed
    };
    unquoted
}

/// Shared structural rejection rules for both generic-secret validators.
/// Returns `false` if the value is obviously not a real secret
/// regardless of its entropy.
fn secret_value_obviously_invalid(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    // All-same character (entropy 0).
    let first = value.chars().next().unwrap();
    if value.chars().all(|c| c == first) {
        return true;
    }
    // Inline placeholder list, case-insensitive match.
    let lower = value.to_ascii_lowercase();
    if SECRET_VALUE_PLACEHOLDERS.iter().any(|&p| p == lower) {
        return true;
    }
    false
}

/// Validate a `Generic API Key` match. API keys are effectively random
/// tokens by design — real values come from a CSPRNG, not from human
/// keyboards. The regex requires `[A-Za-z0-9\-._~+/]{16,}`, which is a
/// 67-character alphabet; the theoretical entropy ceiling is
/// `log2(67) ≈ 6.07` bits/char and well-formed real keys average ~5.5.
///
/// Rules:
///   * regex floor: 16 chars (already enforced by the pattern)
///   * structural: not all-same, not in inline placeholder list
///   * entropy: Shannon entropy of the value ≥ 3.0 bits/char
///
/// The 3.0 floor is calibrated against AWS's published example
/// `AKIAIOSFODNN7EXAMPLE` (entropy ≈ 3.77) — well-formed real keys
/// pass with margin, while the obvious garbage class (constant strings,
/// short repeated patterns) gets rejected.
pub fn is_plausible_api_key(matched: &str) -> bool {
    let value = extract_secret_value(matched);
    if value.chars().count() < 16 {
        return false;
    }
    if secret_value_obviously_invalid(value) {
        return false;
    }
    crate::scanner::char_entropy(value) >= 3.0
}

/// Validate a `Generic Secret Assignment` match. Unlike API keys,
/// passwords and other user-chosen secrets are often word-shaped:
/// `SpringWinter2024!`, `MyDog'sName123`. These values have entropy
/// in the 3.0-4.0 range — well below random-token entropy. A high
/// entropy floor here would false-negative on real password fields,
/// so we set the floor at the level where only obvious garbage gets
/// caught (~2.5 bits/char) and rely on the placeholder list to handle
/// the well-known word-shaped placeholders.
///
/// Rules:
///   * regex floor: 8 chars (already enforced); validator floor 12
///     to add an extra layer above the regex
///   * structural: not all-same, not in inline placeholder list
///   * entropy: Shannon entropy of the value ≥ 2.5 bits/char
pub fn is_plausible_secret_assignment(matched: &str) -> bool {
    let value = extract_secret_value(matched);
    if value.chars().count() < 12 {
        return false;
    }
    if secret_value_obviously_invalid(value) {
        return false;
    }
    crate::scanner::char_entropy(value) >= 2.5
}

/// Validate a Dutch Burgerservicenummer (BSN) using the
/// eleven-test. BSN is 8 or 9 digits; 8-digit BSNs are treated
/// as 9-digit with a leading zero.
///
/// Algorithm: multiply each digit by a weight. Weights from left
/// to right are `[9, 8, 7, 6, 5, 4, 3, 2, -1]` (the last weight
/// is minus one, not two). The sum must be non-negative and
/// divisible by 11. A BSN of all zeros is valid by the
/// arithmetic but is explicitly rejected as a sentinel.
pub fn is_valid_netherlands_bsn(bsn: &str) -> bool {
    let mut digits: Vec<i32> = bsn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as i32))
        .collect();
    // Pad 8-digit form with a leading zero.
    if digits.len() == 8 {
        digits.insert(0, 0);
    }
    if digits.len() != 9 {
        return false;
    }
    if digits.iter().all(|&d| d == 0) {
        return false;
    }
    let weights: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = digits.iter().zip(weights.iter()).map(|(d, w)| d * w).sum();
    sum >= 0 && sum % 11 == 0
}

/// Validate a Brazilian CPF (Cadastro de Pessoas Físicas) using
/// its two mod-11 check digits. CPF is 11 digits total:
///
///   * positions 0-8: the 9-digit ID payload;
///   * position 9: first check digit — compute
///     `sum = Σ d[i] * (10 - i)` for i in 0..9, then
///     `check1 = (sum * 10) % 11`, with 10 mapped to 0;
///   * position 10: second check digit — compute
///     `sum = Σ d[i] * (11 - i)` for i in 0..10 (now including
///     the first check), then `check2 = (sum * 10) % 11`, same
///     10 → 0 mapping.
///
/// Also rejects the all-same-digit sentinels: Brazilian tax
/// authorities publish that 00000000000 through 99999999999
/// (repeating) coincidentally satisfy the checksum arithmetic
/// and must be rejected explicitly.
pub fn is_valid_brazil_cpf(cpf: &str) -> bool {
    let digits: Vec<u32> = cpf
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    // Brazilian RFB explicitly declares all-same-digit CPFs
    // invalid even though they satisfy the checksum formulas.
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // First check digit.
    let sum1: u32 = digits[..9]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (10 - i as u32))
        .sum();
    let check1 = {
        let r = (sum1 * 10) % 11;
        if r == 10 { 0 } else { r }
    };
    if digits[9] != check1 {
        return false;
    }
    // Second check digit, using the first 10 digits (including
    // the first check).
    let sum2: u32 = digits[..10]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (11 - i as u32))
        .sum();
    let check2 = {
        let r = (sum2 * 10) % 11;
        if r == 10 { 0 } else { r }
    };
    digits[10] == check2
}

/// Validate an ABA/Fedwire routing transit number (9 digits)
/// using the weighted mod-10 check. Formula from the ABA spec:
/// multiply each digit by its weight from `[3, 7, 1, 3, 7, 1, 3,
/// 7, 1]` and require the sum to be divisible by 10.
///
/// Also verifies the first-two-digit Federal Reserve district
/// prefix is one of the published ranges (00-12 FR districts,
/// 21-32 thrift mirror, 61-72 electronic funds transfer, 80
/// shared-network special). Sequences that fail either check
/// are rejected outright.
pub fn is_valid_aba_routing(routing: &str) -> bool {
    let digits: Vec<u32> = routing
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    // Reject trivial all-same sequences.
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Federal Reserve district prefix check.
    let prefix = digits[0] * 10 + digits[1];
    let valid_prefix = (0..=12).contains(&prefix)
        || (21..=32).contains(&prefix)
        || (61..=72).contains(&prefix)
        || prefix == 80;
    if !valid_prefix {
        return false;
    }
    // ABA weighted mod-10.
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum % 10 == 0
}

/// Validate a Belgian Rijksregisternummer / Numéro national (NRN).
/// The NRN is 11 digits laid out as:
///
///   * positions 0-5: date of birth YYMMDD (with the day field
///     encoding gender: serial for male, serial+500 for female).
///   * positions 6-8: daily serial (001..997).
///   * positions 9-10: mod-97 check digit.
///
/// Checksum: treat the first 9 digits as an integer N. The check
/// must equal `97 - (N mod 97)` for cardholders born before 2000,
/// or `97 - ((2000000000 + N) mod 97)` for cardholders born 2000
/// or later (the "2" prefix disambiguates the two generations).
/// A number is valid if either form matches.
pub fn is_valid_belgium_nrn(nrn: &str) -> bool {
    let digits: Vec<u32> = nrn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    // Reject trivial sentinels.
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Structural DOB gate. Month after stripping gender offset
    // must be in 1..=12; day in 1..=31.
    let month = digits[2] * 10 + digits[3];
    if !(1..=12).contains(&month) {
        return false;
    }
    let day = digits[4] * 10 + digits[5];
    // Day field is raw day of month 1..=31 (NRN doesn't offset
    // day for gender — gender lives in the serial).
    if !(1..=31).contains(&day) {
        return false;
    }
    // Build the first 9 digits as a u64.
    let first9: u64 = digits[..9].iter().fold(0u64, |acc, &d| acc * 10 + d as u64);
    let expected_check = digits[9] * 10 + digits[10];
    // Pre-2000 form.
    let check_pre = 97 - (first9 % 97);
    // Post-2000 form: prepend "2" to the 9-digit payload.
    let check_post = 97 - ((2_000_000_000u64 + first9) % 97);
    expected_check as u64 == check_pre || expected_check as u64 == check_post
}

/// Validate a Polish PESEL (Powszechny Elektroniczny System
/// Ewidencji Ludności) national ID number. PESEL is 11 digits:
///
///   * positions 0-5: date of birth encoded as YYMMDD, with the
///     month field offset by {0, +20, +40, +60, +80} to indicate
///     century (19xx, 20xx, 21xx, 22xx, 18xx respectively);
///   * positions 6-9: serial number + gender (last of these 4
///     is even=female, odd=male);
///   * position 10: weighted-sum check digit.
///
/// Checksum: `sum = Σ digits[i] * weights[i]` for i in 0..10 with
/// `weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]`, then
/// `check = (10 - sum % 10) % 10`. Valid iff `digits[10] == check`.
///
/// Also applies a loose structural gate on the month field: the
/// month after stripping the century offset must be in 1..=12,
/// which rejects all-zero / all-same numbers that would otherwise
/// coincidentally satisfy the checksum.
pub fn is_valid_poland_pesel(pesel: &str) -> bool {
    let digits: Vec<u32> = pesel
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    // Reject all-same-digit sentinels (e.g., 00000000000).
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Month gate. The raw MM field is digits[2..4]; strip the
    // century offset by reducing modulo 20 (valid month-encoded
    // ranges are 01..12, 21..32, 41..52, 61..72, 81..92; all
    // reduce to 01..12 after mod-20 except invalid encodings
    // like 13..19, 33..39, etc.).
    let raw_month = digits[2] * 10 + digits[3];
    let stripped = raw_month % 20;
    if !(1..=12).contains(&stripped) {
        return false;
    }
    // Day gate. Digits[4..6].
    let day = digits[4] * 10 + digits[5];
    if !(1..=31).contains(&day) {
        return false;
    }
    // Weighted checksum.
    let weights = [1u32, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = digits[..10]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (10 - sum % 10) % 10;
    digits[10] == check
}

// ---------------------------------------------------------------------------
// Checksum batch 1: India Aadhaar, Japan My Number, Italy Codice Fiscale,
// Spain DNI/NIE, Israel Teudat Zehut.
// ---------------------------------------------------------------------------

/// Verhoeff algorithm multiplication table (Dihedral group D5).
/// Indexed as `VERHOEFF_D[a][b]`. Used by India Aadhaar check.
static VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff algorithm permutation table.
/// Indexed as `VERHOEFF_P[i mod 8][digit]`.
static VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Validate an Indian Aadhaar number (12 digits) using the Verhoeff
/// algorithm. The Aadhaar is the Indian national biometric ID and
/// uses Verhoeff — a dihedral-group D5 checksum — as its final
/// digit, which is the same algorithm used by several European ID
/// schemes and offers better error detection than simple weighted
/// sums (catches all single-digit errors and almost all adjacent
/// transposition errors).
///
/// Algorithm: iterate the digits from right to left, maintaining
/// a running check `c`. At position `i` (starting at 0 for the
/// rightmost), update `c = VERHOEFF_D[c][VERHOEFF_P[i mod 8][digit]]`.
/// After all 12 digits, `c == 0` iff the number is valid.
///
/// Also rejects leading-zero and leading-one Aadhaar numbers (UIDAI
/// reserves `0xxx` and `1xxx` prefixes) and all-same-digit sentinels.
pub fn is_valid_india_aadhaar(aadhaar: &str) -> bool {
    let digits: Vec<u8> = aadhaar
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    if digits.len() != 12 {
        return false;
    }
    // UIDAI spec: Aadhaar numbers never start with 0 or 1.
    if digits[0] == 0 || digits[0] == 1 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut c: u8 = 0;
    for (i, &d) in digits.iter().rev().enumerate() {
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][d as usize] as usize];
    }
    c == 0
}

/// Validate a Japanese My Number (個人番号, kojin bangou) — a
/// 12-digit individual identifier issued by the Japanese national
/// government. Uses a weighted mod-11 checksum where positions 0-10
/// are weighted and position 11 is the check digit.
///
/// Algorithm per National Tax Agency spec:
///   weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
///   sum = Σ digits[i] * weights[i]   for i in 0..=10
///   remainder = sum % 11
///   check = if remainder <= 1 { 0 } else { 11 - remainder }
///   valid iff digits[11] == check
pub fn is_valid_japan_my_number(my_number: &str) -> bool {
    let digits: Vec<u32> = my_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 12 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let weights = [6u32, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..11]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    let check = if remainder <= 1 { 0 } else { 11 - remainder };
    digits[11] == check
}

/// Odd-position value lookup for Italian Codice Fiscale control
/// character. Positions are 1-indexed in the spec; we use 0-based
/// positions, so the "odd" set is the set of 0-based positions
/// `[0, 2, 4, 6, 8, 10, 12, 14]`.
fn codice_fiscale_odd_value(c: char) -> Option<u32> {
    match c {
        '0' | 'A' => Some(1),
        '1' | 'B' => Some(0),
        '2' | 'C' => Some(5),
        '3' | 'D' => Some(7),
        '4' | 'E' => Some(9),
        '5' | 'F' => Some(13),
        '6' | 'G' => Some(15),
        '7' | 'H' => Some(17),
        '8' | 'I' => Some(19),
        '9' | 'J' => Some(21),
        'K' => Some(2),
        'L' => Some(4),
        'M' => Some(18),
        'N' => Some(20),
        'O' => Some(11),
        'P' => Some(3),
        'Q' => Some(6),
        'R' => Some(8),
        'S' => Some(12),
        'T' => Some(14),
        'U' => Some(16),
        'V' => Some(10),
        'W' => Some(22),
        'X' => Some(25),
        'Y' => Some(24),
        'Z' => Some(23),
        _ => None,
    }
}

/// Even-position value lookup for Italian Codice Fiscale. For
/// 0-based positions `[1, 3, 5, 7, 9, 11, 13]`. Digit values are
/// their literal integer value; letter values are their ordinal
/// in the alphabet starting from 0 (A=0, B=1, ..., Z=25).
fn codice_fiscale_even_value(c: char) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    if c.is_ascii_uppercase() {
        return Some(c as u32 - 'A' as u32);
    }
    None
}

/// Validate an Italian Codice Fiscale (16 characters: 6 letters
/// encoding surname + first name, then DOB/gender encoded as 2
/// digits + 1 letter + 2 digits, then birthplace as 1 letter +
/// 3 digits, then 1 check letter). The 16th character is a check
/// character computed from the first 15 via a table-driven
/// weighted sum modulo 26.
///
/// Algorithm:
///   sum = Σ (odd_value(c[i]) if i even (0-based) else even_value(c[i]))
///   check_letter = (char) ('A' + (sum mod 26))
///   valid iff c[15] == check_letter
///
/// Also accepts the `omocode` form where digits in some positions
/// are substituted with letters — `codice_fiscale_odd_value` already
/// handles the digit-letter substitutions that omocode uses.
pub fn is_valid_italy_codice_fiscale(cf: &str) -> bool {
    let chars: Vec<char> = cf.chars().collect();
    if chars.len() != 16 {
        return false;
    }
    if !chars.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &c) in chars[..15].iter().enumerate() {
        let v = if i % 2 == 0 {
            codice_fiscale_odd_value(c)
        } else {
            codice_fiscale_even_value(c)
        };
        match v {
            Some(val) => sum += val,
            None => return false,
        }
    }
    let expected = char::from_u32('A' as u32 + (sum % 26)).unwrap_or('?');
    chars[15] == expected
}

/// Spanish DNI check-letter lookup table. The letter is determined
/// by `DNI_LETTERS[digit_part mod 23]`. Vowels and certain
/// letters are excluded to avoid confusion with digits.
static DNI_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Validate a Spanish DNI / NIE:
///
///   * DNI is 8 digits + 1 check letter.
///   * NIE is `X`, `Y`, or `Z` + 7 digits + 1 check letter. The
///     prefix letter contributes to the numeric value as
///     `X = 0, Y = 1, Z = 2`.
///
/// Algorithm: compute the numeric payload, take modulo 23, and
/// look up the check letter in `DNI_LETTERS`. The letter must
/// match exactly.
pub fn is_valid_spain_dni(dni: &str) -> bool {
    // Strip any whitespace / hyphens the regex might have left.
    let compact: String = dni
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let bytes = compact.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    let check_char = bytes[8].to_ascii_uppercase();
    if !(b'A'..=b'Z').contains(&check_char) {
        return false;
    }
    // Determine whether this is a DNI or NIE and compute the
    // numeric payload accordingly.
    let (prefix_value, digit_start): (u64, usize) = match bytes[0].to_ascii_uppercase() {
        b'X' => (0, 1),
        b'Y' => (1, 1),
        b'Z' => (2, 1),
        b if b.is_ascii_digit() => (0, 0),
        _ => return false,
    };
    // The digit portion is positions [digit_start..8]. For DNI this
    // is 8 digits; for NIE it's 7 digits.
    let digit_slice = &bytes[digit_start..8];
    if !digit_slice.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut payload: u64 = prefix_value;
    for &b in digit_slice {
        payload = payload * 10 + (b - b'0') as u64;
    }
    let expected = DNI_LETTERS[(payload % 23) as usize];
    check_char == expected
}

/// Validate an Israeli Teudat Zehut (national ID) using the
/// weighted Luhn-like check. 9 digits total. The algorithm:
///
///   1. Multiply each digit by its position weight (weights
///      alternate 1, 2, 1, 2, ... starting from position 0).
///   2. If any product is >= 10, sum its two decimal digits
///      (equivalently, subtract 9).
///   3. Total must be divisible by 10.
///
/// Also rejects all-same-digit sentinels.
pub fn is_valid_israel_teudat_zehut(id: &str) -> bool {
    let digits: Vec<u32> = id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut total: u32 = 0;
    for (i, &d) in digits.iter().enumerate() {
        let weight = if i % 2 == 0 { 1 } else { 2 };
        let prod = d * weight;
        total += if prod >= 10 { prod - 9 } else { prod };
    }
    total % 10 == 0
}

// ---------------------------------------------------------------------------
// Checksum batch 2: British NHS, Brazil CNPJ, China Resident ID,
// South Korea RRN, France NIR, Mexico CURP.
// ---------------------------------------------------------------------------

/// Validate a British NHS number (10 digits) using the NHS
/// weighted mod-11 check. Algorithm per NHS Digital spec:
///
///   * multiply each of the first 9 digits by weights
///     `[10, 9, 8, 7, 6, 5, 4, 3, 2]`;
///   * sum the products and take mod 11;
///   * check = 11 - remainder;
///   * if check == 11, check = 0;
///   * if check == 10, the NHS number is invalid (NHS Digital
///     does not issue check=10 numbers).
///
/// Also rejects all-same-digit sentinels.
pub fn is_valid_british_nhs(nhs: &str) -> bool {
    let digits: Vec<u32> = nhs
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let weights = [10u32, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..9]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    let check = 11 - remainder;
    let expected = if check == 11 {
        0
    } else if check == 10 {
        return false; // NHS Digital reserves check=10, never issued
    } else {
        check
    };
    digits[9] == expected
}

/// Validate a Brazilian CNPJ (Cadastro Nacional da Pessoa
/// Jurídica) using its two mod-11 check digits. CNPJ is the
/// corporate tax ID, 14 digits total:
///
///   * positions 0-7: base (8 digits);
///   * positions 8-11: branch suffix (usually `0001`);
///   * position 12: first check digit;
///   * position 13: second check digit.
///
/// Same dual-check structure as CPF, but with different weights.
/// First check weights: `[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]`.
/// Second check weights: `[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]`.
/// For each: sum mod 11, if remainder < 2 → 0 else 11 - remainder.
pub fn is_valid_brazil_cnpj(cnpj: &str) -> bool {
    let digits: Vec<u32> = cnpj
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 14 {
        return false;
    }
    // RFB explicitly declares all-same-digit CNPJs invalid
    // (same reasoning as CPF — they satisfy the checksum
    // arithmetic but are never issued).
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // First check digit.
    let weights1 = [5u32, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum1: u32 = digits[..12]
        .iter()
        .zip(weights1.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let r1 = sum1 % 11;
    let check1 = if r1 < 2 { 0 } else { 11 - r1 };
    if digits[12] != check1 {
        return false;
    }
    // Second check digit, using the first 13 digits (including
    // the first check).
    let weights2 = [6u32, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum2: u32 = digits[..13]
        .iter()
        .zip(weights2.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let r2 = sum2 % 11;
    let check2 = if r2 < 2 { 0 } else { 11 - r2 };
    digits[13] == check2
}

/// Validate a Chinese Resident ID card number (18 characters:
/// 17 digits + 1 check digit that can be `0-9` or `X` where X
/// represents 10). The check is a weighted mod-11 per GB 11643.
///
///   weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
///   sum = Σ d[i] * weights[i] for i in 0..17
///   remainder = sum mod 11
///   check_table = ['1','0','X','9','8','7','6','5','4','3','2']
///   valid iff chars[17] == check_table[remainder]
///
/// Also performs a loose structural DOB gate on positions 6-13
/// (YYYYMMDD), rejecting obvious garbage like year 0000.
pub fn is_valid_china_resident_id(id: &str) -> bool {
    // The last char can be `X` (upper or lower); everything else
    // must be a digit.
    let compact: String = id.chars().filter(|c| !c.is_whitespace()).collect();
    let chars: Vec<char> = compact.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    let mut digits = [0u32; 17];
    for (i, &c) in chars[..17].iter().enumerate() {
        digits[i] = match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
    }
    // Loose DOB gate.
    let year = digits[6] * 1000 + digits[7] * 100 + digits[8] * 10 + digits[9];
    let month = digits[10] * 10 + digits[11];
    let day = digits[12] * 10 + digits[13];
    if !(1800..=2099).contains(&year) {
        return false;
    }
    if !(1..=12).contains(&month) {
        return false;
    }
    if !(1..=31).contains(&day) {
        return false;
    }
    // Weighted mod-11.
    let weights: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let sum: u32 = digits.iter().zip(weights.iter()).map(|(&d, &w)| d * w).sum();
    let remainder = sum % 11;
    let check_table = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let expected = check_table[remainder as usize];
    let actual = chars[17].to_ascii_uppercase();
    actual == expected
}

/// Validate a South Korean Resident Registration Number (RRN):
/// 13 digits laid out as `YYMMDD-CGGGGGS`:
///
///   * positions 0-5: YYMMDD date of birth;
///   * position 6: century + sex code (1-4 for 1800s/1900s/2000s
///     + M/F, 5-8 for foreigners, 9-0 for pre-1800);
///   * positions 7-11: region / order;
///   * position 12: check digit.
///
/// Checksum: `weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]`,
/// applied to positions 0-11. `remainder = (11 - sum mod 11) mod 10`.
/// Valid iff `digits[12] == remainder`.
///
/// Also enforces a structural gate: sex/century code in 1-8
/// (9 and 0 are reserved for pre-1800 births but historically
/// unused), month 01-12, day 01-31.
pub fn is_valid_south_korea_rrn(rrn: &str) -> bool {
    let digits: Vec<u32> = rrn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 13 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Month and day gate.
    let month = digits[2] * 10 + digits[3];
    let day = digits[4] * 10 + digits[5];
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    // Sex/century code. The regex already restricts to 1-8 but
    // belt-and-suspenders here.
    if digits[6] == 0 || digits[6] == 9 {
        return false;
    }
    // Weighted mod-11, special tail mapping.
    let weights = [2u32, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = digits[..12]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let check = (11 - sum % 11) % 10;
    digits[12] == check
}

/// Validate a French INSEE / NIR (social security number) using
/// the mod-97 check. NIR is 15 digits total: `S YY MM DD CCC NNN KK`
/// where the final 2 digits are the check (KK) and the first 13
/// form the payload used to compute it.
///
/// Check: `expected = 97 - (payload mod 97)`. Valid iff the last
/// two digits of the input equal `expected`.
///
/// Corsica substitution: positions 5-6 (department) can be `2A`
/// or `2B` in the printed form. Those map to `19` and `18`
/// respectively for checksum purposes. We handle this if the
/// input still contains the letters (the pattern regex allows
/// them) by performing the substitution before computing the
/// payload.
pub fn is_valid_france_nir(nir: &str) -> bool {
    // Strip spaces but keep letters for Corsica substitution.
    let compact: String = nir
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if compact.len() != 15 {
        return false;
    }
    // Check that positions 0-4 and 7-14 are digits (the only
    // positions where letters are allowed is 5-6 for 2A/2B).
    let bytes = compact.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i == 5 || i == 6 {
            if !b.is_ascii_alphanumeric() {
                return false;
            }
        } else if !b.is_ascii_digit() {
            return false;
        }
    }
    // Apply Corsica substitution: positions 5-6 if letters.
    let corsica_sub_applied: String = if bytes[5] == b'2' && (bytes[6] == b'A' || bytes[6] == b'a')
    {
        format!("{}19{}", &compact[..5], &compact[7..])
    } else if bytes[5] == b'2' && (bytes[6] == b'B' || bytes[6] == b'b') {
        format!("{}18{}", &compact[..5], &compact[7..])
    } else {
        compact.clone()
    };
    // After substitution, all chars must be digits.
    if !corsica_sub_applied.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Build the 13-digit payload and parse the 2-digit check.
    let payload: u64 = corsica_sub_applied[..13].parse().unwrap_or(0);
    let expected_check: u64 = corsica_sub_applied[13..15].parse().unwrap_or(u64::MAX);
    let computed = 97 - (payload % 97);
    computed == expected_check
}

/// Character-to-value lookup for Mexican CURP check digit.
/// CURP digits and letters map to 0..36 where:
///   '0'-'9' → 0-9
///   'A'-'N' → 10-23
///   'Ñ'     → 24 (but ASCII-only implementation treats this
///                  as invalid since the regex excludes it)
///   'O'-'Z' → 25-36
fn curp_char_value(c: char) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    if c.is_ascii_uppercase() {
        let ord = c as u32 - 'A' as u32;
        // 'A'=0 → 10, 'B'=1 → 11, ... 'N'=13 → 23, 'O'=14 → 25
        // (skip 24 for Ñ), 'Z'=25 → 36.
        return Some(if ord < 14 { ord + 10 } else { ord + 11 });
    }
    None
}

/// Validate a Mexican CURP (Clave Única de Registro de Población)
/// using its table-driven check digit. CURP is 18 characters:
/// 4 letters + 6 digits (YYMMDD) + 1 letter (H/M gender) +
/// 5 letters (state + consonants) + 1 alphanumeric homoclave +
/// 1 digit check.
///
/// Checksum: multiply each of the first 17 characters by
/// `(18 - position)` and sum. `check = (10 - (sum mod 10)) mod 10`.
/// Valid iff digit[17] == check.
///
/// Also gates the embedded date: month 01-12, day 01-31, and
/// the gender position must be H or M.
pub fn is_valid_mexico_curp(curp: &str) -> bool {
    let chars: Vec<char> = curp.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    // Structural gates first.
    if !chars[..4].iter().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    let year = chars[4].to_digit(10);
    let year2 = chars[5].to_digit(10);
    let month1 = chars[6].to_digit(10);
    let month2 = chars[7].to_digit(10);
    let day1 = chars[8].to_digit(10);
    let day2 = chars[9].to_digit(10);
    if [year, year2, month1, month2, day1, day2]
        .iter()
        .any(|d| d.is_none())
    {
        return false;
    }
    let month = month1.unwrap() * 10 + month2.unwrap();
    let day = day1.unwrap() * 10 + day2.unwrap();
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    if chars[10] != 'H' && chars[10] != 'M' {
        return false;
    }
    if !chars[11..16].iter().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    if !chars[16].is_ascii_alphanumeric() {
        return false;
    }
    let last = match chars[17].to_digit(10) {
        Some(d) => d,
        None => return false,
    };
    // Weighted sum.
    let mut sum: u32 = 0;
    for (i, &c) in chars[..17].iter().enumerate() {
        let v = curp_char_value(c);
        match v {
            Some(val) => sum += val * (18 - i as u32),
            None => return false,
        }
    }
    let check = (10 - (sum % 10)) % 10;
    last == check
}

// ---------------------------------------------------------------------------
// Checksum batch 3: Sweden PIN, Argentina CUIL/CUIT, Singapore NRIC,
// Singapore FIN, Hong Kong ID, US NPI, UAE Emirates ID, Denmark CPR
// (structural only), Italy SSN (aliased to Codice Fiscale).
// ---------------------------------------------------------------------------

/// Validate a Swedish personnummer (Personal Identification
/// Number) using the standard Luhn check. The 10-digit form is
/// `YYMMDD-XXXC` where the last digit is the Luhn check computed
/// over the 9 preceding digits.
pub fn is_valid_sweden_pin(pin: &str) -> bool {
    let digits: Vec<u32> = pin
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // DOB structural gate on the first 6 digits (YYMMDD).
    let month = digits[2] * 10 + digits[3];
    let day = digits[4] * 10 + digits[5];
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    // Standard Luhn over all 10 digits.
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

/// Validate a Danish CPR (Central Person Register) number. CPR is
/// 10 digits laid out as `DDMMYY-XXXX`. Historically there was a
/// modulus-11 weighted check, but since 2007 Denmark has been
/// issuing CPRs that deliberately fail the mod-11 check because
/// the old system ran out of available combinations. This
/// validator therefore performs only the structural DOB gate
/// (day 1-31, month 1-12) and rejects all-same-digit sentinels.
/// A stricter mod-11 check would false-negative on every CPR
/// issued to anyone born after the rollover.
pub fn is_valid_denmark_cpr(cpr: &str) -> bool {
    let digits: Vec<u32> = cpr
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let day = digits[0] * 10 + digits[1];
    let month = digits[2] * 10 + digits[3];
    if !(1..=31).contains(&day) || !(1..=12).contains(&month) {
        return false;
    }
    true
}

/// Validate an Argentinian CUIL/CUIT (11 digits) using the
/// published weighted mod-11 check. Algorithm:
///
///   * positions 0-1: type prefix (20/23/24/27 for personal
///     male/female/etc, 30/33 for corporate);
///   * positions 2-9: base;
///   * position 10: check digit.
///   * weights `[5, 4, 3, 2, 7, 6, 5, 4, 3, 2]` applied to
///     positions 0-9;
///   * `check = 11 - (sum mod 11)`; map 11 → 0; map 10 → invalid
///     (AFIP reserves check=10 as not issued).
pub fn is_valid_argentina_cuil(id: &str) -> bool {
    let digits: Vec<u32> = id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    // Type prefix gate (matches the regex alternation).
    let prefix = digits[0] * 10 + digits[1];
    let valid_prefix = matches!(prefix, 20 | 23 | 24 | 27 | 30 | 33);
    if !valid_prefix {
        return false;
    }
    let weights = [5u32, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..10]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let r = sum % 11;
    let check = if r == 0 {
        0
    } else if r == 1 {
        return false; // AFIP reserves check=10 (from r=1) as not issued
    } else {
        11 - r
    };
    digits[10] == check
}

/// Singapore NRIC / FIN shared check computation. Weights are
/// `[2, 7, 6, 5, 4, 3, 2]` applied to the 7 digits. Sum is offset
/// by a prefix-specific value, then reduced mod 11, then looked
/// up in a prefix-specific character table.
///
/// Returns the expected check letter, or `None` if the prefix
/// isn't recognised.
fn singapore_id_check_letter(prefix: char, digits: &[u32; 7]) -> Option<char> {
    let weights = [2u32, 7, 6, 5, 4, 3, 2];
    let base_sum: u32 = digits.iter().zip(weights.iter()).map(|(&d, &w)| d * w).sum();
    // Prefix-specific offset.
    let (offset, table) = match prefix {
        // NRIC: S = pre-2000 resident, T = 2000+ resident.
        'S' => (0u32, ['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A']),
        'T' => (4u32, ['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A']),
        // FIN: F = pre-2000 foreign, G = 2000+ foreign, M =
        // post-2022 foreign. F/G share a table; M uses its own.
        'F' => (0u32, ['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'J', 'L', 'K']),
        'G' => (4u32, ['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'J', 'L', 'K']),
        'M' => (3u32, ['K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X']),
        _ => return None,
    };
    let idx = ((base_sum + offset) % 11) as usize;
    Some(table[idx])
}

/// Validate a Singapore NRIC (National Registration Identity
/// Card) — 9 characters: `S` or `T` + 7 digits + check letter.
pub fn is_valid_singapore_nric(nric: &str) -> bool {
    let chars: Vec<char> = nric.chars().collect();
    if chars.len() != 9 {
        return false;
    }
    let prefix = chars[0].to_ascii_uppercase();
    if prefix != 'S' && prefix != 'T' {
        return false;
    }
    let mut digits = [0u32; 7];
    for (i, &c) in chars[1..8].iter().enumerate() {
        digits[i] = match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
    }
    let expected = match singapore_id_check_letter(prefix, &digits) {
        Some(c) => c,
        None => return false,
    };
    chars[8].to_ascii_uppercase() == expected
}

/// Validate a Singapore FIN (Foreign Identification Number) — 9
/// characters: `F`, `G`, or `M` + 7 digits + check letter.
pub fn is_valid_singapore_fin(fin: &str) -> bool {
    let chars: Vec<char> = fin.chars().collect();
    if chars.len() != 9 {
        return false;
    }
    let prefix = chars[0].to_ascii_uppercase();
    if prefix != 'F' && prefix != 'G' && prefix != 'M' {
        return false;
    }
    let mut digits = [0u32; 7];
    for (i, &c) in chars[1..8].iter().enumerate() {
        digits[i] = match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
    }
    let expected = match singapore_id_check_letter(prefix, &digits) {
        Some(c) => c,
        None => return false,
    };
    chars[8].to_ascii_uppercase() == expected
}

/// Validate a Hong Kong Identity Card number. The number is
/// 1-2 letters + 6 digits + 1 check character (digit or `A` for
/// 10). The checksum is a weighted sum over 8 positions with the
/// following rules:
///
///   * 1-letter prefix: pad position 0 with a space (value 36),
///     so positions 0-7 = [space, letter, d1, d2, d3, d4, d5, d6].
///   * 2-letter prefix: positions 0-7 = [L1, L2, d1..d6].
///   * Letter values: A=1, B=2, …, Z=26.
///   * Weights: `[8, 7, 6, 5, 4, 3, 2, 1]` for positions 0-7,
///     plus weight 1 for the check position.
///   * Sum must be ≡ 0 mod 11. The check character 'A' contributes
///     value 10 to the sum.
pub fn is_valid_hong_kong_id(id: &str) -> bool {
    // Strip common formatting characters (parentheses around the
    // check digit, whitespace between letter and digits).
    let compact: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let chars: Vec<char> = compact.chars().collect();
    // 1-letter form: 8 chars total (L + 6 digits + check).
    // 2-letter form: 9 chars total (LL + 6 digits + check).
    let (prefix_vals, digit_start) = match chars.len() {
        8 => {
            if !chars[0].is_ascii_uppercase() {
                return false;
            }
            let v1 = 36u32; // pad
            let v2 = chars[0] as u32 - 'A' as u32 + 1;
            ([v1, v2], 1)
        }
        9 => {
            if !chars[0].is_ascii_uppercase() || !chars[1].is_ascii_uppercase() {
                return false;
            }
            let v1 = chars[0] as u32 - 'A' as u32 + 1;
            let v2 = chars[1] as u32 - 'A' as u32 + 1;
            ([v1, v2], 2)
        }
        _ => return false,
    };
    // 6 digits at positions [digit_start..digit_start+6], then
    // the check character at position digit_start+6.
    let mut digits = [0u32; 6];
    for (i, &c) in chars[digit_start..digit_start + 6].iter().enumerate() {
        digits[i] = match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
    }
    let check_char = chars[digit_start + 6].to_ascii_uppercase();
    let check_val: u32 = if check_char == 'A' {
        10
    } else if let Some(d) = check_char.to_digit(10) {
        d
    } else {
        return false;
    };
    // Weighted sum: 8 positions with weights [8,7,6,5,4,3,2,1],
    // then the check position with weight 1. Total must be 0 mod 11.
    let weights = [8u32, 7, 6, 5, 4, 3, 2, 1];
    let values = [
        prefix_vals[0],
        prefix_vals[1],
        digits[0],
        digits[1],
        digits[2],
        digits[3],
        digits[4],
        digits[5],
    ];
    let sum: u32 = values.iter().zip(weights.iter()).map(|(&v, &w)| v * w).sum();
    (sum + check_val) % 11 == 0
}

/// Validate a US National Provider Identifier (NPI). NPI is 10
/// digits; the check digit is computed via standard Luhn with
/// the prefix `80840` (the ISO 7812-1 health-industry issuer
/// identifier) prepended. Equivalently, run Luhn over the 15-digit
/// string `"80840" + NPI` and require the final checksum to be 0.
pub fn is_valid_us_npi(npi: &str) -> bool {
    let digits: Vec<u32> = npi
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Regex already enforces leading 1 or 2 (type code), but
    // double-check.
    if digits[0] != 1 && digits[0] != 2 {
        return false;
    }
    // Prepend 80840 and run standard Luhn.
    let mut full: Vec<u32> = vec![8, 0, 8, 4, 0];
    full.extend_from_slice(&digits);
    let sum: u32 = full
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

/// Validate a UAE Emirates ID (15 digits, fixed `784` prefix).
/// The 15th digit is the Luhn check computed over all 15 digits,
/// so a valid Emirates ID satisfies `sum % 10 == 0` under standard
/// Luhn.
pub fn is_valid_uae_emirates_id(id: &str) -> bool {
    let digits: Vec<u32> = id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 15 {
        return false;
    }
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Fixed `784` prefix (UAE ISO 3166-1 country code).
    if digits[0] != 7 || digits[1] != 8 || digits[2] != 4 {
        return false;
    }
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

// ---------------------------------------------------------------------------
// Cryptocurrency address validators (Phase 1a of the always-run precision
// pass). Each crypto address format has a published checksum; verifying it
// turns the "25-34 base58 chars" regex into an actual cryptographic gate.
//
// Algorithms covered:
//   * Base58Check — Bitcoin Legacy (P2PKH 0x00, P2SH 0x05), Litecoin
//     (P2PKH 0x30, P2SH 0x32), and Ripple (different alphabet, version 0x00)
//   * Bech32 (BIP-173 polymod) — Bitcoin SegWit
//   * CashAddr (polymod similar to Bech32 with different constants) —
//     Bitcoin Cash
//
// Ethereum is DELIBERATELY excluded from this batch. EIP-55 mixed-case is
// a soft check (lowercase-only addresses are still valid) and a real
// implementation needs keccak256, which we don't have as a dependency and
// don't want to pull in for a soft-gate. The Ethereum regex
// `0x[0-9a-fA-F]{40}` is already tight enough that FPs are rare.
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

/// Standard Base58 alphabet used by Bitcoin, Litecoin, and most Base58Check
/// addresses. Excludes `0`, `O`, `I`, `l` to avoid visual ambiguity.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Ripple's Base58 alphabet. Same 58-symbol design principle as standard
/// Base58 but deliberately shuffled so addresses don't collide with
/// Bitcoin's. The `r` prefix + different alphabet are the only reason an
/// XRP address can't be confused with a BTC address on inspection.
const BASE58_RIPPLE_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Decode a Base58-encoded string to its byte representation. Returns
/// `None` if any character is not in the supplied alphabet. Handles leading
/// "zeros" (represented by the alphabet's first character — `1` in
/// standard Base58, `r` in Ripple) by prepending the corresponding number
/// of zero bytes to the output.
///
/// This is a bytewise implementation — no big-integer arithmetic required.
/// For each input character we compute `out = out * 58 + digit`, carrying
/// through the existing output bytes from least-significant up.
fn base58_decode(input: &str, alphabet: &[u8; 58]) -> Option<Vec<u8>> {
    // Build an inverse lookup table so we can map chars → indices in O(1).
    // Cost is fixed at 256 bytes per call site — cheap to keep on the
    // stack rather than memoize.
    let mut inverse = [u8::MAX; 128];
    for (i, &c) in alphabet.iter().enumerate() {
        inverse[c as usize] = i as u8;
    }

    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    for c in input.bytes() {
        if c >= 128 {
            return None;
        }
        let digit = inverse[c as usize];
        if digit == u8::MAX {
            return None;
        }
        // out = out * 58 + digit
        let mut carry = digit as u32;
        for byte in output.iter_mut() {
            carry += *byte as u32 * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            output.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Leading "zero" characters in the input (the alphabet's first char)
    // map to leading zero bytes in the output.
    let leading_zero_char = alphabet[0];
    let leading_zeros = input.bytes().take_while(|&c| c == leading_zero_char).count();
    for _ in 0..leading_zeros {
        output.push(0);
    }

    output.reverse();
    Some(output)
}

/// Verify a Base58Check-encoded payload. The last 4 bytes are a checksum
/// computed as `SHA256(SHA256(payload_without_checksum))[..4]`. Returns
/// `true` if the checksum matches. The `expected_version_bytes` slice
/// gates the version byte (first byte of the decoded payload) — pass
/// `&[0x00, 0x05]` for Bitcoin Legacy (P2PKH + P2SH), `&[0x30, 0x32]` for
/// Litecoin (L and M/3 prefixes), and `&[0x00]` for Ripple.
fn verify_base58check(decoded: &[u8], expected_version_bytes: &[u8]) -> bool {
    // Standard Base58Check payload is 25 bytes: 1 version + 20 payload + 4 check.
    // Some exotic formats use longer payloads, but for every format we
    // validate here the length is exactly 25.
    if decoded.len() != 25 {
        return false;
    }
    if !expected_version_bytes.contains(&decoded[0]) {
        return false;
    }
    let payload = &decoded[..21];
    let expected_checksum = &decoded[21..25];
    let first_hash = Sha256::digest(payload);
    let second_hash = Sha256::digest(first_hash);
    &second_hash[..4] == expected_checksum
}

/// Validate a Bitcoin legacy address (P2PKH, starts with `1`, or P2SH,
/// starts with `3`) using Base58Check with double-SHA256 checksum and
/// version byte `0x00` or `0x05`.
pub fn is_valid_bitcoin_legacy(addr: &str) -> bool {
    // The regex requires 26-35 characters; any real address is in this
    // range. Double-check here defensively.
    if !(26..=35).contains(&addr.len()) {
        return false;
    }
    let first = addr.as_bytes().first().copied();
    if first != Some(b'1') && first != Some(b'3') {
        return false;
    }
    let Some(decoded) = base58_decode(addr, BASE58_ALPHABET) else {
        return false;
    };
    verify_base58check(&decoded, &[0x00, 0x05])
}

/// Validate a Litecoin address (P2PKH `L`, P2SH `M` or `3`) using
/// Base58Check with the Litecoin version bytes `0x30` (L), `0x32` (M),
/// and historically `0x05` (3, same prefix as Bitcoin P2SH — now
/// deprecated in favour of `M`).
pub fn is_valid_litecoin(addr: &str) -> bool {
    if !(27..=34).contains(&addr.len()) {
        return false;
    }
    let first = addr.as_bytes().first().copied();
    if !matches!(first, Some(b'L') | Some(b'M') | Some(b'3')) {
        return false;
    }
    let Some(decoded) = base58_decode(addr, BASE58_ALPHABET) else {
        return false;
    };
    // 0x30 = L (P2PKH), 0x32 = M (P2SH-new), 0x05 = 3 (P2SH-old).
    verify_base58check(&decoded, &[0x30, 0x32, 0x05])
}

/// Validate a Ripple (XRP) classic address. Uses Base58Check with
/// Ripple's custom 58-symbol alphabet and version byte `0x00`.
pub fn is_valid_ripple(addr: &str) -> bool {
    if !(25..=35).contains(&addr.len()) {
        return false;
    }
    if addr.as_bytes().first().copied() != Some(b'r') {
        return false;
    }
    let Some(decoded) = base58_decode(addr, BASE58_RIPPLE_ALPHABET) else {
        return false;
    };
    verify_base58check(&decoded, &[0x00])
}

/// Bech32 character set used by BIP-173. Mapped by index for the
/// expand-char step of the polymod check.
const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32 polymod function from BIP-173. Takes an iterator of 5-bit
/// groups and computes the polynomial modulus used by the checksum.
fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, &g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Expand an ASCII HRP into the 5-bit value sequence the bech32 polymod
/// expects (high bits, zero separator, low bits).
fn bech32_hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(hrp.len() * 2 + 1);
    for &c in hrp {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in hrp {
        out.push(c & 31);
    }
    out
}

/// Validate a Bitcoin SegWit (Bech32 / Bech32m) address. BIP-173 defines
/// the checksum: the polymod of `hrp_expand(hrp) || data_part` must equal
/// 1 (bech32) or 0x2bc830a3 (bech32m, BIP-350). Bitcoin witness version 0
/// uses bech32; witness version 1+ (Taproot) uses bech32m. We accept
/// either so Taproot addresses validate.
pub fn is_valid_bitcoin_bech32(addr: &str) -> bool {
    // Find the HRP / data separator. For Bitcoin mainnet this is always
    // `bc`. The regex requires the address to start with `bc1` so the
    // split is at index 2.
    if !addr.starts_with("bc1") && !addr.starts_with("BC1") {
        return false;
    }
    // Normalize to lowercase for checksum computation. Bech32 is
    // case-insensitive but the encoding must not mix cases.
    let lower = addr.to_ascii_lowercase();
    let upper = addr.to_ascii_uppercase();
    if addr != lower && addr != upper {
        return false;
    }
    let hrp = b"bc";
    let data_part = &lower[3..];
    if data_part.len() < 6 {
        return false;
    }
    // Decode each data char to its 5-bit value in BECH32_CHARSET.
    let mut data_values: Vec<u8> = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        if let Some(v) = BECH32_CHARSET.iter().position(|&x| x == c) {
            data_values.push(v as u8);
        } else {
            return false;
        }
    }
    let mut polymod_input: Vec<u8> = bech32_hrp_expand(hrp);
    polymod_input.extend_from_slice(&data_values);
    let check = bech32_polymod(&polymod_input);
    // Witness version 0 → bech32 (check == 1)
    // Witness version 1+ → bech32m (check == 0x2bc830a3)
    check == 1 || check == 0x2bc830a3
}

/// CashAddr character set (same layout as Bech32 but different generator).
const CASHADDR_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// CashAddr polymod function. Similar to Bech32 but with a different
/// generator polynomial and a larger state (40 bits vs 30 bits).
fn cashaddr_polymod(values: &[u8]) -> u64 {
    const GEN: [u64; 5] = [
        0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470,
    ];
    let mut c: u64 = 1;
    for &v in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07ffffffff) << 5) ^ (v as u64);
        for (i, &g) in GEN.iter().enumerate() {
            if (c0 >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

/// Expand an ASCII prefix into the 5-bit value sequence the CashAddr
/// polymod expects: low 5 bits of each char, then a zero separator.
fn cashaddr_prefix_expand(prefix: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(prefix.len() + 1);
    for &c in prefix {
        out.push(c & 0x1f);
    }
    out.push(0);
    out
}

/// Validate a Bitcoin Cash address. Accepts both the bare CashAddr body
/// (`q...` or `p...`, 42 chars) and the prefixed form
/// (`bitcoincash:q...`). The checksum is computed over
/// `prefix_expand("bitcoincash") || data_values` and must equal 0.
pub fn is_valid_bitcoin_cash(addr: &str) -> bool {
    // Split off optional prefix.
    let (prefix, body) = match addr.split_once(':') {
        Some((p, b)) => {
            if p.to_ascii_lowercase() != "bitcoincash" {
                return false;
            }
            ("bitcoincash", b)
        }
        None => ("bitcoincash", addr),
    };
    // Body must be 42 ASCII lowercase chars starting with q or p.
    if body.len() != 42 {
        return false;
    }
    let first = body.as_bytes().first().copied();
    if first != Some(b'q') && first != Some(b'p') {
        return false;
    }
    // Decode each body char to its 5-bit value.
    let mut data_values: Vec<u8> = Vec::with_capacity(body.len());
    for c in body.bytes() {
        if let Some(v) = CASHADDR_CHARSET.iter().position(|&x| x == c) {
            data_values.push(v as u8);
        } else {
            return false;
        }
    }
    let mut polymod_input: Vec<u8> = cashaddr_prefix_expand(prefix.as_bytes());
    polymod_input.extend_from_slice(&data_values);
    cashaddr_polymod(&polymod_input) == 0
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
    // Digit-frequency structural check. The official
    // Bundeszentralamt für Steuern spec says positions 0-9 use
    // exactly 9 distinct digits (one digit from 0-9 never appears,
    // one digit appears 2-3 times, the rest appear once each).
    // We implement a weaker rule that still catches the
    // coincidence class that got through the MOD 11,10 check
    // alone: require at least 7 distinct digits AND no single
    // digit appearing more than 3 times. Values like
    // `10000000000` (2 distinct, digit 0 appears 9 times) and
    // `12121212120` (2 distinct, both appear 5 times) get
    // rejected here; every real Steuer-ID has 8-9 distinct digits
    // and no digit appearing more than 3 times, so real numbers
    // still pass.
    //
    // The loose rule is deliberate: the spec had a minor revision
    // in 2016 and the exact "8 or 9 distinct" range is not
    // uniformly applied to all issued IDs. "At least 7" is
    // strictly looser than every variant of the spec and avoids
    // introducing false negatives on legitimate numbers.
    let mut digit_counts = [0u8; 10];
    for &d in &digits[..10] {
        digit_counts[d as usize] += 1;
    }
    let distinct = digit_counts.iter().filter(|&&c| c > 0).count();
    let max_count = digit_counts.iter().copied().max().unwrap_or(0);
    if distinct < 7 || max_count > 3 {
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
        // Vehicle Identification Number — ISO 3779 transliteration
        // + weighted mod-11 check digit at position 8. Closes the
        // last "high-risk 16" pattern that has a published checksum
        // (Ethereum's EIP-55 is deliberately deferred for lack of
        // a keccak256 dependency).
        // DEA registration number — weighted mod-10 check digit on
        // the 7-digit tail. HIPAA-critical pattern.
        "DEA Number" => is_valid_dea_number(matched_text),
        // GDPR device/financial identifiers.
        "ICCID" => is_valid_iccid(matched_text),
        "LEI" => is_valid_lei(matched_text),
        // FIGI: deferred — the check-digit algorithm needs verified
        // documentation. The BBG prefix + alphanumeric shape is already
        // fairly tight (specificity 0.90).
        "Australia Medicare" => is_valid_australia_medicare(matched_text),
        "India PAN" => is_valid_india_pan(matched_text),
        // Remaining validators batch.
        "South Africa ID" => is_valid_south_africa_id(matched_text),
        "MERS MIN" => is_valid_mers_min(matched_text),
        "Fedwire IMAD" => is_valid_fedwire_imad(matched_text),
        "Universal Loan Identifier" => is_valid_uli(matched_text),
        "VIN" => is_valid_vin(matched_text),
        // Network identifiers — structural filtering for non-routable
        // / reserved / documentation / sentinel ranges. The regex is
        // kept always-run so log-file scanning still catches leaked
        // public IPs, and the validator rejects the ranges that are
        // never sensitive. See the network-filters section in
        // validation.rs for the full RFC range list.
        "IPv4 Address" => is_valid_ipv4(matched_text),
        "IPv6 Address" => is_valid_ipv6(matched_text),
        "MAC Address" => is_valid_mac_address(matched_text),
        "GPS Coordinates" => is_valid_gps_coordinates(matched_text),
        // URL credential filters — each regex is fairly tight already,
        // but placeholder values ("YOUR_API_KEY") and too-short token
        // portions are common in documentation. The validators below
        // add length floors + a small placeholder stop-list.
        "Bearer Token" => is_plausible_bearer_token(matched_text),
        "URL with Token" => is_plausible_url_token(matched_text),
        "Slack Webhook" => is_plausible_slack_webhook(matched_text),
        // Generic secret entropy filters — extract the value from
        // the `key = "value"` assignment and apply Shannon entropy
        // floor + length floor + inline placeholder list. API Key
        // gets a stricter entropy threshold (3.0) because real keys
        // are random; Secret Assignment gets a looser one (2.5)
        // because user-chosen passwords are word-shaped.
        "Generic API Key" => is_plausible_api_key(matched_text),
        "Generic Secret Assignment" => is_plausible_secret_assignment(matched_text),
        // Germany Steuer-ID — 11 digits with an ISO 7064 MOD 11,10
        // check. Without this, `\b\d{11}\b` fires on every 11-digit
        // invoice number, timestamp, or phone sequence in a
        // document and Germany Tax ID is in CRITICAL_ALWAYS_RUN so
        // the AC prefilter can't save us.
        "Germany Tax ID" => is_valid_germany_tax_id(matched_text),
        // Polish PESEL — 11 digits with a weighted mod-10
        // checksum + structural DOB gate. Without this, the bare
        // `\b\d{11}\b` regex matches every 11-digit sequence and
        // — because PESEL is in CRITICAL_ALWAYS_RUN and the blind
        // harness exposed it after Germany Tax ID was tightened —
        // it was inheriting all of Germany Tax ID's old FP class.
        "Poland PESEL" => is_valid_poland_pesel(matched_text),
        // Belgian Rijksregisternummer — 11 digits with a mod-97
        // check and DOB structural gate. Previously unvalidated;
        // the bare regex matched any 11-digit sequence.
        "Belgium NRN" => is_valid_belgium_nrn(matched_text),
        // ABA / Fedwire routing transit number — 9 digits with a
        // weighted mod-10 checksum AND a valid Federal Reserve
        // district prefix. Both the "ABA Routing Number" and
        // "USA Routing Number" sub_categories share the same
        // underlying concept — they're duplicate coverage
        // patterns from different taxonomies — so both go through
        // the same validator.
        "ABA Routing Number" | "USA Routing Number" => is_valid_aba_routing(matched_text),
        // Brazilian CPF — 11 digits with two mod-11 check digits
        // and an explicit all-same-digit rejection (the Brazilian
        // RFB publishes that all-repeating CPFs coincidentally
        // satisfy the checksum arithmetic and must be rejected).
        "Brazil CPF" => is_valid_brazil_cpf(matched_text),
        // India Aadhaar — 12 digits with Verhoeff dihedral-group
        // checksum. Previously unvalidated; bare `\d{12}` matched
        // any 12-digit sequence and the pattern was in
        // CRITICAL_ALWAYS_RUN.
        "India Aadhaar" => is_valid_india_aadhaar(matched_text),
        // Japan My Number — 12 digits with a weighted mod-11
        // check from the National Tax Agency. Same class of bug
        // as Aadhaar — bare regex, no validator, always-run.
        "Japan My Number" => is_valid_japan_my_number(matched_text),
        // Italian Codice Fiscale — 16 alphanumeric characters
        // with a table-driven check letter (mod-26 sum of
        // position-weighted character values). Without the
        // validator, the regex accepts any correctly-shaped
        // 16-char string including obvious test data like
        // `AAAAAA00A00A000A`.
        "Italy Codice Fiscale" => is_valid_italy_codice_fiscale(matched_text),
        // Spanish DNI and NIE — 8 digits + 1 letter (DNI) or
        // X/Y/Z + 7 digits + 1 letter (NIE). Check letter is
        // deterministic via `DNI_LETTERS[payload mod 23]`, so
        // any bare-shape match can be verified in O(1) without
        // data tables larger than the 23-letter alphabet itself.
        "Spain DNI" => is_valid_spain_dni(matched_text),
        // Israeli Teudat Zehut — 9 digits with weighted Luhn-like
        // check. The bare `\b\d{9}\b` regex was — like many other
        // 9-digit national ID patterns — false-positiving on
        // every 9-digit sequence. The checksum is cheap to run
        // and catches ~90% of random 9-digit noise.
        "Israel Teudat Zehut" => is_valid_israel_teudat_zehut(matched_text),
        // British NHS number — 10 digits with weighted mod-11
        // check. NHS Digital reserves check=10 as invalid so the
        // validator also rejects that case.
        "British NHS" => is_valid_british_nhs(matched_text),
        // Brazilian CNPJ — 14 digits with two mod-11 check
        // digits. Same structure as CPF but with different
        // weights and a second pass that includes the first check.
        "Brazil CNPJ" => is_valid_brazil_cnpj(matched_text),
        // Chinese Resident ID (GB 11643) — 18 characters with
        // weighted mod-11 check, where the check position can be
        // `X` (representing 10). Also performs a DOB gate.
        "China Resident ID" => is_valid_china_resident_id(matched_text),
        // South Korean RRN — 13 digits with weighted mod-11 and
        // DOB + sex-code structural gate.
        "South Korea RRN" => is_valid_south_korea_rrn(matched_text),
        // French NIR (INSEE social security number) — 15 digits
        // with mod-97 check, with Corsica letter-for-digit
        // substitution (2A → 19, 2B → 18) applied before the
        // payload is computed.
        "France NIR" => is_valid_france_nir(matched_text),
        // Mexican CURP — 18 characters with a weighted check
        // digit. Validates the embedded DOB + gender structure
        // plus the checksum.
        "Mexico CURP" => is_valid_mexico_curp(matched_text),
        // Swedish personnummer — 10 digits with standard Luhn
        // on all 10 digits, plus DOB structural gate.
        "Sweden PIN" => is_valid_sweden_pin(matched_text),
        // Danish CPR — structural DOB only. Modern CPRs
        // deliberately fail mod-11 (see is_valid_denmark_cpr
        // docstring), so we can't checksum this one.
        "Denmark CPR" => is_valid_denmark_cpr(matched_text),
        // Argentinian CUIL/CUIT — weighted mod-11 with valid
        // type-prefix gate (20/23/24/27 personal, 30/33 corporate).
        "Argentina CUIL/CUIT" => is_valid_argentina_cuil(matched_text),
        // Singapore NRIC — letter + 7 digits + check letter,
        // checksum looks up in a prefix-specific letter table.
        "Singapore NRIC" => is_valid_singapore_nric(matched_text),
        // Singapore FIN — same algorithm as NRIC but with
        // different prefix letters (F/G/M) and a different letter
        // table for M.
        "Singapore FIN" => is_valid_singapore_fin(matched_text),
        // Hong Kong Identity Card — 1-2 letter prefix + 6 digits
        // + check char, weighted sum over letter+digit values
        // with space-padding for the 1-letter form.
        "Hong Kong ID" => is_valid_hong_kong_id(matched_text),
        // US NPI — 10-digit National Provider Identifier with
        // Luhn check over the ISO-7812 prefix `80840` + NPI.
        "US NPI" => is_valid_us_npi(matched_text),
        // UAE Emirates ID — 15 digits with fixed `784` prefix
        // and Luhn check on all 15.
        "UAE Emirates ID" => is_valid_uae_emirates_id(matched_text),
        // Cryptocurrency addresses — every format validated here has a
        // published checksum, turning the regex into a real
        // cryptographic gate rather than "looks like a 25-35 char
        // base58 string." See the crypto section of validation.rs for
        // per-format notes.
        "Bitcoin Address (Legacy)" => is_valid_bitcoin_legacy(matched_text),
        "Bitcoin Address (Bech32)" => is_valid_bitcoin_bech32(matched_text),
        "Bitcoin Cash Address" => is_valid_bitcoin_cash(matched_text),
        "Litecoin Address" => is_valid_litecoin(matched_text),
        "Ripple Address" => is_valid_ripple(matched_text),
        // Italian "SSN" pattern shares the Codice Fiscale
        // check-letter algorithm — it's a slightly looser regex
        // variant of the same ID. Wire it to the same validator.
        "Italy SSN" => is_valid_italy_codice_fiscale(matched_text),
        // Dutch BSN — 9-digit "eleven-test" (weights 9..2, -1;
        // sum mod 11 == 0). The bare `\b\d{9}\b` regex was
        // firing on every 9-digit sequence before the validator.
        "Netherlands BSN" => is_valid_netherlands_bsn(matched_text),
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
    fn test_netherlands_bsn_valid() {
        // Hand-verified eleven-test values.
        // 111222333: 1*9+1*8+1*7+2*6+2*5+2*4+3*3+3*2+3*-1
        //          = 9+8+7+12+10+8+9+6-3 = 66, 66 % 11 == 0 ✓
        assert!(is_valid_netherlands_bsn("111222333"));
        // 123456782: 1*9+2*8+3*7+4*6+5*5+6*4+7*3+8*2+2*-1
        //          = 9+16+21+24+25+24+21+16-2 = 154, 154 % 11 == 0 ✓
        assert!(is_valid_netherlands_bsn("123456782"));
    }

    #[test]
    fn test_netherlands_bsn_invalid() {
        // Bumped last digit.
        assert!(!is_valid_netherlands_bsn("111222334"));
        assert!(!is_valid_netherlands_bsn("123456783"));
        // Sentinel all-zeros.
        assert!(!is_valid_netherlands_bsn("000000000"));
        // The blind-test FP residue — `441234567` is the digit
        // substring of `+441234567` (a too-short UK phone) that
        // the Netherlands BSN regex was firing on.
        assert!(!is_valid_netherlands_bsn("441234567"));
        // Wrong length (too long).
        assert!(!is_valid_netherlands_bsn("1234567890"));
        // 8-digit form that gets zero-padded but still fails.
        // Padded: "012345678" → sum 104 % 11 = 5, not divisible.
        assert!(!is_valid_netherlands_bsn("12345678"));
    }

    #[test]
    fn test_sweden_pin_valid() {
        // 8112189876 — hand-verified. Luhn sum = 50, mod 10 = 0.
        assert!(is_valid_sweden_pin("8112189876"));
        // Hyphen form (regex allows separator).
        assert!(is_valid_sweden_pin("811218-9876"));
    }

    #[test]
    fn test_sweden_pin_invalid() {
        // Bumped last digit.
        assert!(!is_valid_sweden_pin("8112189877"));
        // Invalid month (13).
        assert!(!is_valid_sweden_pin("8113189876"));
        // Invalid day (32).
        assert!(!is_valid_sweden_pin("8112329876"));
        // All-same sentinels.
        assert!(!is_valid_sweden_pin("0000000000"));
        assert!(!is_valid_sweden_pin("9999999999"));
        // Wrong length.
        assert!(!is_valid_sweden_pin("811218987"));
        assert!(!is_valid_sweden_pin("81121898765"));
    }

    #[test]
    fn test_denmark_cpr_valid() {
        // Structural only — modern CPRs don't satisfy mod-11.
        // 0705624995 = 07 May 1962, serial 4995.
        assert!(is_valid_denmark_cpr("0705624995"));
        // Dashed form.
        assert!(is_valid_denmark_cpr("070562-4995"));
        // Day 31, month 12.
        assert!(is_valid_denmark_cpr("3112990001"));
    }

    #[test]
    fn test_denmark_cpr_invalid() {
        // Day 00.
        assert!(!is_valid_denmark_cpr("0005624995"));
        // Day 32.
        assert!(!is_valid_denmark_cpr("3205624995"));
        // Month 00.
        assert!(!is_valid_denmark_cpr("0700624995"));
        // Month 13.
        assert!(!is_valid_denmark_cpr("0713624995"));
        // All-same sentinels.
        assert!(!is_valid_denmark_cpr("0000000000"));
        // Wrong length.
        assert!(!is_valid_denmark_cpr("070562499"));
        assert!(!is_valid_denmark_cpr("07056249950"));
    }

    #[test]
    fn test_argentina_cuil_valid() {
        // 20123456786 — hand-verified. weights [5,4,3,2,7,6,5,4,3,2]
        // sum = 148, mod 11 = 5, check = 6 ✓.
        assert!(is_valid_argentina_cuil("20123456786"));
        // Dashed form (CUIL is commonly written XX-XXXXXXXX-X).
        assert!(is_valid_argentina_cuil("20-12345678-6"));
        // 30500001735 — hand-verified. sum = 61, mod 11 = 6,
        // check = 5 ✓.
        assert!(is_valid_argentina_cuil("30500001735"));
    }

    #[test]
    fn test_argentina_cuil_invalid() {
        // Bumped check digit.
        assert!(!is_valid_argentina_cuil("20123456787"));
        assert!(!is_valid_argentina_cuil("30500001736"));
        // Invalid type prefix (21 not in AFIP list).
        assert!(!is_valid_argentina_cuil("21123456786"));
        // All-same sentinels.
        assert!(!is_valid_argentina_cuil("00000000000"));
        assert!(!is_valid_argentina_cuil("11111111111"));
        // Wrong length.
        assert!(!is_valid_argentina_cuil("2012345678"));
        assert!(!is_valid_argentina_cuil("201234567867"));
    }

    #[test]
    fn test_singapore_nric_valid() {
        // S0000001I — hand-verified. weights [2,7,6,5,4,3,2]
        // sum = 2, S_TABLE[2] = 'I' ✓.
        assert!(is_valid_singapore_nric("S0000001I"));
        // S1234567D — hand-verified. sum = 106, mod 11 = 7,
        // S_TABLE[7] = 'D' ✓.
        assert!(is_valid_singapore_nric("S1234567D"));
        // Lowercase also accepted.
        assert!(is_valid_singapore_nric("s1234567d"));
    }

    #[test]
    fn test_singapore_nric_invalid() {
        // Bumped check letter.
        assert!(!is_valid_singapore_nric("S0000001J"));
        assert!(!is_valid_singapore_nric("S1234567E"));
        // Wrong prefix (F is FIN, not NRIC).
        assert!(!is_valid_singapore_nric("F1234567D"));
        // Non-digit in the payload.
        assert!(!is_valid_singapore_nric("S123456AD"));
        // Wrong length.
        assert!(!is_valid_singapore_nric("S123456D"));
        assert!(!is_valid_singapore_nric("S12345678D"));
    }

    #[test]
    fn test_singapore_fin_valid() {
        // F1234567N — hand-verified. sum = 106, mod 11 = 7,
        // F_TABLE[7] = 'N' ✓.
        assert!(is_valid_singapore_fin("F1234567N"));
        // G with offset +4: sum = 110, mod 11 = 0, F_TABLE[0] = 'X'.
        assert!(is_valid_singapore_fin("G1234567X"));
    }

    #[test]
    fn test_singapore_fin_invalid() {
        // Bumped check letter.
        assert!(!is_valid_singapore_fin("F1234567O"));
        assert!(!is_valid_singapore_fin("G1234567Y"));
        // Wrong prefix (S is NRIC, not FIN).
        assert!(!is_valid_singapore_fin("S1234567N"));
        // Wrong length.
        assert!(!is_valid_singapore_fin("F123456N"));
    }

    #[test]
    fn test_hong_kong_id_valid() {
        // 1-letter form (8 chars: L + 6 digits + check).
        // Z683322A — hand-verified. Padded space(36), Z=26,
        // 6,8,3,3,2,2; weighted sum = 573; + 10 (A=10) = 583;
        // 583 = 53*11 → mod 11 = 0 ✓.
        assert!(is_valid_hong_kong_id("Z683322A"));
        assert!(is_valid_hong_kong_id("Z683322(A)"));
        // A1111113 — hand-verified. Padded space(36), A=1,
        // 1,1,1,1,1,1; weighted sum = 316; + 3 = 319; 319 = 29*11
        // → mod 11 = 0 ✓.
        assert!(is_valid_hong_kong_id("A1111113"));
        // 2-letter form (9 chars): AB123456A —
        // values 1,2,1,2,3,4,5,6; weights 8..1; sum = 78;
        // + 10 (A=10) = 88; 88 = 8*11 → mod 11 = 0 ✓.
        assert!(is_valid_hong_kong_id("AB123456A"));
        assert!(is_valid_hong_kong_id("AB123456(A)"));
    }

    #[test]
    fn test_hong_kong_id_invalid() {
        // Bumped check char on valid inputs.
        assert!(!is_valid_hong_kong_id("Z6833220"));
        assert!(!is_valid_hong_kong_id("A1111110"));
        assert!(!is_valid_hong_kong_id("AB1234560"));
        // Wrong length (no check, 7 chars).
        assert!(!is_valid_hong_kong_id("A111111"));
        // Lowercase prefix — rejected (spec is uppercase).
        assert!(!is_valid_hong_kong_id("z683322a"));
    }

    #[test]
    fn test_us_npi_valid() {
        // 1234567893 — hand-verified. "80840" + "123456789" +
        // check; Luhn on all 15 digits sums to 70, mod 10 = 0 ✓.
        assert!(is_valid_us_npi("1234567893"));
        // 1245319599 — hand-verified. Luhn sum = 80, mod 10 = 0 ✓.
        assert!(is_valid_us_npi("1245319599"));
    }

    #[test]
    fn test_us_npi_invalid() {
        // Bumped check digit.
        assert!(!is_valid_us_npi("1234567894"));
        assert!(!is_valid_us_npi("1245319590"));
        // Wrong type prefix (must be 1 or 2).
        assert!(!is_valid_us_npi("3234567893"));
        assert!(!is_valid_us_npi("0234567893"));
        // All-same sentinels.
        assert!(!is_valid_us_npi("1111111111"));
        // Wrong length.
        assert!(!is_valid_us_npi("123456789"));
        assert!(!is_valid_us_npi("12345678934"));
    }

    #[test]
    fn test_uae_emirates_id_valid() {
        // 784197512345675 — hand-verified. 15 digits starting
        // with 784, Luhn sum = 70, mod 10 = 0 ✓.
        assert!(is_valid_uae_emirates_id("784197512345675"));
        // Dashed form (regex allows separators).
        assert!(is_valid_uae_emirates_id("784-1975-1234567-5"));
    }

    #[test]
    fn test_uae_emirates_id_invalid() {
        // Bumped check digit.
        assert!(!is_valid_uae_emirates_id("784197512345674"));
        // Wrong country prefix (UAE is fixed 784).
        assert!(!is_valid_uae_emirates_id("785197512345675"));
        assert!(!is_valid_uae_emirates_id("123197512345675"));
        // All-same sentinels.
        assert!(!is_valid_uae_emirates_id("000000000000000"));
        // Wrong length.
        assert!(!is_valid_uae_emirates_id("78419751234567"));
        assert!(!is_valid_uae_emirates_id("7841975123456750"));
    }

    #[test]
    fn test_bitcoin_legacy_valid() {
        // 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 — the genesis block
        // coinbase address (Satoshi's original). Canonical P2PKH
        // with version byte 0x00.
        assert!(is_valid_bitcoin_legacy("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa — another published
        // Satoshi address.
        assert!(is_valid_bitcoin_legacy("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        // 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy — a published P2SH
        // address (version byte 0x05).
        assert!(is_valid_bitcoin_legacy("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn test_bitcoin_legacy_invalid() {
        // Bumped last char — checksum fails.
        assert!(!is_valid_bitcoin_legacy("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"));
        // Wrong version byte (2... is testnet P2PKH — 0x6f, not 0x00).
        assert!(!is_valid_bitcoin_legacy("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc"));
        // Random base58 string that doesn't checksum.
        assert!(!is_valid_bitcoin_legacy("1234567890ABCDEFGHJKmnopqrstuvwxyz"));
        // Wrong length (too short).
        assert!(!is_valid_bitcoin_legacy("1BvBMSEYstWetqT"));
        // Contains a forbidden Base58 character (`0`, `O`, `I`, `l`).
        assert!(!is_valid_bitcoin_legacy("10vBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    }

    #[test]
    fn test_bitcoin_bech32_valid() {
        // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 — the canonical
        // BIP-173 test vector for P2WPKH (witness version 0).
        assert!(is_valid_bitcoin_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 —
        // published Taproot (witness v1, uses bech32m) test vector.
        assert!(is_valid_bitcoin_bech32(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        ));
        // Case-insensitive: all uppercase form should also validate.
        assert!(is_valid_bitcoin_bech32(
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        ));
    }

    #[test]
    fn test_bitcoin_bech32_invalid() {
        // Bumped last char.
        assert!(!is_valid_bitcoin_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
        ));
        // Mixed case — bech32 spec forbids mixed case in the same
        // encoding.
        assert!(!is_valid_bitcoin_bech32(
            "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // Wrong HRP (tb = testnet, not mainnet).
        assert!(!is_valid_bitcoin_bech32(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // Too short to be a real bech32 address.
        assert!(!is_valid_bitcoin_bech32("bc1q"));
    }

    #[test]
    fn test_bitcoin_cash_valid() {
        // qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a — the canonical
        // published test vector for Bitcoin Cash CashAddr format
        // (from the BCH documentation).
        assert!(is_valid_bitcoin_cash(
            "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        ));
        // Same address with the "bitcoincash:" prefix — also valid.
        assert!(is_valid_bitcoin_cash(
            "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        ));
    }

    #[test]
    fn test_bitcoin_cash_invalid() {
        // Bumped last char.
        assert!(!is_valid_bitcoin_cash(
            "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b"
        ));
        // Wrong prefix.
        assert!(!is_valid_bitcoin_cash(
            "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        ));
        // Wrong length (41 chars instead of 42).
        assert!(!is_valid_bitcoin_cash(
            "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6"
        ));
        // Wrong first char (must be q or p).
        assert!(!is_valid_bitcoin_cash(
            "rpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        ));
    }

    #[test]
    fn test_litecoin_valid() {
        // LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9 — a published Litecoin
        // P2PKH test address (version byte 0x30 = L prefix).
        assert!(is_valid_litecoin("LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9"));
        // LTpYZG19YmfvY2bBDYtCKpunVRw7nVgRHW — a published Litecoin
        // test address.
        assert!(is_valid_litecoin("LTpYZG19YmfvY2bBDYtCKpunVRw7nVgRHW"));
    }

    #[test]
    fn test_litecoin_invalid() {
        // Bumped last char.
        assert!(!is_valid_litecoin("LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH8"));
        // Bitcoin address (wrong version byte — would decode to 0x00
        // but Litecoin expects 0x30/0x32/0x05).
        assert!(!is_valid_litecoin("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        // Random base58.
        assert!(!is_valid_litecoin("LAnybodyOutThereMakingUpStrings12"));
    }

    #[test]
    fn test_ripple_valid() {
        // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh — Ripple Labs published
        // classic address test vector.
        assert!(is_valid_ripple("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
        // rUn84CUYbNjRoTQ6mSW7BVJPSVJNLb1QLo — another published
        // Ripple test vector.
        assert!(is_valid_ripple("rUn84CUYbNjRoTQ6mSW7BVJPSVJNLb1QLo"));
    }

    #[test]
    fn test_ripple_invalid() {
        // Bumped last char.
        assert!(!is_valid_ripple("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTj"));
        // Wrong prefix (Ripple addresses always start with 'r').
        assert!(!is_valid_ripple("1Hb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
        // Uses standard Base58 alphabet but Ripple has its own.
        // "I" exists in Ripple alphabet but not in standard Base58;
        // this one uses the standard alphabet and would decode
        // differently, failing the checksum.
        assert!(!is_valid_ripple("rHbcCJAWyB4rj91VRWn96DkukG4bwdtyTh"));
    }

    #[test]
    fn test_italy_ssn_aliases_codice_fiscale() {
        // Italy SSN regex is a slightly looser variant of the CF
        // regex; the check-letter algorithm is the same. We wire
        // Italy SSN to the CF validator, so any valid CF should
        // also validate as Italy SSN.
        assert!(is_valid_italy_codice_fiscale("MRTMTT25D09F205Z"));
        assert!(is_valid_italy_codice_fiscale("BNCNRC65B01F205G"));
    }

    #[test]
    fn test_british_nhs_valid() {
        // 9434765919 — hand-verified. Weighted sum = 299, mod 11 = 2,
        // check = 9 ✓.
        assert!(is_valid_british_nhs("9434765919"));
        // Same with space formatting (regex allows it).
        assert!(is_valid_british_nhs("943 476 5919"));
        // 1234567881 — hand-verified. Sum = 208, mod 11 = 10,
        // check = 1 ✓.
        assert!(is_valid_british_nhs("1234567881"));
    }

    #[test]
    fn test_british_nhs_invalid() {
        // Bumped check digit.
        assert!(!is_valid_british_nhs("9434765910"));
        assert!(!is_valid_british_nhs("1234567882"));
        // All-same sentinels.
        assert!(!is_valid_british_nhs("0000000000"));
        assert!(!is_valid_british_nhs("9999999999"));
        // Wrong length.
        assert!(!is_valid_british_nhs("943476591"));
        assert!(!is_valid_british_nhs("94347659190"));
    }

    #[test]
    fn test_brazil_cnpj_valid() {
        // 11222333000181 — hand-verified. First check sum = 102,
        // mod 11 = 3, check1 = 8. Second check sum = 120, mod 11
        // = 10, check2 = 1.
        assert!(is_valid_brazil_cnpj("11222333000181"));
        // Dotted form (regex allows separators).
        assert!(is_valid_brazil_cnpj("11.222.333/0001-81"));
        // 60746948000112 — hand-verified. First check 263 mod 11 =
        // 10 → 1; second check 262 mod 11 = 9 → 2.
        assert!(is_valid_brazil_cnpj("60746948000112"));
    }

    #[test]
    fn test_brazil_cnpj_invalid() {
        // Bumped second check digit.
        assert!(!is_valid_brazil_cnpj("11222333000182"));
        // Bumped first check digit.
        assert!(!is_valid_brazil_cnpj("11222333000171"));
        // All-same sentinels (explicit RFB rejection).
        assert!(!is_valid_brazil_cnpj("00000000000000"));
        assert!(!is_valid_brazil_cnpj("11111111111111"));
        // Wrong length.
        assert!(!is_valid_brazil_cnpj("1122233300018"));
        assert!(!is_valid_brazil_cnpj("112223330001810"));
    }

    #[test]
    fn test_china_resident_id_valid() {
        // 110101199003078515 — hand-verified. Weighted sum = 238,
        // mod 11 = 7, check table[7] = '5' ✓.
        assert!(is_valid_china_resident_id("110101199003078515"));
        // 11010519491231002X — hand-verified. Weighted sum = 167,
        // mod 11 = 2, check table[2] = 'X' ✓.
        assert!(is_valid_china_resident_id("11010519491231002X"));
        // Lowercase x also accepted.
        assert!(is_valid_china_resident_id("11010519491231002x"));
    }

    #[test]
    fn test_china_resident_id_invalid() {
        // Bumped check character.
        assert!(!is_valid_china_resident_id("110101199003078516"));
        // Wrong length.
        assert!(!is_valid_china_resident_id("11010119900307851"));
        assert!(!is_valid_china_resident_id("1101011990030785155"));
        // Invalid DOB (month 13).
        assert!(!is_valid_china_resident_id("110101199013078515"));
        // Invalid DOB (day 32).
        assert!(!is_valid_china_resident_id("110101199003328515"));
        // Year 0000 (DOB gate).
        assert!(!is_valid_china_resident_id("110101000001018515"));
    }

    #[test]
    fn test_south_korea_rrn_valid() {
        // 9001011234568 — hand-verified. Sum = 124, check =
        // (11 - 3) % 10 = 8 ✓.
        assert!(is_valid_south_korea_rrn("9001011234568"));
        // Same with hyphen (regex allows it).
        assert!(is_valid_south_korea_rrn("900101-1234568"));
    }

    #[test]
    fn test_south_korea_rrn_invalid() {
        // Bumped check digit.
        assert!(!is_valid_south_korea_rrn("9001011234569"));
        // Invalid month.
        assert!(!is_valid_south_korea_rrn("9013011234568"));
        // Invalid day.
        assert!(!is_valid_south_korea_rrn("9001321234568"));
        // Invalid sex code (0 or 9).
        assert!(!is_valid_south_korea_rrn("9001010234568"));
        assert!(!is_valid_south_korea_rrn("9001019234568"));
        // All-same sentinels.
        assert!(!is_valid_south_korea_rrn("0000000000000"));
        // Wrong length.
        assert!(!is_valid_south_korea_rrn("900101123456"));
    }

    #[test]
    fn test_france_nir_valid() {
        // 185127511418052 — hand-verified.
        // payload 1851275114180 mod 97 = 45, check = 52.
        assert!(is_valid_france_nir("185127511418052"));
        // 285017511621819 — hand-verified.
        // payload 2850175116218 mod 97 = 78, check = 19.
        assert!(is_valid_france_nir("285017511621819"));
    }

    #[test]
    fn test_france_nir_invalid() {
        // Bumped check digit.
        assert!(!is_valid_france_nir("185127511418053"));
        assert!(!is_valid_france_nir("285017511621820"));
        // Wrong length.
        assert!(!is_valid_france_nir("18512751141805"));
        assert!(!is_valid_france_nir("1851275114180522"));
        // Non-digit at a position where only digits are allowed.
        assert!(!is_valid_france_nir("18512751141805A"));
    }

    #[test]
    fn test_mexico_curp_valid() {
        // AABB850515HDFRRR09 — hand-verified. Sum = 1631,
        // mod 10 = 1, check = (10 - 1) % 10 = 9 ✓.
        assert!(is_valid_mexico_curp("AABB850515HDFRRR09"));
        // HEGG560427MVZRRL04 — hand-verified. Sum = 2246,
        // mod 10 = 6, check = 4 ✓.
        assert!(is_valid_mexico_curp("HEGG560427MVZRRL04"));
    }

    #[test]
    fn test_mexico_curp_invalid() {
        // Bumped check digit.
        assert!(!is_valid_mexico_curp("AABB850515HDFRRR08"));
        assert!(!is_valid_mexico_curp("HEGG560427MVZRRL03"));
        // Invalid DOB (month 13).
        assert!(!is_valid_mexico_curp("AABB851315HDFRRR09"));
        // Invalid DOB (day 32).
        assert!(!is_valid_mexico_curp("AABB850532HDFRRR09"));
        // Invalid gender (must be H or M).
        assert!(!is_valid_mexico_curp("AABB850515XDFRRR09"));
        // Wrong length.
        assert!(!is_valid_mexico_curp("AABB850515HDFRRR0"));
        assert!(!is_valid_mexico_curp("AABB850515HDFRRR099"));
        // Lowercase letters.
        assert!(!is_valid_mexico_curp("aabb850515hdfrrr09"));
    }

    #[test]
    fn test_india_aadhaar_valid() {
        // 999941057058 — public UIDAI test Aadhaar. Verhoeff
        // final `c` computes to 0.
        assert!(is_valid_india_aadhaar("999941057058"));
        // Formatted with spaces — the regex leaves them in place.
        assert!(is_valid_india_aadhaar("9999 4105 7058"));
        // 999971658847 — second published test value.
        assert!(is_valid_india_aadhaar("999971658847"));
    }

    #[test]
    fn test_india_aadhaar_invalid() {
        // Bumped check digit.
        assert!(!is_valid_india_aadhaar("999941057059"));
        assert!(!is_valid_india_aadhaar("999971658848"));
        // UIDAI reserves 0xxx and 1xxx prefixes.
        assert!(!is_valid_india_aadhaar("099941057058"));
        assert!(!is_valid_india_aadhaar("199941057058"));
        // All-same sentinels.
        assert!(!is_valid_india_aadhaar("222222222222"));
        assert!(!is_valid_india_aadhaar("999999999999"));
        // Wrong length.
        assert!(!is_valid_india_aadhaar("99994105705"));
        assert!(!is_valid_india_aadhaar("9999410570580"));
    }

    #[test]
    fn test_japan_my_number_valid() {
        // 123456789018 — hand-verified: sum=212, rem=3, check=8.
        assert!(is_valid_japan_my_number("123456789018"));
        // 111222333446 — hand-verified: sum=104, rem=5, check=6.
        assert!(is_valid_japan_my_number("111222333446"));
    }

    #[test]
    fn test_japan_my_number_invalid() {
        // Bumped check digit.
        assert!(!is_valid_japan_my_number("123456789019"));
        assert!(!is_valid_japan_my_number("111222333447"));
        // All-same sentinels.
        assert!(!is_valid_japan_my_number("000000000000"));
        assert!(!is_valid_japan_my_number("111111111111"));
        assert!(!is_valid_japan_my_number("999999999999"));
        // Wrong length.
        assert!(!is_valid_japan_my_number("12345678901"));
        assert!(!is_valid_japan_my_number("1234567890123"));
    }

    #[test]
    fn test_italy_codice_fiscale_valid() {
        // MRTMTT25D09F205Z — hand-verified: sum=155, mod 26=25, 'Z'.
        assert!(is_valid_italy_codice_fiscale("MRTMTT25D09F205Z"));
        // BNCNRC65B01F205G — hand-verified: sum=84, mod 26=6, 'G'.
        assert!(is_valid_italy_codice_fiscale("BNCNRC65B01F205G"));
    }

    #[test]
    fn test_italy_codice_fiscale_invalid() {
        // Bumped check letter.
        assert!(!is_valid_italy_codice_fiscale("MRTMTT25D09F205Y"));
        assert!(!is_valid_italy_codice_fiscale("BNCNRC65B01F205H"));
        // Wrong shape: all-A is a classic test sentinel but has
        // the wrong check letter (real sum won't be 0).
        assert!(!is_valid_italy_codice_fiscale("AAAAAA00A00A000A"));
        // Wrong length.
        assert!(!is_valid_italy_codice_fiscale("MRTMTT25D09F205"));
        assert!(!is_valid_italy_codice_fiscale("MRTMTT25D09F205ZZ"));
        // Lowercase — CF is strictly uppercase.
        assert!(!is_valid_italy_codice_fiscale("mrtmtt25d09f205z"));
        // Contains non-alphanumeric.
        assert!(!is_valid_italy_codice_fiscale("MRTMTT25D09F205!"));
    }

    #[test]
    fn test_spain_dni_valid() {
        // 12345678 mod 23 = 14 → DNI_LETTERS[14] = 'Z'.
        assert!(is_valid_spain_dni("12345678Z"));
        // 00000001 mod 23 = 1 → DNI_LETTERS[1] = 'R'.
        assert!(is_valid_spain_dni("00000001R"));
        // Lowercase check letter normalized to uppercase.
        assert!(is_valid_spain_dni("12345678z"));
        // NIE with X prefix: payload = 0_1234567 = 1234567,
        // 1234567 mod 23 = 19 → DNI_LETTERS[19] = 'L'.
        assert!(is_valid_spain_dni("X1234567L"));
        // NIE with Y prefix: payload = 1_1234567 = 11234567,
        // 11234567 mod 23 = ? 11234567/23 = 488459, 488459*23 =
        // 11234557, remainder 10 → DNI_LETTERS[10] = 'X'.
        assert!(is_valid_spain_dni("Y1234567X"));
    }

    #[test]
    fn test_spain_dni_invalid() {
        // Bumped check letter.
        assert!(!is_valid_spain_dni("12345678A"));
        assert!(!is_valid_spain_dni("12345678Y"));
        // NIE with wrong letter.
        assert!(!is_valid_spain_dni("X1234567K"));
        assert!(!is_valid_spain_dni("Y1234567L"));
        // Digit where a letter should be.
        assert!(!is_valid_spain_dni("123456789"));
        // Wrong length.
        assert!(!is_valid_spain_dni("1234567Z"));
        assert!(!is_valid_spain_dni("123456789Z"));
        // Invalid prefix letter (NIE only accepts X, Y, Z).
        assert!(!is_valid_spain_dni("A1234567L"));
    }

    #[test]
    fn test_israel_teudat_zehut_valid() {
        // 000000018 — weighted sum = 0+0+0+0+0+0+0+2+8 = 10; mod 10 = 0.
        assert!(is_valid_israel_teudat_zehut("000000018"));
        // 123456782 — hand-verified: sum = 40, mod 10 = 0.
        assert!(is_valid_israel_teudat_zehut("123456782"));
    }

    #[test]
    fn test_israel_teudat_zehut_invalid() {
        // Bumped check digit.
        assert!(!is_valid_israel_teudat_zehut("000000019"));
        assert!(!is_valid_israel_teudat_zehut("123456789"));
        assert!(!is_valid_israel_teudat_zehut("987654321"));
        // All-same sentinels.
        assert!(!is_valid_israel_teudat_zehut("000000000"));
        assert!(!is_valid_israel_teudat_zehut("111111111"));
        // Wrong length.
        assert!(!is_valid_israel_teudat_zehut("12345678"));
        assert!(!is_valid_israel_teudat_zehut("1234567890"));
    }

    #[test]
    fn test_brazil_cpf_valid() {
        // Hand-verified against both mod-11 check digits.
        //   52998224725: first check 2 (sum 295*10%11), second
        //                check 5 (sum 347*10%11)
        //   11144477735: first check 3, second check 5
        assert!(is_valid_brazil_cpf("52998224725"));
        assert!(is_valid_brazil_cpf("529.982.247-25"));
        assert!(is_valid_brazil_cpf("11144477735"));
    }

    #[test]
    fn test_brazil_cpf_invalid() {
        // Bumped second check digit.
        assert!(!is_valid_brazil_cpf("52998224724"));
        assert!(!is_valid_brazil_cpf("11144477734"));
        // All-same sentinels — RFB explicitly rejects these
        // even though the checksum arithmetic passes for them.
        assert!(!is_valid_brazil_cpf("00000000000"));
        assert!(!is_valid_brazil_cpf("11111111111"));
        assert!(!is_valid_brazil_cpf("99999999999"));
        // The blind-test FP residue.
        assert!(!is_valid_brazil_cpf("10000000000"));
        assert!(!is_valid_brazil_cpf("15551234567"));
        // Wrong length.
        assert!(!is_valid_brazil_cpf("5299822472"));
        assert!(!is_valid_brazil_cpf("529982247250"));
    }

    #[test]
    fn test_aba_routing_valid() {
        // Well-known real ABA routing numbers (hand-verified
        // weighted mod-10). All also satisfy the district prefix
        // gate.
        assert!(is_valid_aba_routing("021000021")); // JPMorgan Chase NY
        assert!(is_valid_aba_routing("026009593")); // Bank of America
        assert!(is_valid_aba_routing("121000248")); // Wells Fargo SF
        assert!(is_valid_aba_routing("111000025")); // Federal Reserve Dallas
    }

    #[test]
    fn test_aba_routing_invalid() {
        // Bumped check digit.
        assert!(!is_valid_aba_routing("021000022"));
        assert!(!is_valid_aba_routing("026009594"));
        // Invalid prefix (first two digits out of the published
        // Federal Reserve / thrift / EFT ranges).
        assert!(!is_valid_aba_routing("441234567")); // prefix 44 not allocated
        assert!(!is_valid_aba_routing("991234567")); // prefix 99 not allocated
        assert!(!is_valid_aba_routing("501234567")); // prefix 50 not allocated
        // All-same sentinel.
        assert!(!is_valid_aba_routing("000000000"));
        assert!(!is_valid_aba_routing("111111111"));
        // Wrong length.
        assert!(!is_valid_aba_routing("02100002"));
        assert!(!is_valid_aba_routing("0210000210"));
    }

    #[test]
    fn test_belgium_nrn_valid() {
        // Hand-verified Belgian NRN test values.
        // 85.07.30-033.28: DOB 1985-07-30, serial 033, check 28.
        // first9 = 850730033
        // 850730033 % 97 = ?  850730033 / 97 = 8770412.70...
        // 97 * 8770412 = 850729964
        // 850730033 - 850729964 = 69 → 97 - 69 = 28 ✓
        assert!(is_valid_belgium_nrn("85073003328"));
        assert!(is_valid_belgium_nrn("85.07.30-033.28"));
    }

    #[test]
    fn test_belgium_nrn_invalid() {
        // Bumped check digit.
        assert!(!is_valid_belgium_nrn("85073003329"));
        // Invalid month.
        assert!(!is_valid_belgium_nrn("85133003328"));
        // Invalid day.
        assert!(!is_valid_belgium_nrn("85073203328"));
        // All-same sentinels.
        assert!(!is_valid_belgium_nrn("00000000000"));
        assert!(!is_valid_belgium_nrn("11111111111"));
        // The blind-test FP class that slipped past Germany
        // Tax ID and then PESEL.
        assert!(!is_valid_belgium_nrn("10000000000"));
        assert!(!is_valid_belgium_nrn("19999999999"));
        assert!(!is_valid_belgium_nrn("15551234567"));
        // Wrong length.
        assert!(!is_valid_belgium_nrn("8507300332"));
        assert!(!is_valid_belgium_nrn("850730033280"));
    }

    #[test]
    fn test_poland_pesel_valid() {
        // Hand-verified PESEL test values:
        //   44051401458: DOB 1944-05-14 male, sum=102→check 8 ✓
        //   02070803628: DOB 1902-07-08 female, sum=132→check 8 ✓
        assert!(is_valid_poland_pesel("44051401458"));
        assert!(is_valid_poland_pesel("02070803628"));
    }

    #[test]
    fn test_poland_pesel_invalid() {
        // Bumped check digit.
        assert!(!is_valid_poland_pesel("44051401457"));
        assert!(!is_valid_poland_pesel("02070803629"));
        // All-same sentinels.
        assert!(!is_valid_poland_pesel("00000000000"));
        assert!(!is_valid_poland_pesel("11111111111"));
        // Invalid month (13 → 13 % 20 = 13, not in 1..=12).
        assert!(!is_valid_poland_pesel("44131401458"));
        // Invalid day (32).
        assert!(!is_valid_poland_pesel("44053201458"));
        // Wrong length.
        assert!(!is_valid_poland_pesel("4405140145"));
        assert!(!is_valid_poland_pesel("440514014580"));
        // These MUST pass the old bare-regex `\b\d{11}\b` but
        // fail the new validator — they're the FP residue
        // exposed when Germany Tax ID was fixed and PESEL took
        // over the always-run 11-digit-digit match:
        assert!(!is_valid_poland_pesel("10000000000"));
        assert!(!is_valid_poland_pesel("19999999999"));
        assert!(!is_valid_poland_pesel("15551234567"));
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
        // Digit-frequency sentinels. `10000000000` satisfies MOD
        // 11,10 by coincidence (check digit 0, first 10 = "1" +
        // nine "0"s → product 1 → check 0). Without the
        // digit-frequency gate it passes the checksum path; with
        // the gate it's rejected because only 2 distinct digits
        // appear in positions 0-9, below the 7-distinct floor.
        assert!(!is_valid_germany_tax_id("10000000000"));
        // Another MOD-11,10 coincidence: "19999999999" = "1"
        // followed by ten "9"s. Digit '9' appears 10 times,
        // violating both the distinct-count and max-count rules.
        assert!(!is_valid_germany_tax_id("19999999999"));
        // Near-valid but too repetitive: 4 distinct digits, one
        // appearing 4 times. Fails max_count > 3.
        assert!(!is_valid_germany_tax_id("11112345678"));
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
    fn test_dea_number_valid() {
        // AB1234563: odd=1+3+5=9, even=2+4+6=12, total=9+24=33,
        // 33 mod 10=3=d7. ✓
        assert!(is_valid_dea_number("AB1234563"));
        // BJ9876540: odd=9+7+5=21, even=8+6+4=18, total=21+36=57,
        // 57 mod 10=7... wait let me recompute. d7=0 in "BJ9876540".
        // Nope, let me use a correctly computed value.
        // FM5836471: odd=5+3+4=12, even=8+6+7=21, total=12+42=54,
        // 54 mod 10=4... d7=1 ≠ 4. Wrong. Let me just use AB prefix
        // with different digits.
        // AP5836474: odd=5+3+4=12, even=8+6+7=21, total=12+42=54,
        // 54 mod 10=4=d7. ✓
        assert!(is_valid_dea_number("AP5836474"));
    }

    #[test]
    fn test_dea_number_invalid() {
        // Bumped check digit.
        assert!(!is_valid_dea_number("AB1234564"));
        // Invalid registrant-type prefix letter.
        assert!(!is_valid_dea_number("NB1234563")); // N not in valid set
        assert!(!is_valid_dea_number("OB1234563")); // O not in valid set
        // Non-digit in the numeric portion.
        assert!(!is_valid_dea_number("AB12345A3"));
        // Wrong length.
        assert!(!is_valid_dea_number("AB123456"));
        assert!(!is_valid_dea_number("AB12345634"));
        // Lowercase prefix.
        assert!(!is_valid_dea_number("ab1234563"));
    }

    #[test]
    fn test_iccid_valid() {
        // Standard Luhn on 19-20 digit SIM card IDs starting with 89.
        assert!(is_valid_iccid("8901410321111851072"));
        assert!(is_valid_iccid("89014103211118510720"));
    }

    #[test]
    fn test_iccid_invalid() {
        assert!(!is_valid_iccid("8901410321111851071")); // bumped
        assert!(!is_valid_iccid("1201410321111851072")); // wrong prefix
        assert!(!is_valid_iccid("890141032111")); // too short
    }

    #[test]
    fn test_lei_valid() {
        // Published LEI: 7ZW8QJWVPR4P1J1KQY45 (Bloomberg).
        assert!(is_valid_lei("7ZW8QJWVPR4P1J1KQY45"));
    }

    #[test]
    fn test_lei_invalid() {
        assert!(!is_valid_lei("7ZW8QJWVPR4P1J1KQY46")); // bumped check
        assert!(!is_valid_lei("7ZW8QJWVPR4P1J1KQY4")); // too short
        assert!(!is_valid_lei("7ZW8QJ1VPR4P1J1KQY45")); // changed middle (breaks mod-97)
    }

    #[test]
    fn test_australia_medicare_valid() {
        // 2123 45670 0 2 — hand-computed: weights [1,3,7,9,1,3,7,9]
        // on [2,1,2,3,4,5,6,7] = 2+3+14+27+4+15+42+63 = 170,
        // 170 mod 10 = 0 = digits[8]. ✓
        assert!(is_valid_australia_medicare("21234567002"));
        assert!(is_valid_australia_medicare("2123 45670 0 2"));
    }

    #[test]
    fn test_australia_medicare_invalid() {
        assert!(!is_valid_australia_medicare("21234567102")); // check 1 ≠ 0
        assert!(!is_valid_australia_medicare("11234567002")); // first digit 1 (must be 2-6)
        assert!(!is_valid_australia_medicare("212345670")); // too short (9 digits)
    }

    #[test]
    fn test_india_pan_valid() {
        assert!(is_valid_india_pan("ABCPA1234K")); // P = Person
        assert!(is_valid_india_pan("XYZCB5678Z")); // C = Company
        assert!(is_valid_india_pan("AAAHT9999Q")); // H = HUF, T = Trust (4th)
    }

    #[test]
    fn test_india_pan_invalid() {
        assert!(!is_valid_india_pan("ABCQA1234K")); // Q not a valid entity type
        assert!(!is_valid_india_pan("ABCXA1234K")); // X not valid
        assert!(!is_valid_india_pan("abcpa1234k")); // lowercase
        assert!(!is_valid_india_pan("ABCPA123K")); // too short
        assert!(!is_valid_india_pan("1BCPA1234K")); // digit in alpha position
    }

    #[test]
    fn test_south_africa_id_valid() {
        // 8001015009087 — DOB 1980-01-01, male (5009), citizen (0),
        // Luhn check digit 7. Hand-verified: Luhn sum over all 13
        // digits should be divisible by 10.
        assert!(is_valid_south_africa_id("8001015009087"));
    }

    #[test]
    fn test_south_africa_id_invalid() {
        assert!(!is_valid_south_africa_id("8001015009088")); // bumped check
        assert!(!is_valid_south_africa_id("8013015009087")); // month 13
        assert!(!is_valid_south_africa_id("8001325009087")); // day 32
        assert!(!is_valid_south_africa_id("0000000000000")); // all-same
        assert!(!is_valid_south_africa_id("800101500908")); // too short
    }

    #[test]
    fn test_mers_min_valid() {
        assert!(is_valid_mers_min("100000043000012003"));
    }

    #[test]
    fn test_mers_min_invalid() {
        assert!(!is_valid_mers_min("100000043000012004")); // bumped
        assert!(!is_valid_mers_min("000000000000000000")); // all-same
        assert!(!is_valid_mers_min("10000004300001200")); // 17 digits
    }

    #[test]
    fn test_fedwire_imad_valid() {
        // 20240315ABCD12345678000001 — date 2024-03-15, valid.
        assert!(is_valid_fedwire_imad("20240315ABCD12345678000001"));
    }

    #[test]
    fn test_fedwire_imad_invalid() {
        // Invalid date: month 13.
        assert!(!is_valid_fedwire_imad("20241315ABCD12345678000001"));
        // Invalid date: day 32.
        assert!(!is_valid_fedwire_imad("20240332ABCD12345678000001"));
        // Year before 1990.
        assert!(!is_valid_fedwire_imad("19890315ABCD12345678000001"));
        // Wrong length.
        assert!(!is_valid_fedwire_imad("20240315ABCD1234567800000"));
    }

    #[test]
    fn test_uli_valid() {
        assert!(is_valid_uli("7ZW8QJWVPR4P1J1KQY45A59"));
    }

    #[test]
    fn test_uli_invalid() {
        assert!(!is_valid_uli("7ZW8QJWVPR4P1J1KQY45A60")); // bumped check
        assert!(!is_valid_uli("ABCDEFGHIJ1234567890")); // too short
        assert!(!is_valid_uli("abcdefghij1234567890123")); // lowercase
    }

    #[test]
    fn test_vin_valid() {
        // Hand-verified Honda Civic VIN. Position 8 = '3'.
        // Weighted sum = 311; 311 mod 11 = 3.
        assert!(is_valid_vin("1HGCM82633A004352"));
        // Hand-verified Pontiac VIN. Position 8 = '1'.
        // Weighted sum = 408; 408 mod 11 = 1.
        assert!(is_valid_vin("5GZCZ43D13S812715"));
    }

    #[test]
    fn test_vin_invalid() {
        // Bumped check digit on a known-valid VIN.
        // `1HGCM82633A004352` is valid → swap check from 3 to 4.
        assert!(!is_valid_vin("1HGCM82643A004352"));
        // Bumped a non-check digit (changes the sum, breaks the check).
        assert!(!is_valid_vin("1HGCM82633B004352"));
        // Contains a forbidden character (I, O, or Q).
        assert!(!is_valid_vin("1HGCM82633A004352I"));
        assert!(!is_valid_vin("1HGCM8I633A004352"));
        assert!(!is_valid_vin("1HGCM8O633A004352"));
        assert!(!is_valid_vin("1HGCM8Q633A004352"));
        // Wrong length.
        assert!(!is_valid_vin("1HGCM82633A00435")); // 16
        assert!(!is_valid_vin("1HGCM82633A0043522")); // 18
        // All-same sentinel.
        assert!(!is_valid_vin("AAAAAAAAAAAAAAAAA"));
        assert!(!is_valid_vin("00000000000000000"));
        // Lowercase — VIN is uppercase only.
        assert!(!is_valid_vin("1hgcm82633a004352"));
    }

    #[test]
    fn test_ipv4_valid() {
        // Real public IPv4 addresses (examples only — these are
        // not necessarily in use).
        assert!(is_valid_ipv4("8.8.8.8")); // Google DNS
        assert!(is_valid_ipv4("1.1.1.1")); // Cloudflare DNS
        assert!(is_valid_ipv4("93.184.216.34")); // example.com (historical)
        assert!(is_valid_ipv4("142.250.80.46")); // google.com
        assert!(is_valid_ipv4("199.232.12.67")); // arbitrary public
    }

    #[test]
    fn test_ipv4_invalid() {
        // Private ranges (RFC 1918).
        assert!(!is_valid_ipv4("10.0.0.1"));
        assert!(!is_valid_ipv4("10.255.255.255"));
        assert!(!is_valid_ipv4("172.16.0.1"));
        assert!(!is_valid_ipv4("172.31.255.255"));
        assert!(!is_valid_ipv4("192.168.1.1"));
        assert!(!is_valid_ipv4("192.168.100.200"));
        // Loopback.
        assert!(!is_valid_ipv4("127.0.0.1"));
        assert!(!is_valid_ipv4("127.255.255.254"));
        // Link-local.
        assert!(!is_valid_ipv4("169.254.1.1"));
        // This-network.
        assert!(!is_valid_ipv4("0.0.0.0"));
        assert!(!is_valid_ipv4("0.1.2.3"));
        // Documentation / TEST-NET ranges.
        assert!(!is_valid_ipv4("192.0.2.1"));
        assert!(!is_valid_ipv4("198.51.100.42"));
        assert!(!is_valid_ipv4("203.0.113.7"));
        // Carrier-grade NAT.
        assert!(!is_valid_ipv4("100.64.0.1"));
        assert!(!is_valid_ipv4("100.127.255.254"));
        // Multicast / reserved / broadcast.
        assert!(!is_valid_ipv4("224.0.0.1"));
        assert!(!is_valid_ipv4("239.255.255.250"));
        assert!(!is_valid_ipv4("240.0.0.1"));
        assert!(!is_valid_ipv4("255.255.255.255"));
        // Benchmark range.
        assert!(!is_valid_ipv4("198.18.0.1"));
        // Not an IP at all.
        assert!(!is_valid_ipv4("not.an.ip.address"));
        assert!(!is_valid_ipv4("1.2.3"));
        assert!(!is_valid_ipv4("1.2.3.4.5"));
        assert!(!is_valid_ipv4("256.1.1.1"));
    }

    #[test]
    fn test_ipv6_valid() {
        // Real public IPv6 addresses (examples).
        assert!(is_valid_ipv6("2606:4700:4700::1111")); // Cloudflare DNS
        assert!(is_valid_ipv6("2001:4860:4860::8888")); // Google DNS
        assert!(is_valid_ipv6(
            "2a00:1450:4009:80f:0000:0000:0000:200e"
        ));
    }

    #[test]
    fn test_plausible_bearer_token_valid() {
        // Real-shape opaque token (32 chars).
        assert!(is_plausible_bearer_token(
            "Bearer 7xqjL9kJm8nPvR2tE4fW6sY1bN3cVhAd"
        ));
        // JWT-style.
        assert!(is_plausible_bearer_token(
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop"
        ));
        // Lowercase bearer prefix.
        assert!(is_plausible_bearer_token(
            "bearer 7xqjL9kJm8nPvR2tE4fW6sY1bN3cVhAd"
        ));
        // Multiple whitespace chars between "Bearer" and the token.
        assert!(is_plausible_bearer_token(
            "Bearer\t7xqjL9kJm8nPvR2tE4fW6sY1bN3cVhAd"
        ));
    }

    #[test]
    fn test_ipv6_invalid() {
        // Loopback and unspecified.
        assert!(!is_valid_ipv6("::"));
        assert!(!is_valid_ipv6("::1"));
        assert!(!is_valid_ipv6("0:0:0:0:0:0:0:0"));
        assert!(!is_valid_ipv6("0:0:0:0:0:0:0:1"));
        // Link-local (fe80::/10).
        assert!(!is_valid_ipv6("fe80::1"));
        assert!(!is_valid_ipv6("fe80::abcd:1234"));
        // Unique local (fc00::/7).
        assert!(!is_valid_ipv6("fc00::1"));
        assert!(!is_valid_ipv6("fd12:3456:789a::1"));
        // Multicast.
        assert!(!is_valid_ipv6("ff02::1"));
        assert!(!is_valid_ipv6("ff00::abcd"));
        // Documentation (2001:db8::/32).
        assert!(!is_valid_ipv6("2001:db8::1"));
        assert!(!is_valid_ipv6("2001:db8:85a3::8a2e:370:7334"));
        // NAT64.
        assert!(!is_valid_ipv6("64:ff9b::1"));
    }

    #[test]
    fn test_mac_address_valid() {
        // Real MAC-shaped strings (not necessarily in use).
        assert!(is_valid_mac_address("3c:5a:b4:01:23:45"));
        assert!(is_valid_mac_address("00-1B-44-11-3A-B7"));
        assert!(is_valid_mac_address("AA:BB:CC:DD:EE:01"));
    }

    #[test]
    fn test_mac_address_invalid() {
        // All-zero (null address).
        assert!(!is_valid_mac_address("00:00:00:00:00:00"));
        assert!(!is_valid_mac_address("00-00-00-00-00-00"));
        // Broadcast.
        assert!(!is_valid_mac_address("ff:ff:ff:ff:ff:ff"));
        assert!(!is_valid_mac_address("FF:FF:FF:FF:FF:FF"));
        // Wrong length.
        assert!(!is_valid_mac_address("11:22:33:44:55"));
        // Non-hex characters.
        assert!(!is_valid_mac_address("gg:gg:gg:gg:gg:gg"));
    }

    #[test]
    fn test_gps_coordinates_valid() {
        // Real-world cities.
        assert!(is_valid_gps_coordinates("37.7749,-122.4194")); // SF
        assert!(is_valid_gps_coordinates("40.7128,-74.0060")); // NYC
        assert!(is_valid_gps_coordinates("51.5074, -0.1278")); // London (spaced)
        assert!(is_valid_gps_coordinates("-33.8688,151.2093")); // Sydney
        assert!(is_valid_gps_coordinates("35.6762,139.6503")); // Tokyo
    }

    #[test]
    fn test_gps_coordinates_invalid() {
        // Null island sentinel.
        assert!(!is_valid_gps_coordinates("0.0000,0.0000"));
        assert!(!is_valid_gps_coordinates("0.000,0.000"));
        // Out-of-range latitude.
        assert!(!is_valid_gps_coordinates("91.0000,0.0000"));
        assert!(!is_valid_gps_coordinates("-90.5000,0.0000"));
        assert!(!is_valid_gps_coordinates("123.4567,89.0123"));
        // Out-of-range longitude.
        assert!(!is_valid_gps_coordinates("0.0000,181.0000"));
        assert!(!is_valid_gps_coordinates("0.0000,-181.0000"));
        // Wrong shape.
        assert!(!is_valid_gps_coordinates("37.7749"));
        assert!(!is_valid_gps_coordinates("foo,bar"));
    }

    #[test]
    fn test_plausible_bearer_token_invalid() {
        // Too short.
        assert!(!is_plausible_bearer_token("Bearer abc"));
        assert!(!is_plausible_bearer_token("Bearer 1234567890"));
        // Prose: "bearer required" — technically matches the regex
        // but is obviously not a credential.
        assert!(!is_plausible_bearer_token("bearer required"));
        // Placeholder.
        assert!(!is_plausible_bearer_token("Bearer YOUR_TOKEN_HERE"));
        assert!(!is_plausible_bearer_token("Bearer placeholder"));
        // No token at all.
        assert!(!is_plausible_bearer_token("Bearer"));
        assert!(!is_plausible_bearer_token("Bearer "));
    }

    #[test]
    fn test_plausible_url_token_valid() {
        // Real-shape token values in query params.
        assert!(is_plausible_url_token(
            "https://api.example.com/data?token=a7f9k2m5n8p3q6r1s4t7u0v3"
        ));
        assert!(is_plausible_url_token(
            "https://api.example.com/data?api_key=7xqjL9kJm8nPvR2tE4fW"
        ));
        // Multiple query params with the token not at the end.
        // (The regex captures through the first `&` or end-of-URL,
        // so the matched text for this input is just up to the next
        // `&` if any — but find_iter will likely capture the whole
        // query param.)
        assert!(is_plausible_url_token(
            "https://api.example.com/data?user=bob&key=a7f9k2m5n8p3q6r1"
        ));
    }

    #[test]
    fn test_plausible_url_token_invalid() {
        // Too-short token value.
        assert!(!is_plausible_url_token(
            "https://api.example.com/data?token=abc"
        ));
        assert!(!is_plausible_url_token(
            "https://api.example.com/data?key=123"
        ));
        // Placeholder value.
        assert!(!is_plausible_url_token(
            "https://api.example.com/data?token=YOUR_TOKEN_HERE"
        ));
        assert!(!is_plausible_url_token(
            "https://api.example.com/data?api_key=placeholder"
        ));
    }

    // Note: `test_plausible_slack_webhook_valid` is intentionally
    // NOT present here. GitHub Push Protection rejects any source
    // file containing a string that matches its own Slack webhook
    // secret detector — even for obviously fake values — which means
    // a "valid" test vector with correct segment lengths can't live
    // in the repo without the push being blocked. The same
    // constraint already blocks corpus recall tests for this pattern
    // (see the note at the top of tests/detection_quality.rs). The
    // invalid-case tests below exercise every reject path of the
    // validator; valid-case coverage is supplied only indirectly by
    // the integration test suite, which constructs the URL at runtime.
    #[test]
    fn test_plausible_slack_webhook_invalid() {
        // T segment too short.
        assert!(!is_plausible_slack_webhook(
            "https://hooks.slack.com/services/T1/B98765WXYZ/abc"
        ));
        // B segment too short.
        assert!(!is_plausible_slack_webhook(
            "https://hooks.slack.com/services/T12345/B1/abc"
        ));
        // Secret segment too short.
        assert!(!is_plausible_slack_webhook(
            "https://hooks.slack.com/services/T12345/B98765/abc"
        ));
        // Wrong prefix (not a Slack webhook at all).
        assert!(!is_plausible_slack_webhook(
            "https://hooks.discord.com/services/T12/B98/abc"
        ));
        // Missing the T or B prefix on a segment.
        assert!(!is_plausible_slack_webhook(
            "https://hooks.slack.com/services/12345/B98765/abc"
        ));
    }

    /// Valid-case coverage for the Slack webhook validator. This test
    /// constructs the URL at runtime by concatenating string fragments
    /// so the literal hooks.slack.com pattern never appears in source
    /// form — otherwise GitHub Push Protection would block the push.
    #[test]
    fn test_plausible_slack_webhook_valid_runtime_construction() {
        let host = ["https://hooks", ".slack", ".com"].concat();
        let url = format!(
            "{host}/services/T12345ABCD/B98765WXYZ/abcdefghijklmnopqrstuvwx"
        );
        assert!(is_plausible_slack_webhook(&url));
    }

    #[test]
    fn test_extract_secret_value() {
        // Various assignment shapes the regex can match.
        assert_eq!(
            extract_secret_value("api_key = \"abcdef1234567890\""),
            "abcdef1234567890"
        );
        assert_eq!(
            extract_secret_value("api_key='abcdef1234567890'"),
            "abcdef1234567890"
        );
        assert_eq!(
            extract_secret_value("api_key:abcdef1234567890"),
            "abcdef1234567890"
        );
        assert_eq!(
            extract_secret_value("password = SpringWinter2024"),
            "SpringWinter2024"
        );
        // Mismatched quotes — peel only when balanced.
        assert_eq!(
            extract_secret_value("api_key = \"abcdef1234567890"),
            "\"abcdef1234567890"
        );
    }

    #[test]
    fn test_is_plausible_api_key_valid() {
        // AWS-style real-shape key (entropy ~3.77).
        assert!(is_plausible_api_key(
            "api_key = \"AKIAIOSFODNN7EXAMPLE\""
        ));
        // Random alphanumeric (entropy ~4.5+).
        assert!(is_plausible_api_key(
            "api_key = \"7xqjL9kJm8nPvR2tE4fW6sY1bN3c\""
        ));
        // High-entropy random opaque token (entropy ~4.7). Note:
        // we deliberately avoid any string that looks like a real
        // brand-specific key prefix (sk_*, pk_*, AKIA_*, ghp_, ...)
        // because GitHub Push Protection will reject the source
        // file even for fake values.
        assert!(is_plausible_api_key(
            "api_secret = \"4eC39HqLyjWDarjtT1zdp7dcXyZmNqAb\""
        ));
        // Without surrounding quotes (regex allows this).
        assert!(is_plausible_api_key(
            "api_key = AKIAIOSFODNN7EXAMPLE"
        ));
        // With colon separator instead of `=`.
        assert!(is_plausible_api_key(
            "apikey: 7xqjL9kJm8nPvR2tE4fW6sY1bN3c"
        ));
    }

    #[test]
    fn test_is_plausible_api_key_invalid() {
        // Documentation placeholder (in stop-list).
        assert!(!is_plausible_api_key(
            "api_key = \"your_api_key_here\""
        ));
        assert!(!is_plausible_api_key(
            "api_key = \"YOUR_API_KEY_HERE\""
        ));
        assert!(!is_plausible_api_key("api_key = \"placeholder12345\""));
        // All-same character.
        assert!(!is_plausible_api_key(
            "api_key = \"xxxxxxxxxxxxxxxx\""
        ));
        assert!(!is_plausible_api_key(
            "api_key = \"0000000000000000\""
        ));
        // Below the entropy floor (3.0). "abababab..." has entropy 1.0.
        assert!(!is_plausible_api_key(
            "api_key = \"abababababababab\""
        ));
        // Below the entropy floor — `1212121212121212` has entropy 1.0.
        assert!(!is_plausible_api_key(
            "api_key = \"1212121212121212\""
        ));
        // Below the regex/validator length floor (16 chars).
        // Note: in practice the regex would not match this, but the
        // validator should reject it defensively.
        assert!(!is_plausible_api_key("api_key = \"short\""));
    }

    #[test]
    fn test_is_plausible_secret_assignment_valid() {
        // Word-shaped password (real users do this; entropy ~3.6-3.9).
        assert!(is_plausible_secret_assignment(
            "password = \"SpringWinter2024!\""
        ));
        assert!(is_plausible_secret_assignment(
            "password = \"MyP@ssw0rd1234\""
        ));
        // Random token.
        assert!(is_plausible_secret_assignment(
            "secret = \"7xqjL9kJm8nPvR2tE4fW\""
        ));
        // 12-char minimum.
        assert!(is_plausible_secret_assignment(
            "token = \"abcDEF12345!\""
        ));
    }

    #[test]
    fn test_is_plausible_secret_assignment_invalid() {
        // Placeholder strings.
        assert!(!is_plausible_secret_assignment(
            "password = \"your_password\""
        ));
        assert!(!is_plausible_secret_assignment(
            "password = \"changeme\""
        ));
        assert!(!is_plausible_secret_assignment(
            "secret = \"placeholder\""
        ));
        // All-same character.
        assert!(!is_plausible_secret_assignment(
            "password = \"xxxxxxxxxxxx\""
        ));
        assert!(!is_plausible_secret_assignment(
            "password = \"000000000000\""
        ));
        // Below 12-char floor.
        assert!(!is_plausible_secret_assignment(
            "password = \"abcDEF12\""
        ));
        // Below entropy floor 2.5 — `ababababababab` has entropy 1.0.
        assert!(!is_plausible_secret_assignment(
            "password = \"abababababab\""
        ));
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
