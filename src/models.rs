//! Core data types: Match, PatternDef, and pattern metadata.

use serde::{Deserialize, Serialize};

/// A single sensitive-data match found by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// The matched text from the input.
    pub text: String,
    /// Top-level pattern category (e.g., "Credit Card Numbers").
    pub category: String,
    /// Specific pattern name (e.g., "Visa").
    pub sub_category: String,
    /// Whether contextual keywords were found nearby.
    pub has_context: bool,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f64,
    /// (start, end) byte offsets in the input text.
    pub span: (usize, usize),
    /// Whether this pattern requires context to be reliable.
    pub context_required: bool,
    /// Optional metadata for enriched findings (e.g., BIN issuer, country).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, String>,
}

impl Match {
    /// Create a new Match.
    pub fn new(
        text: String,
        category: String,
        sub_category: String,
        has_context: bool,
        confidence: f64,
        span: (usize, usize),
        context_required: bool,
    ) -> Self {
        Self {
            text,
            category,
            sub_category,
            has_context,
            confidence,
            span,
            context_required,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add a metadata key-value pair.
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Return a redacted version of the matched text.
    /// Shows first 3 and last 3 characters for matches longer than 8 chars.
    ///
    /// NOTE: This retains partial plaintext and is intended for operator-
    /// facing contexts (CLI output, audit logs with access controls). Do
    /// NOT use this for API responses or any external surface where even
    /// partial disclosure would be a leak — use [`Self::masked_text`] there.
    pub fn redacted_text(&self) -> String {
        if self.text.len() <= 8 {
            "*".repeat(self.text.len())
        } else {
            let first: String = self.text.chars().take(3).collect();
            let last: String = self
                .text
                .chars()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let middle_len = self.text.chars().count().saturating_sub(6);
            format!("{}{}{}", first, "*".repeat(middle_len), last)
        }
    }

    /// Return a fully-masked version of the matched text, preserving length
    /// in characters but revealing no plaintext. Use this on any external
    /// surface (HTTP API responses, webhook payloads, SIEM forwards) where
    /// the caller must not see any portion of the matched value.
    pub fn masked_text(&self) -> String {
        "*".repeat(self.text.chars().count())
    }

    /// Convert to a JSON-serializable map.
    pub fn to_dict(&self, redact: bool) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_default();
        if redact {
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "text".into(),
                    serde_json::Value::String(self.redacted_text()),
                );
            }
        }
        val
    }
}

/// Definition of a DLP pattern used by the scanner.
#[derive(Debug, Clone)]
pub struct PatternDef {
    /// Top-level category name.
    pub category: &'static str,
    /// Specific pattern name within the category.
    pub sub_category: &'static str,
    /// The regex pattern string.
    pub regex: &'static str,
    /// Whether this pattern is case-insensitive.
    pub case_insensitive: bool,
    /// Base specificity score (0.0-1.0).
    pub specificity: f64,
    /// Whether context keywords are required for this pattern.
    pub context_required: bool,
}

/// Default specificity for patterns not explicitly scored.
pub const DEFAULT_SPECIFICITY: f64 = 0.40;

/// Get the specificity score for a sub_category.
pub fn pattern_specificity(sub_category: &str) -> f64 {
    match sub_category {
        // Credit Cards (Luhn-validated, highly specific)
        "Visa" | "MasterCard" | "Amex" | "Discover" | "JCB" | "Diners Club" | "UnionPay" => 0.90,
        "PAN" => 0.60,
        "Masked PAN" => 0.85,
        "Track 1 Data" | "Track 2 Data" => 0.95,
        "Card Expiry" => 0.30,

        // Banking
        "IBAN Generic" => 0.90,
        "SWIFT/BIC" => 0.65, // lowered from 0.85 — context-gated + country code validation
        "ABA Routing Number" => 0.55,
        "US Bank Account Number" => 0.20,
        "Canada Transit Number" => 0.40,
        "Fedwire IMAD" => 0.90,
        "CHIPS UID" => 0.50,
        "Wire Reference Number" | "SEPA Reference" => 0.50,
        "ACH Trace Number" => 0.55,
        "ACH Batch Number" => 0.20,
        "MICR Line" => 0.90,
        "Check Number" => 0.15,
        "Cashier Check Number" => 0.20,
        "CUSIP" => 0.70,
        "ISIN" => 0.75,
        "SEDOL" => 0.50, // lowered — 7-char alphanumeric is common; context-gated + check digit
        "FIGI" => 0.90,
        "LEI" => 0.80,
        "Ticker Symbol" => 0.60, // lowered — $WORD is common in shell/templates; context-gated
        "Loan Number" => 0.45,
        "MERS MIN" => 0.50,
        "Universal Loan Identifier" => 0.75,
        "LTV Ratio" => 0.40,
        "SAR Filing Number" | "CTR Number" | "FinCEN Report Number" => 0.30,
        "AML Case ID" => 0.60,
        "OFAC SDN Entry" => 0.15,
        "Compliance Case Number" => 0.55,
        "PIN Block" => 0.65,
        "HSM Key" => 0.55,
        "Encryption Key" => 0.50,
        "Account Balance" => 0.50,
        "Balance with Currency Code" => 0.55,
        "Income Amount" => 0.40,
        "DTI Ratio" => 0.45,
        "Internal Account Ref" => 0.50,
        "Teller ID" => 0.35,
        "Cardholder Name Pattern" => 0.10,

        // Contact Info
        "Email Address" => 0.90,
        "Phone Number (E.164)" => 0.70,
        "IPv4 Address" => 0.60,
        "IPv6 Address" => 0.80,
        "MAC Address" => 0.80,

        // PII
        "Date of Birth" => 0.40,
        "Gender Marker" => 0.25,
        "GPS Coordinates" => 0.80,
        "GPS DMS" => 0.85,
        "Geohash" => 0.60,
        "US ZIP+4 Code" => 0.55,
        "UK Postcode" => 0.70,
        "Canada Postal Code" => 0.75,
        "Japan Postal Code" => 0.45,
        "Brazil CEP" => 0.45,
        "IMEI" | "IMEISV" => 0.55,
        "MEID" => 0.70,
        "ICCID" => 0.85,
        "IDFA/IDFV" => 0.85,
        "Health Plan ID" => 0.60,
        "DEA Number" => 0.55,
        "ICD-10 Code" => 0.50,
        "NDC Code" => 0.65,
        "Insurance Policy Number" => 0.50,
        "Insurance Claim Number" => 0.45,
        "Session ID" => 0.55,
        "Twitter Handle" => 0.60,
        "Hashtag" => 0.30,
        "EDU Email" => 0.90,
        "US Federal Case Number" => 0.80,
        "Court Docket Number" => 0.45,
        "Employee ID" => 0.35,
        "Work Permit Number" => 0.50,
        "Biometric Hash" => 0.70,
        "Biometric Template ID" => 0.75,
        "Parcel Number" => 0.60,
        "Title Deed Number" => 0.40,

        // Secrets
        "Bearer Token" => 0.80,
        "JWT Token" => 0.95,
        "Private Key" => 0.95,
        "API Key Generic" | "Generic API Key" => 0.50,
        "Database Connection String" => 0.90,
        "AWS Access Key" => 0.95,
        "AWS Secret Key" => 0.90,
        "Google API Key" => 0.90,
        "GitHub Token (Classic)" | "GitHub Token (Fine-Grained)" | "GitHub OAuth Token" => 0.95,
        "NPM Token" | "PyPI Token" => 0.95,
        "Stripe Secret Key" => 0.95,
        "Stripe Publishable Key" => 0.85,
        "Slack Bot Token" | "Slack User Token" => 0.95,
        "Slack Webhook URL" => 0.90,
        "SendGrid API Key" => 0.95,
        "Twilio API Key" | "Mailgun API Key" => 0.90,

        // Cryptocurrency
        //
        // Note: the actual sub_category names for Bitcoin are
        // `"Bitcoin Address (Legacy)"` and `"Bitcoin Address (Bech32)"`
        // — both with the parenthetical form. A previous revision
        // of this map used the bare `"Bitcoin Address"` key, which
        // silently matched no real sub_category and left both
        // Bitcoin patterns defaulting to DEFAULT_SPECIFICITY = 0.40.
        // That made the Bech32 primary match lose dedup against the
        // spurious `"Bitcoin Cash Address"` match (specificity 0.75)
        // generated by the alt-decodings reverse-text pass — the
        // detection-quality harness reported Bech32 0/1 because the
        // reversed bech32 `qdm5...` happened to match the loose
        // Bitcoin Cash regex, and the higher specificity made it
        // win dedup. With the correct sub_category names here the
        // primary Bech32 match gets its proper 0.80 base and
        // dominates the reverse-pass false positive.
        "Bitcoin Address (Legacy)"
        | "Bitcoin Address (Bech32)"
        | "Ethereum Address"
        | "Litecoin Address"
        | "Ripple Address" => 0.80,
        "Bitcoin Cash Address" => 0.75,
        "Monero Address" => 0.85,

        // National IDs with checksum validators — specificity set above
        // PAN (0.60) so they win dedup when both match the same digits.
        "USA SSN" => 0.70,
        "Canada SIN" => 0.70,
        "India Aadhaar" => 0.65,
        "India PAN" => 0.65,
        "South Africa ID" => 0.65,
        "UAE Emirates ID" => 0.65,
        "Israel Teudat Zehut" => 0.65,
        "Germany Tax ID" => 0.65,
        "Poland PESEL" => 0.65,
        "France NIR" => 0.65,
        "Belgium NRN" => 0.65,
        "Netherlands BSN" => 0.65,
        "Italy Codice Fiscale" | "Italy SSN" => 0.65,
        "Spain DNI" => 0.65,
        "Sweden PIN" => 0.65,
        "Denmark CPR" => 0.55,
        "British NHS" => 0.65,
        "Brazil CPF" => 0.65,
        "Brazil CNPJ" => 0.70,
        "Chile RUN/RUT" => 0.65,
        "Argentina CUIL/CUIT" => 0.65,
        "Mexico CURP" => 0.70,
        "Japan My Number" => 0.65,
        "China Resident ID" => 0.70,
        "South Korea RRN" => 0.65,
        "Singapore NRIC" | "Singapore FIN" => 0.65,
        "Hong Kong ID" => 0.65,
        "Australia TFN" => 0.65,
        "Australia Medicare" => 0.55,
        "Quebec HC" => 0.55,
        "UK NIN" => 0.65,

        // Vehicles
        "VIN" => 0.70,

        // URLs
        // NB: these are the real sub_category names used by the
        // PatternDef entries in src/patterns/mod.rs. Earlier the
        // map had "URL with Credentials" and "URL with Token
        // Parameter" which never matched any pattern and left both
        // URL-credential patterns silently falling through to
        // DEFAULT_SPECIFICITY = 0.40. That dropped their confidence
        // below the email-address dedup tiebreaker and meant a
        // perfectly-shaped credentialed URL was being dropped in
        // favour of the embedded email — the detection-quality
        // harness started reporting `URL with Password` recall 0/1
        // on `quality/url-credential-filters` and this is the fix.
        "URL with Password" => 0.90,
        "URL with Token" => 0.75,

        _ => DEFAULT_SPECIFICITY,
    }
}

/// Patterns that REQUIRE context to be reported.
/// These are patterns so broad that without context keywords nearby,
/// they produce too many false positives.
pub fn is_context_required(sub_category: &str) -> bool {
    matches!(
        sub_category,
        "USA SSN"
            | "USA ITIN"
            | "US Bank Account Number"
            | "ACH Batch Number"
            | "Check Number"
            | "Cashier Check Number"
            | "OFAC SDN Entry"
            | "Cardholder Name Pattern"
            | "Gender Marker"
            | "Hashtag"
            | "Card Expiry"
            | "Date of Birth"
            | "LTV Ratio"
            | "DTI Ratio"
            // Added to reduce false positives on common text
            | "Account Balance"
            | "Balance with Currency Code"
            | "Income Amount"
            | "Teller ID"
            | "Ticker Symbol"
            | "CUSIP"
            | "SEDOL"
            | "Australia TFN"
            // HIPAA #8 — MRN is a bare 6-10 digit regex that would
            // match essentially every order number, account ref,
            // ZIP+4, and phone-minus-area-code in any document.
            // Only safe to fire when an MRN-context keyword is within
            // 50 characters (see `Medical Record Number` in
            // context/keywords.rs).
            | "Medical Record Number"
            // IMEISV is a 16-digit device identifier whose last 2
            // digits are a Software Version, NOT a checksum, so the
            // pattern has no structural signal beyond "16 digits."
            // That makes it indistinguishable from a Luhn-failing
            // credit card, a 16-digit invoice number, or any other
            // 16-digit sequence at the regex layer. Restrict it to
            // fire only when an IMEISV keyword is in range (see
            // `IMEISV` in context/keywords.rs).
            | "IMEISV"
            // USA EIN is a 9-digit bare regex `\d{2}[sep?]\d{7}` that
            // fires on any 9-digit sequence with an optional
            // separator after the second digit. The blind harness
            // showed EIN matching the digit substring of
            // `+441234567`, and at specificity 0.40 without context
            // gating it would match every 9-digit account number,
            // invoice reference, or phone-minus-country-code in a
            // document. IRS publishes a set of valid EIN prefixes
            // (roughly 100 two-digit values) but we don't bundle
            // that table — context gating on `ein` / `employer
            // identification` / `federal tax id` keywords is enough
            // to neutralise the FP class without bringing the data.
            | "USA EIN"
            // USA Passport is a bare `\b\d{9}\b` regex with no
            // published check digit — US passport books use a
            // 9-digit serial with no checksum. Every 9-digit
            // sequence in a document would otherwise match. The
            // keyword set under `USA Passport` in keywords.rs is
            // rich (us passport, passport number, passport book,
            // passport card, ...) so context gating is effective.
            | "USA Passport"
            // UK Passport is a bare `\b\d{9}\b` regex, same class
            // of problem as USA Passport — no published checksum,
            // every 9-digit number matches. Context-gate on the
            // rich `UK Passport` keyword set in keywords.rs.
            | "UK Passport"
            // Bare-regex national ID / passport patterns with no
            // published check digit. Each one below is either a
            // short letter-prefix + digit-suffix shape or a
            // bare digit run, which means the regex alone has no
            // structural discipline beyond "looks right-shaped."
            // Every one of these was firing on arbitrary document
            // content (invoice numbers, SKUs, product codes) when
            // left always-run. Each has a rich keyword set in
            // context/keywords.rs so context gating is effective.
            | "USA Passport Card"          // C + 8 digits
            | "Canada Passport"            // 2 letters + 6 digits
            | "Australia Passport"         // 1-2 letters + 7 digits
            | "Australia Medicare"         // 4-6 + 9 digits (loose shape)
            | "Saudi Arabia National ID"   // 1 or 2 + 9 digits
            // US MBI (Medicare Beneficiary Identifier) has a very
            // tight 11-character structural pattern (specific
            // digit/letter positions, excluded-letter alphabet)
            // but NO published check digit. The regex alone is
            // disciplined enough to mostly avoid FPs on arbitrary
            // text, but context gating adds a safety rail and
            // matches the treatment of US Passport / EIN / etc.
            | "US MBI"
            // HIPAA insurance/health plan identifiers — all three use
            // loose letter+digit regexes with no published checksum.
            // `[A-Z]{3}\d{9}` (Health Plan ID), `[A-Z]{2,4}\d{6,12}`
            // (Insurance Policy), `[A-Z]{1,3}\d{8,15}` (Insurance
            // Claim) would each fire on serial numbers, SKUs, product
            // codes, and order references. Context gating on their
            // HIPAA-specific keyword sets (health plan, policy number,
            // claim number, etc.) is the right discipline.
            | "Health Plan ID"
            | "Insurance Policy Number"
            | "Insurance Claim Number"
            // MEID: 14 hex chars with no check digit captured by the
            // regex. The regex `[0-9A-F]{14}` (with optional seps)
            // matches too many hex-shaped strings. Context-gate on
            // the MEID keyword set.
            | "MEID"
            // --- Context-gate sweep (47 patterns) ---
            // All patterns below have specificity < 0.60, no
            // published checksum validator, and a loose regex that
            // fires on common text. Each has keywords registered in
            // context/keywords.rs. Gating them ensures they only
            // fire when their domain-specific keyword is nearby.
            //
            // Classification labels
            | "Top Secret"
            | "Secret Classification"
            | "Confidential Classification"
            | "FOUO"
            | "CUI"
            | "SBU"
            | "LES"
            | "NOFORN"
            | "Restricted"
            | "Highly Confidential"
            | "Need to Know"
            | "Eyes Only"
            // Corporate classification
            | "Internal Only"
            | "Corporate Confidential"
            | "Do Not Distribute"
            | "Proprietary"
            | "Draft Not for Circulation"
            | "Embargoed"
            // Legal privilege
            | "Attorney-Client Privilege"
            | "Privileged and Confidential"
            | "Work Product"
            | "Privileged Information"
            | "Legal Privilege"
            | "Litigation Hold"
            | "Protected by Privilege"
            // Supervisory / examination
            | "Supervisory Controlled"
            | "Supervisory Confidential"
            | "CSI"
            | "Non-Public Supervisory"
            | "Restricted Supervisory"
            | "Examination Findings"
            // Financial regulation
            | "MNPI"
            | "Pre-Decisional"
            | "Market Sensitive"
            | "Information Barrier"
            | "Inside Information"
            | "Investment Restricted"
            // Compliance labels
            | "PII Label"
            | "PHI Label"
            | "HIPAA"
            | "GDPR Personal Data"
            | "PCI-DSS"
            | "FERPA"
            | "GLBA"
            | "CCPA/CPRA"
            | "SOX"
            | "NPI"
            // Remaining patterns with no published checksum.
            | "ACH Trace Number"  // 15 digits, prefix-validated by regex, no check digit
            | "India Voter ID"    // 3 letters + 7 digits, no published check digit
    )
}
