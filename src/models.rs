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
        }
    }

    /// Return a redacted version of the matched text.
    /// Shows first 3 and last 3 characters for matches longer than 8 chars.
    pub fn redacted_text(&self) -> String {
        if self.text.len() <= 8 {
            "*".repeat(self.text.len())
        } else {
            let first: String = self.text.chars().take(3).collect();
            let last: String = self.text.chars().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect();
            let middle_len = self.text.chars().count().saturating_sub(6);
            format!("{}{}{}", first, "*".repeat(middle_len), last)
        }
    }

    /// Convert to a JSON-serializable map.
    pub fn to_dict(&self, redact: bool) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_default();
        if redact {
            if let Some(obj) = val.as_object_mut() {
                obj.insert("text".into(), serde_json::Value::String(self.redacted_text()));
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
        "SWIFT/BIC" => 0.85,
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
        "SEDOL" => 0.70,
        "FIGI" => 0.90,
        "LEI" => 0.80,
        "Ticker Symbol" => 0.80,
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
        "Bitcoin Address" | "Ethereum Address" | "Litecoin Address" | "Ripple Address" => 0.80,
        "Bitcoin Cash Address" => 0.75,
        "Monero Address" => 0.85,

        // Vehicles
        "VIN" => 0.70,

        // URLs
        "URL with Credentials" => 0.90,
        "URL with Token Parameter" => 0.75,

        _ => DEFAULT_SPECIFICITY,
    }
}

/// Patterns that REQUIRE context to be reported.
/// These are patterns so broad that without context keywords nearby,
/// they produce too many false positives.
pub fn is_context_required(sub_category: &str) -> bool {
    matches!(
        sub_category,
        "US Bank Account Number"
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
    )
}
