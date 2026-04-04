//! Compliance presets mapping to pattern categories.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compliance presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// PCI-DSS: Credit card & banking data.
    PciDss,
    /// Social security numbers.
    SsnSin,
    /// Personal identifiable information.
    Pii,
    /// PII + regional identifiers.
    PiiStrict,
    /// API keys, tokens, secrets.
    Credentials,
    /// All financial data.
    Financial,
    /// Medical/insurance data.
    Healthcare,
    /// Email, phone, addresses.
    ContactInfo,
}

/// Map presets to category sets.
pub static PRESET_CATEGORIES: Lazy<HashMap<Preset, Vec<&'static str>>> = Lazy::new(|| {
    let mut m = HashMap::new();

    m.insert(
        Preset::PciDss,
        vec![
            "Credit Card Numbers",
            "Primary Account Numbers",
            "Card Track Data",
            "Card Expiration Dates",
            "Banking and Financial",
            "PCI Sensitive Data",
        ],
    );

    m.insert(
        Preset::SsnSin,
        vec![
            "North America - United States",
            "North America - Canada",
        ],
    );

    m.insert(
        Preset::Pii,
        vec![
            "Personal Identifiers",
            "Contact Information",
            "Geolocation",
            "Postal Codes",
            "Device Identifiers",
            "Social Media Identifiers",
            "Education Identifiers",
            "Employment Identifiers",
            "Biometric Identifiers",
            "Property Identifiers",
        ],
    );

    m.insert(
        Preset::PiiStrict,
        vec![
            "Personal Identifiers",
            "Contact Information",
            "Geolocation",
            "Postal Codes",
            "Device Identifiers",
            "Social Media Identifiers",
            "Education Identifiers",
            "Employment Identifiers",
            "Biometric Identifiers",
            "Property Identifiers",
            "North America - United States",
            "North America - US Generic DL",
            "North America - Canada",
            "North America - Mexico",
            "Europe - United Kingdom",
            "Europe - Germany",
            "Europe - France",
            "Europe - Italy",
            "Europe - Spain",
        ],
    );

    m.insert(
        Preset::Credentials,
        vec![
            "Generic Secrets",
            "Cloud Provider Secrets",
            "Code Platform Secrets",
            "Payment Service Secrets",
            "Messaging Service Secrets",
        ],
    );

    m.insert(
        Preset::Financial,
        vec![
            "Credit Card Numbers",
            "Primary Account Numbers",
            "Card Track Data",
            "Card Expiration Dates",
            "Banking and Financial",
            "Wire Transfer Data",
            "Check and MICR Data",
            "Securities Identifiers",
            "Loan and Mortgage Data",
            "Regulatory Identifiers",
            "Banking Authentication",
            "Customer Financial Data",
            "Internal Banking References",
            "PCI Sensitive Data",
            "Cryptocurrency",
        ],
    );

    m.insert(
        Preset::Healthcare,
        vec![
            "Medical Identifiers",
            "Insurance Identifiers",
        ],
    );

    m.insert(
        Preset::ContactInfo,
        vec!["Contact Information"],
    );

    m
});
