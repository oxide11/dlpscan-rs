//! Classification labels and Traffic Light Protocol (TLP) severity policy.
//!
//! Provides a normalized severity rank over the heterogeneous set of
//! classification and sharing-control markings the scanner recognizes:
//!
//! - Corporate labels ("Internal Only", "Confidential", "Highly Confidential")
//! - Government labels ("CUI", "FOUO", "Secret", "Top Secret", "NOFORN")
//! - Privilege markings ("Attorney-Client Privilege", "Work Product")
//! - Financial labels ("MNPI")
//! - **Traffic Light Protocol** (TLP:CLEAR, TLP:GREEN, TLP:AMBER,
//!   TLP:AMBER+STRICT, TLP:RED) — per FIRST.org TLP 2.0.
//!
//! Each marking maps to a [`ClassificationLevel`] so callers can apply
//! a single policy threshold — for example, "block anything labeled
//! Confidential or above" or "block TLP:AMBER or above" — without
//! having to enumerate every specific sub-category.

use serde::{Deserialize, Serialize};

/// Normalized severity of a classification or sharing-control label.
///
/// Higher variants are more sensitive. The numeric discriminants are
/// stable and intended to be used in `>=` comparisons for policy
/// thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum ClassificationLevel {
    /// Public / TLP:CLEAR — no sharing restrictions.
    Public = 0,
    /// Internal / TLP:GREEN — community or organization-wide.
    Internal = 1,
    /// Restricted / FOUO / CUI / SBU — limited internal distribution.
    Restricted = 2,
    /// Confidential / TLP:AMBER / TLP:AMBER+STRICT / Privileged —
    /// limited to a specific audience within an organization.
    Confidential = 3,
    /// Secret / TLP:RED / NOFORN — named-recipients-only or compartmented.
    Secret = 4,
    /// Top Secret / TS//SCI — highest enforceable classification.
    TopSecret = 5,
}

impl ClassificationLevel {
    /// Short human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Restricted => "restricted",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
            Self::TopSecret => "top-secret",
        }
    }

    /// Parse a level from a case-insensitive string. Accepts both the
    /// short form (`"confidential"`) and common synonyms
    /// (`"tlp:amber"`, `"top-secret"`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "public" | "unclassified" | "clear" | "tlp:clear" | "tlp:white" | "white" => {
                Some(Self::Public)
            }
            "internal" | "tlp:green" | "green" => Some(Self::Internal),
            "restricted" | "fouo" | "cui" | "sbu" => Some(Self::Restricted),
            "confidential" | "tlp:amber" | "amber" | "tlp:amber+strict" | "amber+strict" => {
                Some(Self::Confidential)
            }
            "secret" | "tlp:red" | "red" | "noforn" => Some(Self::Secret),
            "top-secret" | "topsecret" | "top_secret" | "ts" | "ts//sci" => Some(Self::TopSecret),
            _ => None,
        }
    }
}

/// Default classification threshold at which [`crate::guard::InputGuard`]
/// blocks input: **Confidential** — covers corporate "Confidential",
/// TLP:AMBER, TLP:AMBER+STRICT, Attorney-Client Privilege, and everything
/// more sensitive.
pub const DEFAULT_BLOCK_LEVEL: ClassificationLevel = ClassificationLevel::Confidential;

/// Map a scanner `(category, sub_category)` pair to its
/// [`ClassificationLevel`], if the pattern represents a classification
/// marking at all. Non-classification patterns return `None`.
///
/// The mapping is deliberately exhaustive over the labels the scanner
/// emits so that a policy `block_at_or_above(Confidential)` catches
/// every "Confidential" synonym without the caller having to enumerate
/// sub-categories.
pub fn classify(category: &str, sub_category: &str) -> Option<ClassificationLevel> {
    // Traffic Light Protocol (FIRST.org TLP 2.0).
    if category == "Traffic Light Protocol" {
        return match sub_category {
            "TLP:CLEAR" | "TLP:WHITE" => Some(ClassificationLevel::Public),
            "TLP:GREEN" => Some(ClassificationLevel::Internal),
            "TLP:AMBER" | "TLP:AMBER+STRICT" => Some(ClassificationLevel::Confidential),
            "TLP:RED" => Some(ClassificationLevel::Secret),
            _ => None,
        };
    }

    // Government / IC markings.
    if category == "Data Classification Labels" {
        return match sub_category {
            "Top Secret" => Some(ClassificationLevel::TopSecret),
            "Secret Classification" | "NOFORN" => Some(ClassificationLevel::Secret),
            "Confidential Classification" => Some(ClassificationLevel::Confidential),
            "CUI" | "FOUO" | "SBU" | "LES" => Some(ClassificationLevel::Restricted),
            _ => None,
        };
    }

    // Corporate sharing-control markings.
    if category == "Corporate Classification" {
        return match sub_category {
            "Highly Confidential" => Some(ClassificationLevel::Secret),
            "Corporate Confidential" | "Eyes Only" | "Need to Know" => {
                Some(ClassificationLevel::Confidential)
            }
            "Restricted" | "Do Not Distribute" | "Proprietary" | "Embargoed" => {
                Some(ClassificationLevel::Restricted)
            }
            "Internal Only" => Some(ClassificationLevel::Internal),
            _ => None,
        };
    }

    // Attorney-client privilege + supervisory markings live under
    // "Legal Privileged Content" / "Financial Regulatory Labels".
    match (category, sub_category) {
        ("Legal Privileged Content", "Privileged and Confidential")
        | ("Legal Privileged Content", "Supervisory Confidential")
        | ("Legal Privileged Content", "Attorney-Client Privilege")
        | ("Legal Privileged Content", "Attorney Work Product")
        | ("Financial Regulatory Labels", "MNPI") => Some(ClassificationLevel::Confidential),
        _ => None,
    }
}

/// Find the highest classification level across a slice of matches.
/// Returns `None` if none of the matches carry a classification label.
pub fn highest_level<'a, I>(matches: I) -> Option<ClassificationLevel>
where
    I: IntoIterator<Item = &'a crate::models::Match>,
{
    matches
        .into_iter()
        .filter_map(|m| classify(&m.category, &m.sub_category))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_ordering() {
        assert!(ClassificationLevel::Public < ClassificationLevel::Internal);
        assert!(ClassificationLevel::Confidential < ClassificationLevel::Secret);
        assert!(ClassificationLevel::Secret < ClassificationLevel::TopSecret);
    }

    #[test]
    fn test_parse_canonical() {
        assert_eq!(
            ClassificationLevel::parse("confidential"),
            Some(ClassificationLevel::Confidential)
        );
        assert_eq!(
            ClassificationLevel::parse("TOP-SECRET"),
            Some(ClassificationLevel::TopSecret)
        );
    }

    #[test]
    fn test_parse_tlp_aliases() {
        assert_eq!(
            ClassificationLevel::parse("tlp:amber"),
            Some(ClassificationLevel::Confidential)
        );
        assert_eq!(
            ClassificationLevel::parse("TLP:AMBER+STRICT"),
            Some(ClassificationLevel::Confidential)
        );
        assert_eq!(
            ClassificationLevel::parse("tlp:red"),
            Some(ClassificationLevel::Secret)
        );
        assert_eq!(
            ClassificationLevel::parse("tlp:clear"),
            Some(ClassificationLevel::Public)
        );
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert_eq!(ClassificationLevel::parse("pickles"), None);
        assert_eq!(ClassificationLevel::parse(""), None);
    }

    #[test]
    fn test_classify_tlp_amber() {
        assert_eq!(
            classify("Traffic Light Protocol", "TLP:AMBER"),
            Some(ClassificationLevel::Confidential)
        );
        assert_eq!(
            classify("Traffic Light Protocol", "TLP:AMBER+STRICT"),
            Some(ClassificationLevel::Confidential)
        );
    }

    #[test]
    fn test_classify_government() {
        assert_eq!(
            classify("Data Classification Labels", "Top Secret"),
            Some(ClassificationLevel::TopSecret)
        );
        assert_eq!(
            classify("Data Classification Labels", "CUI"),
            Some(ClassificationLevel::Restricted)
        );
    }

    #[test]
    fn test_classify_corporate_confidential() {
        assert_eq!(
            classify("Corporate Classification", "Corporate Confidential"),
            Some(ClassificationLevel::Confidential)
        );
        assert_eq!(
            classify("Corporate Classification", "Highly Confidential"),
            Some(ClassificationLevel::Secret)
        );
    }

    #[test]
    fn test_classify_returns_none_for_non_label_categories() {
        assert_eq!(classify("Credit Card Numbers", "Visa"), None);
        assert_eq!(classify("Contact Information", "Email Address"), None);
    }

    #[test]
    fn test_default_block_level_is_confidential() {
        assert_eq!(DEFAULT_BLOCK_LEVEL, ClassificationLevel::Confidential);
    }
}
