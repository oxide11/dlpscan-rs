//! Server-side redaction of matched values.
//!
//! # Why this is not a UI concern
//!
//! The console renders matched values masked, with a reveal control. That was
//! cosmetic: the endpoints returned the value in the clear, so the SSN was
//! already in the JSON, in browser memory, in devtools, and readable by any
//! extension on the page. A mask over data the server already handed out is a
//! courtesy, not a control.
//!
//! So redaction happens here, keyed on the caller's permissions, and revealing
//! is an explicit request that the server can refuse and *must* record. That
//! ordering is also what makes the audit trail honest — a client-side toggle
//! can never be audited, because the client can simply not tell you.
//!
//! # Fail closed
//!
//! [`DataClass::of`] defaults to [`DataClass::Pii`]. A category nobody has
//! classified yet is masked, not exposed. Adding a pattern category should
//! never widen what is visible as a side effect.

use siphon::rbac::{role_has_permission, Permission, Role};

/// What kind of sensitive data a finding's category holds.
///
/// PCI is split out because PCI-DSS gives cardholder data its own regulatory
/// basis and a narrower need-to-know than personal data generally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    /// Cardholder data — PAN, track data, expiry. Needs `UnmaskPci`.
    Pci,
    /// Everything else sensitive. Needs `UnmaskPii`.
    Pii,
    /// Not personal data at all: classification markings like "CONFIDENTIAL",
    /// regulatory labels. Masking these would hide the very thing the finding
    /// is reporting, and there is nothing to protect.
    Public,
}

/// Categories that carry cardholder data under PCI-DSS.
const PCI_CATEGORIES: &[&str] = &[
    "Credit Card Numbers",
    "Primary Account Numbers",
    "Card Expiration Dates",
    "Card Track Data",
    "PCI Sensitive Data",
];

/// Categories whose matched value *is* a label rather than personal data.
/// Redacting "CONFIDENTIAL" to "CON…IAL" helps nobody.
const PUBLIC_CATEGORIES: &[&str] = &[
    "Data Classification Labels",
    "Corporate Classification",
    "Privacy Classification",
    "Financial Regulatory Labels",
];

impl DataClass {
    pub fn of(category: &str) -> Self {
        if PCI_CATEGORIES.contains(&category) {
            Self::Pci
        } else if PUBLIC_CATEGORIES.contains(&category) {
            Self::Public
        } else {
            // Fail closed. An unclassified category is sensitive until
            // someone decides otherwise.
            Self::Pii
        }
    }

    /// The permission needed to see this class in the clear.
    pub fn permission(self) -> Option<Permission> {
        match self {
            Self::Pci => Some(Permission::UnmaskPci),
            Self::Pii => Some(Permission::UnmaskPii),
            Self::Public => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pci => "pci",
            Self::Pii => "pii",
            Self::Public => "public",
        }
    }
}

/// Which classes the caller asked to see in the clear.
///
/// Parsed from `?unmask=pii,pci`. Absent means "mask everything", which is the
/// default for every endpoint — a caller who wants the value has to say so,
/// and that request is what gets audited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnmaskRequest {
    pub pii: bool,
    pub pci: bool,
}

impl UnmaskRequest {
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::default();
        };
        let mut req = Self::default();
        for part in raw.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "pii" => req.pii = true,
                "pci" => req.pci = true,
                // `all` is a convenience for an operator with both
                // permissions; it grants nothing extra on its own.
                "all" => {
                    req.pii = true;
                    req.pci = true;
                }
                _ => {}
            }
        }
        req
    }

    pub fn any(self) -> bool {
        self.pii || self.pci
    }

    fn wants(self, class: DataClass) -> bool {
        match class {
            DataClass::Pci => self.pci,
            DataClass::Pii => self.pii,
            DataClass::Public => true,
        }
    }
}

/// Redact a matched value: first three and last three characters survive.
///
/// Enough to correlate two sightings of the same value and to eyeball whether
/// a match looks plausible, without disclosing it. Short values are masked
/// entirely — `redacted("4111")` must not be most of a number.
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len().max(4));
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 3..].iter().collect();
    format!("{head}{}{tail}", "•".repeat(chars.len() - 6))
}

/// The outcome of applying masking to one value.
pub struct Decision {
    /// What to send.
    pub text: Option<String>,
    /// True when the caller received the value in the clear *because they
    /// asked and were allowed*. Drives the audit event; `Public` values do
    /// not count, since nothing was disclosed.
    pub disclosed: bool,
}

/// Decide what a caller may see for one finding.
///
/// Three inputs, in order of authority: the class of the data, whether the
/// role holds the matching permission, and whether the caller actually asked.
/// A caller who holds `UnmaskPii` still gets masked output unless they request
/// it — so an ordinary page load discloses nothing and generates no audit
/// noise, and every disclosure is a deliberate act.
pub fn apply(value: Option<&str>, category: &str, role: Role, req: UnmaskRequest) -> Decision {
    let Some(value) = value else {
        return Decision {
            text: None,
            disclosed: false,
        };
    };
    let class = DataClass::of(category);

    let permitted = match class.permission() {
        None => true,
        Some(p) => role_has_permission(role, p),
    };

    if permitted && req.wants(class) {
        Decision {
            text: Some(value.to_string()),
            disclosed: class != DataClass::Public,
        }
    } else {
        Decision {
            text: Some(redact(value)),
            disclosed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unclassified_category_is_masked() {
        // The property that matters most: adding a pattern category must not
        // widen what is visible just because nobody classified it.
        assert_eq!(DataClass::of("Some Brand New Category"), DataClass::Pii);
    }

    #[test]
    fn cardholder_categories_need_the_pci_permission() {
        assert_eq!(DataClass::of("Credit Card Numbers"), DataClass::Pci);
        assert_eq!(DataClass::of("Card Track Data"), DataClass::Pci);
        assert_eq!(
            DataClass::of("Credit Card Numbers").permission(),
            Some(Permission::UnmaskPci)
        );
    }

    #[test]
    fn classification_labels_are_not_redacted() {
        // "CONFIDENTIAL" masked to "CON…IAL" hides the finding's whole point.
        let d = apply(
            Some("CONFIDENTIAL"),
            "Data Classification Labels",
            Role::Viewer,
            UnmaskRequest::default(),
        );
        assert_eq!(d.text.as_deref(), Some("CONFIDENTIAL"));
        assert!(!d.disclosed, "a public label is not a disclosure");
    }

    #[test]
    fn holding_the_permission_is_not_enough_without_asking() {
        // An ordinary page load must disclose nothing, so that an audit row
        // means someone deliberately looked.
        let d = apply(
            Some("219-09-9999"),
            "Personal Identifiers",
            Role::Admin,
            UnmaskRequest::default(),
        );
        assert_eq!(d.text.as_deref(), Some("219•••••999"));
        assert!(!d.disclosed);
    }

    #[test]
    fn asking_without_the_permission_still_masks() {
        let d = apply(
            Some("4111111111111111"),
            "Credit Card Numbers",
            // Analyst holds UnmaskPii but deliberately not UnmaskPci.
            Role::Analyst,
            UnmaskRequest {
                pii: true,
                pci: true,
            },
        );
        assert_eq!(d.text.as_deref(), Some("411••••••••••111"));
        assert!(!d.disclosed);
    }

    #[test]
    fn a_responder_asking_for_pci_gets_it_and_it_is_recorded() {
        let d = apply(
            Some("4111111111111111"),
            "Credit Card Numbers",
            Role::Responder,
            UnmaskRequest {
                pii: false,
                pci: true,
            },
        );
        assert_eq!(d.text.as_deref(), Some("4111111111111111"));
        assert!(d.disclosed, "a real disclosure must be auditable");
    }

    #[test]
    fn pii_and_pci_are_independent() {
        // Analyst asking only for PII gets PII, and PCI stays masked in the
        // same response.
        let req = UnmaskRequest {
            pii: true,
            pci: false,
        };
        let pii = apply(
            Some("219-09-9999"),
            "Personal Identifiers",
            Role::Analyst,
            req,
        );
        let pci = apply(
            Some("4111111111111111"),
            "Credit Card Numbers",
            Role::Analyst,
            req,
        );
        assert_eq!(pii.text.as_deref(), Some("219-09-9999"));
        assert_eq!(pci.text.as_deref(), Some("411••••••••••111"));
    }

    #[test]
    fn short_values_are_masked_whole() {
        // Keeping head and tail of a short value leaves most of it intact.
        assert_eq!(redact("4111"), "••••");
        assert_eq!(redact("12345678"), "••••••••");
        assert!(!redact("12345678").contains('1'));
    }

    #[test]
    fn parsing_is_permissive_but_grants_nothing_by_itself() {
        assert_eq!(UnmaskRequest::parse(None), UnmaskRequest::default());
        assert_eq!(
            UnmaskRequest::parse(Some(" PII , junk ")),
            UnmaskRequest {
                pii: true,
                pci: false
            }
        );
        assert_eq!(
            UnmaskRequest::parse(Some("all")),
            UnmaskRequest {
                pii: true,
                pci: true
            }
        );
    }
}
