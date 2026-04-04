//! Policy engine — TOML-based policy evaluation for DLP scanning.
//!
//! Policies define scan configuration, per-category rules, audit settings,
//! and rate limiting. The PolicyEngine applies these policies to text.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::guard::{Action, InputGuard, Mode, Preset, ScanResult};
use crate::models::Match;

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// A per-category override rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub match_categories: Vec<String>,
    #[serde(default)]
    pub match_sub_categories: Option<Vec<String>>,
    #[serde(default = "default_action_str")]
    pub action: String,
    #[serde(default)]
    pub min_confidence: f64,
}

/// Complete DLP scanning policy loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub scan: ScanPolicyConfig,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub audit: Option<AuditPolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Scan configuration block within a policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanPolicyConfig {
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_action_str")]
    pub action: String,
    #[serde(default = "default_mode_str")]
    pub mode: String,
    #[serde(default)]
    pub min_confidence: f64,
    #[serde(default)]
    pub require_context: bool,
    #[serde(default = "default_redaction_char")]
    pub redaction_char: String,
}

/// Audit configuration within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub file: Option<String>,
}

/// Rate limit configuration within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_max_requests")]
    pub max_requests: u64,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: usize,
}

fn default_version() -> String {
    "1".to_string()
}
fn default_action_str() -> String {
    "flag".to_string()
}
fn default_mode_str() -> String {
    "denylist".to_string()
}
fn default_redaction_char() -> String {
    "X".to_string()
}
fn default_max_requests() -> u64 {
    100
}
fn default_window_seconds() -> u64 {
    60
}
fn default_max_payload() -> usize {
    10 * 1024 * 1024
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

/// Applies a Policy to scan text via InputGuard.
pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Access the underlying policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Create an InputGuard from the policy's scan configuration.
    pub fn create_guard(&self) -> InputGuard {
        let scan = &self.policy.scan;

        let presets: Vec<Preset> = scan
            .presets
            .iter()
            .filter_map(|s| parse_preset(s))
            .collect();

        let mut guard = InputGuard::new().with_presets(presets);

        if !scan.categories.is_empty() {
            let cats: HashSet<String> = scan.categories.iter().cloned().collect();
            guard = guard.with_categories(cats);
        }

        guard = guard.with_action(parse_action(&scan.action));
        guard = guard.with_mode(parse_mode(&scan.mode));
        guard = guard.with_min_confidence(scan.min_confidence);
        guard = guard.with_require_context(scan.require_context);

        if let Some(ch) = scan.redaction_char.chars().next() {
            guard = guard.with_redaction_char(ch);
        }

        guard
    }

    /// Scan text using the policy. Rules override the default action.
    pub fn scan(&self, text: &str) -> crate::Result<ScanResult> {
        // Use FLAG internally so rules take precedence
        let scan = &self.policy.scan;
        let presets: Vec<Preset> = scan
            .presets
            .iter()
            .filter_map(|s| parse_preset(s))
            .collect();

        let mut guard = InputGuard::new().with_presets(presets).with_action(Action::Flag);

        if !scan.categories.is_empty() {
            let cats: HashSet<String> = scan.categories.iter().cloned().collect();
            guard = guard.with_categories(cats);
        }

        guard = guard.with_mode(parse_mode(&scan.mode));
        guard = guard.with_min_confidence(scan.min_confidence);
        guard = guard.with_require_context(scan.require_context);

        let result = guard.scan(text)?;
        Ok(self.apply_rules(result))
    }

    /// Apply per-category rules to override actions on findings.
    pub fn apply_rules(&self, result: ScanResult) -> ScanResult {
        if self.policy.rules.is_empty() {
            return result;
        }

        let mut redact_findings: Vec<&Match> = Vec::new();
        let default_action = parse_action(&self.policy.scan.action);

        for finding in &result.findings {
            let mut matched_action = default_action;

            for rule in &self.policy.rules {
                if rule_matches(rule, finding) {
                    matched_action = parse_action(&rule.action);
                    break;
                }
            }

            if matched_action == Action::Redact {
                redact_findings.push(finding);
            }
        }

        let redacted_text = if !redact_findings.is_empty() {
            let ch = self
                .policy
                .scan
                .redaction_char
                .chars()
                .next()
                .unwrap_or('X');
            Some(redact_text(&result.text, &redact_findings, ch))
        } else {
            result.redacted_text
        };

        ScanResult {
            redacted_text,
            ..result
        }
    }
}

fn rule_matches(rule: &PolicyRule, finding: &Match) -> bool {
    if !rule.match_categories.iter().any(|c| c == &finding.category) {
        return false;
    }
    if let Some(ref subs) = rule.match_sub_categories {
        if !subs.iter().any(|s| s == &finding.sub_category) {
            return false;
        }
    }
    if finding.confidence < rule.min_confidence {
        return false;
    }
    true
}

fn redact_text(text: &str, findings: &[&Match], ch: char) -> String {
    let mut result = text.to_string();
    let mut sorted: Vec<&&Match> = findings.iter().collect();
    sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));

    for finding in sorted {
        let (start, end) = finding.span;
        if start < result.len() && end <= result.len() {
            let replacement: String = std::iter::repeat(ch).take(end - start).collect();
            result.replace_range(start..end, &replacement);
        }
    }
    result
}

fn parse_preset(s: &str) -> Option<Preset> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "pci_dss" => Some(Preset::PciDss),
        "ssn_sin" => Some(Preset::SsnSin),
        "pii" => Some(Preset::Pii),
        "pii_strict" => Some(Preset::PiiStrict),
        "credentials" => Some(Preset::Credentials),
        "financial" => Some(Preset::Financial),
        "healthcare" => Some(Preset::Healthcare),
        "contact_info" => Some(Preset::ContactInfo),
        _ => None,
    }
}

fn parse_action(s: &str) -> Action {
    match s.to_lowercase().as_str() {
        "reject" => Action::Reject,
        "redact" => Action::Redact,
        "tokenize" => Action::Tokenize,
        "obfuscate" => Action::Obfuscate,
        _ => Action::Flag,
    }
}

fn parse_mode(s: &str) -> Mode {
    match s.to_lowercase().as_str() {
        "allowlist" => Mode::Allowlist,
        _ => Mode::Denylist,
    }
}

// ---------------------------------------------------------------------------
// Loading Functions
// ---------------------------------------------------------------------------

/// Load policy from TOML string.
pub fn load_policy_from_str(toml_str: &str) -> crate::Result<Policy> {
    let policy: Policy = toml::from_str(toml_str)?;
    Ok(policy)
}

const MAX_POLICY_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Load policy from file.
pub fn load_policy(path: &str) -> crate::Result<Policy> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_POLICY_FILE_SIZE {
        return Err(crate::DlpError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Policy file too large: {} bytes", metadata.len()),
        )));
    }
    let content = fs::read_to_string(path)?;
    load_policy_from_str(&content)
}

/// Load all policies from a directory (.toml files).
pub fn load_policies_from_dir(dir_path: &str) -> crate::Result<HashMap<String, Policy>> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        return Err(crate::DlpError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{dir_path} is not a directory"),
        )));
    }

    let mut policies = HashMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.extension().map(|e| e == "toml").unwrap_or(false) {
            match fs::read_to_string(&file_path).and_then(|s| {
                toml::from_str::<Policy>(&s)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            }) {
                Ok(policy) => {
                    policies.insert(policy.name.clone(), policy);
                }
                Err(e) => {
                    tracing::warn!("Skipping {:?}: {}", file_path, e);
                }
            }
        }
    }
    Ok(policies)
}

/// Validate a policy and return list of warnings/errors.
pub fn validate_policy(policy: &Policy) -> Vec<String> {
    let mut warnings = Vec::new();

    if policy.version != "1" {
        warnings.push(format!("Unknown version '{}', expected '1'", policy.version));
    }
    if policy.name.is_empty() {
        warnings.push("Policy name is empty".to_string());
    }

    let valid_actions = ["reject", "redact", "flag", "tokenize", "obfuscate"];
    let valid_modes = ["denylist", "allowlist"];

    if !valid_actions.contains(&policy.scan.action.to_lowercase().as_str()) {
        warnings.push(format!("Invalid scan action '{}'", policy.scan.action));
    }
    if !valid_modes.contains(&policy.scan.mode.to_lowercase().as_str()) {
        warnings.push(format!("Invalid scan mode '{}'", policy.scan.mode));
    }
    if !(0.0..=1.0).contains(&policy.scan.min_confidence) {
        warnings.push(format!(
            "min_confidence {} out of range [0.0, 1.0]",
            policy.scan.min_confidence
        ));
    }
    if policy.scan.redaction_char.len() > 1 {
        warnings.push("redaction_char should be a single character".to_string());
    }

    for rule in &policy.rules {
        if rule.name.is_empty() {
            warnings.push("Rule has empty name".to_string());
        }
        if rule.match_categories.is_empty() {
            warnings.push(format!("Rule '{}' has no match_categories", rule.name));
        }
        if !valid_actions.contains(&rule.action.to_lowercase().as_str()) {
            warnings.push(format!(
                "Rule '{}' has invalid action '{}'",
                rule.name, rule.action
            ));
        }
    }

    warnings
}

impl std::fmt::Display for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PolicyEngine(policy='{}', rules={})",
            self.policy.name,
            self.policy.rules.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_policy_from_toml() {
        let toml = r#"
name = "test-policy"
description = "A test policy"
version = "1"

[scan]
presets = ["pci_dss"]
action = "redact"
mode = "denylist"
min_confidence = 0.5

[[rules]]
name = "block-ssn"
match_categories = ["North America - United States"]
match_sub_categories = ["USA SSN"]
action = "reject"
min_confidence = 0.8
"#;
        let policy = load_policy_from_str(toml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.scan.presets, vec!["pci_dss"]);
        assert_eq!(policy.scan.action, "redact");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "block-ssn");
        assert_eq!(policy.rules[0].action, "reject");
    }

    #[test]
    fn test_validate_policy() {
        let policy = Policy {
            name: "".to_string(),
            description: String::new(),
            version: "2".to_string(),
            scan: ScanPolicyConfig {
                action: "invalid".to_string(),
                mode: "bad".to_string(),
                min_confidence: 2.0,
                ..Default::default()
            },
            rules: vec![PolicyRule {
                name: "".to_string(),
                match_categories: vec![],
                match_sub_categories: None,
                action: "nope".to_string(),
                min_confidence: 0.0,
            }],
            audit: None,
            rate_limit: None,
        };

        let warnings = validate_policy(&policy);
        assert!(warnings.len() >= 5);
    }

    #[test]
    fn test_parse_preset() {
        assert_eq!(parse_preset("pci-dss"), Some(Preset::PciDss));
        assert_eq!(parse_preset("PCI_DSS"), Some(Preset::PciDss));
        assert_eq!(parse_preset("credentials"), Some(Preset::Credentials));
        assert_eq!(parse_preset("unknown"), None);
    }

    #[test]
    fn test_rule_matching() {
        let rule = PolicyRule {
            name: "test".to_string(),
            match_categories: vec!["Credit Card Numbers".to_string()],
            match_sub_categories: Some(vec!["Visa".to_string()]),
            action: "reject".to_string(),
            min_confidence: 0.5,
        };

        let finding = Match {
            text: "4111111111111111".to_string(),
            category: "Credit Card Numbers".to_string(),
            sub_category: "Visa".to_string(),
            has_context: false,
            confidence: 0.8,
            span: (0, 16),
            context_required: false,
        };

        assert!(rule_matches(&rule, &finding));

        let low_conf = Match {
            confidence: 0.3,
            ..finding.clone()
        };
        assert!(!rule_matches(&rule, &low_conf));
    }
}
