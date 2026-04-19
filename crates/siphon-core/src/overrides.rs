//! Pattern overrides — deployable layer on top of the compile-time
//! pattern set without rebuilding any crate.
//!
//! Both siphon-api and siphon-fs read the same JSON file (mounted from
//! a Kubernetes ConfigMap in the lab; supplied via `SIPHON_OVERRIDES_PATH`
//! environment variable in dev) at startup and consult it during scans.
//! When the admin console commits an edit (Phase 4), the apply endpoint
//! writes the file and triggers a rolling restart of both Deployments
//! (Phase 6) so every detection pod converges on the new ruleset
//! together.
//!
//! Phase 3a (this file) defines the on-disk shape, the loader, and the
//! lookup helpers. Phase 3b wires the scanner to actually skip
//! `disabled_patterns`. Phases 3c and 3d add field overrides and
//! custom categories respectively.
//!
//! The overrides file is *additive* — base patterns always remain
//! restorable by deleting the relevant entry. Removing the file
//! entirely returns the engine to its compile-time defaults.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Current schema version. Bumped on incompatible shape changes; the
/// loader rejects unknown versions instead of silently ignoring fields
/// it doesn't understand.
pub const CURRENT_VERSION: u32 = 0;

/// Composite key for a pattern in the registry. Used as the lookup key
/// for `disabled_patterns` and `pattern_overrides` so the same shape is
/// reused throughout. Two-string newtype rather than a tuple for clarity
/// at call sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternKey {
    pub category: String,
    pub sub_category: String,
}

impl PatternKey {
    pub fn new(category: impl Into<String>, sub_category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            sub_category: sub_category.into(),
        }
    }

    /// Wire format used for `pattern_overrides` map keys —
    /// "<category>/<sub_category>" — chosen so the JSON file stays
    /// readable in version control diffs.
    pub fn to_wire(&self) -> String {
        format!("{}/{}", self.category, self.sub_category)
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        let (cat, sub) = s.split_once('/')?;
        Some(Self::new(cat, sub))
    }
}

/// Per-pattern field overrides. Every field is Optional so a partial
/// override (e.g. just bumping `specificity`) can sit alongside the
/// compile-time defaults for everything else.
///
/// Honoured by the scanner today (Phase 3c):
///   · specificity        — replaces pattern_specificity() at scoring time
///   · context_required   — replaces is_context_required() at gating time
///
/// Loaded but not yet applied (lands in Phase 3d alongside custom
/// categories, since they share the runtime regex/AC compilation
/// machinery):
///   · regex              — runtime regex recompilation
///   · case_insensitive   — same compilation path
///   · context_keywords   — runtime AC matcher rebuild
///   · proximity_chars    — context distance lookup
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternOverride {
    pub regex: Option<String>,
    pub specificity: Option<f64>,
    pub context_required: Option<bool>,
    pub case_insensitive: Option<bool>,
    pub context_keywords: Option<Vec<String>>,
    pub proximity_chars: Option<u32>,
}

/// One pattern inside a custom category. Mirrors the shape the admin
/// console's NewPatternModal already writes to localStorage so the
/// Phase 4 apply path can serialise localStorage entries straight into
/// this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub sub_category: String,
    pub regex: String,
    pub specificity: f64,
    pub context_required: bool,
    pub case_insensitive: bool,
    pub context_keywords: Vec<String>,
    pub proximity_chars: u32,
}

impl Default for CustomPattern {
    fn default() -> Self {
        Self {
            sub_category: String::new(),
            regex: String::new(),
            specificity: 0.5,
            context_required: false,
            case_insensitive: true,
            context_keywords: Vec::new(),
            proximity_chars: 50,
        }
    }
}

/// A custom category authored by an analyst. Phase 3d wires the
/// scanner to register these as additional patterns at startup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomCategory {
    pub name: String,
    pub group: String,
    pub description: String,
    pub patterns: Vec<CustomPattern>,
}

/// Top-level overrides document. Designed for human edits in git as
/// well as machine writes from the admin console — every collection is
/// optional + defaults to empty so a partially-filled document still
/// loads cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternOverrides {
    /// Schema version. Loader rejects values it doesn't recognise.
    pub version: u32,
    /// Patterns to skip at scan time, by composite key.
    pub disabled_patterns: Vec<PatternKey>,
    /// Field-level overrides keyed by "<category>/<sub_category>".
    pub pattern_overrides: HashMap<String, PatternOverride>,
    /// Analyst-authored categories with their own patterns.
    pub custom_categories: Vec<CustomCategory>,
}

/// Errors surfaced by the loader. Kept simple — the caller logs and
/// either falls back to defaults or refuses to start, depending on
/// readiness-probe semantics chosen per pod.
#[derive(Debug)]
pub enum LoadError {
    /// File could not be opened. The caller decides whether 'no file'
    /// means 'use defaults' or 'fail readiness' — Phase 3b lets it
    /// be the former so dev-mode doesn't need a file at all.
    Io(std::io::Error),
    /// File parsed as JSON but failed schema validation.
    Parse(String),
    /// Schema version doesn't match what this build understands.
    Version { found: u32, expected: u32 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "io: {e}"),
            LoadError::Parse(e) => write!(f, "parse: {e}"),
            LoadError::Version { found, expected } => {
                write!(f, "schema version {found} not supported (expected {expected})")
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl PatternOverrides {
    /// Empty overrides — the scanner behaves exactly as it did before
    /// Phase 3 when this is the active set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load + validate from a JSON file. Caller decides how to react
    /// to errors.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let bytes = std::fs::read(path.as_ref()).map_err(LoadError::Io)?;
        Self::from_bytes(&bytes)
    }

    /// Convenience: try the file, fall back to empty + log a warning
    /// when it's not present. Useful in dev where the file may not
    /// exist; the lab always has it via the ConfigMap mount.
    pub fn from_file_or_empty(path: impl AsRef<Path>) -> Self {
        match Self::from_file(path.as_ref()) {
            Ok(o) => o,
            Err(LoadError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Self::empty(),
            Err(e) => {
                eprintln!(
                    "siphon overrides: failed to load {} — {} · falling back to compile-time defaults",
                    path.as_ref().display(),
                    e
                );
                Self::empty()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LoadError> {
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|e| LoadError::Parse(e.to_string()))?;
        if parsed.version != CURRENT_VERSION {
            return Err(LoadError::Version {
                found: parsed.version,
                expected: CURRENT_VERSION,
            });
        }
        Ok(parsed)
    }

    /// O(1) check used by the scanner emit path. Build the underlying
    /// HashSet once at construction time when overrides are loaded.
    pub fn is_disabled(&self, category: &str, sub_category: &str) -> bool {
        // Linear scan is fine for a handful of disabled entries;
        // callers that need O(1) should call `disabled_set()` once and
        // keep the HashSet around. Phase 3b's scanner integration
        // builds the set up-front.
        self.disabled_patterns
            .iter()
            .any(|k| k.category == category && k.sub_category == sub_category)
    }

    /// Pre-compute a HashSet for repeated lookups.
    pub fn disabled_set(&self) -> HashSet<(String, String)> {
        self.disabled_patterns
            .iter()
            .map(|k| (k.category.clone(), k.sub_category.clone()))
            .collect()
    }

    pub fn override_for(&self, category: &str, sub_category: &str) -> Option<&PatternOverride> {
        let key = format!("{category}/{sub_category}");
        self.pattern_overrides.get(&key)
    }

    /// Pre-compute a `(category, sub_category) → PatternOverride` map
    /// that the scanner consults on every match. Built once at startup
    /// when overrides are loaded; cloned via Arc on each scan.
    pub fn override_lookup(&self) -> HashMap<(String, String), PatternOverride> {
        self.pattern_overrides
            .iter()
            .filter_map(|(k, v)| {
                let (cat, sub) = k.split_once('/')?;
                Some(((cat.to_string(), sub.to_string()), v.clone()))
            })
            .collect()
    }

    /// Counts surfaced via /v1/version + the admin console for an
    /// at-a-glance "what's actually applied" indicator.
    pub fn summary(&self) -> OverridesSummary {
        OverridesSummary {
            disabled_patterns: self.disabled_patterns.len(),
            pattern_overrides: self.pattern_overrides.len(),
            custom_categories: self.custom_categories.len(),
            custom_patterns: self
                .custom_categories
                .iter()
                .map(|c| c.patterns.len())
                .sum(),
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OverridesSummary {
    pub disabled_patterns: usize,
    pub pattern_overrides: usize,
    pub custom_categories: usize,
    pub custom_patterns: usize,
    pub version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_safe() {
        let o = PatternOverrides::empty();
        assert!(!o.is_disabled("Email Address", "personal"));
        assert!(o.override_for("Email Address", "personal").is_none());
        assert_eq!(o.summary().disabled_patterns, 0);
    }

    #[test]
    fn parses_minimal_document() {
        let json = r#"{"version":0}"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(o.version, 0);
        assert!(o.disabled_patterns.is_empty());
    }

    #[test]
    fn rejects_future_versions() {
        let json = r#"{"version":99}"#;
        let err = PatternOverrides::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, LoadError::Version { found: 99, expected: 0 }));
    }

    #[test]
    fn disabled_lookup_round_trip() {
        let json = r#"{
            "version":0,
            "disabled_patterns":[
                {"category":"Email Address","sub_category":"personal"}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert!(o.is_disabled("Email Address", "personal"));
        assert!(!o.is_disabled("Email Address", "corporate"));
    }

    #[test]
    fn pattern_override_lookup_round_trip() {
        let json = r#"{
            "version":0,
            "pattern_overrides":{
                "PII/email.v1":{"specificity":0.95,"context_required":true}
            }
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let ov = o.override_for("PII", "email.v1").unwrap();
        assert_eq!(ov.specificity, Some(0.95));
        assert_eq!(ov.context_required, Some(true));
        assert_eq!(ov.regex, None);
    }

    #[test]
    fn custom_categories_summary() {
        let json = r#"{
            "version":0,
            "custom_categories":[
                {"name":"MYORG","group":"SECRET","patterns":[
                    {"sub_category":"emp.id","regex":"EMP-\\d+","specificity":0.7}
                ]}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let s = o.summary();
        assert_eq!(s.custom_categories, 1);
        assert_eq!(s.custom_patterns, 1);
    }

    #[test]
    fn pattern_key_wire_round_trip() {
        let k = PatternKey::new("PCI", "visa.v3");
        assert_eq!(k.to_wire(), "PCI/visa.v3");
        assert_eq!(PatternKey::from_wire("PCI/visa.v3"), Some(k));
        assert_eq!(PatternKey::from_wire("malformed"), None);
    }

    #[test]
    fn missing_file_falls_back_to_empty() {
        let o = PatternOverrides::from_file_or_empty("/nonexistent/path/x.json");
        assert_eq!(o.summary().disabled_patterns, 0);
    }
}
