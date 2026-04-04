//! Data Masking Profiles — named configuration bundles.
//!
//! Built-in profiles for PCI-DSS, HIPAA, GDPR, SOC2, etc.
//! Profiles can be serialized to/from JSON for persistence.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::guard::{Action, InputGuard, Mode, Preset};

// ---------------------------------------------------------------------------
// MaskingProfile
// ---------------------------------------------------------------------------

/// A named masking configuration bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub min_confidence: f64,
    #[serde(default)]
    pub require_context: bool,
    #[serde(default = "default_redaction_char")]
    pub redaction_char: String,
    #[serde(default)]
    pub confidence_overrides: HashMap<String, f64>,
}

fn default_action() -> String { "redact".to_string() }
fn default_mode() -> String { "denylist".to_string() }
fn default_redaction_char() -> String { "X".to_string() }

impl MaskingProfile {
    /// Create an InputGuard from this profile's settings.
    pub fn to_guard(&self) -> InputGuard {
        let presets: Vec<Preset> = self
            .presets
            .iter()
            .filter_map(|s| match s.as_str() {
                "pii" => Some(Preset::Pii),
                "pci_dss" | "pci-dss" => Some(Preset::PciDss),
                "credentials" => Some(Preset::Credentials),
                "healthcare" => Some(Preset::Healthcare),
                "contact_info" | "contact-info" => Some(Preset::ContactInfo),
                _ => None,
            })
            .collect();

        let action = match self.action.as_str() {
            "reject" => Action::Reject,
            "redact" => Action::Redact,
            "flag" => Action::Flag,
            "tokenize" => Action::Tokenize,
            "obfuscate" => Action::Obfuscate,
            _ => Action::Redact,
        };

        let mode = match self.mode.as_str() {
            "allowlist" => Mode::Allowlist,
            _ => Mode::Denylist,
        };

        let redaction_char = self
            .redaction_char
            .chars()
            .next()
            .unwrap_or('X');

        let mut guard = InputGuard::new()
            .with_presets(presets)
            .with_action(action)
            .with_mode(mode)
            .with_min_confidence(self.min_confidence)
            .with_require_context(self.require_context)
            .with_redaction_char(redaction_char);

        if !self.categories.is_empty() {
            let cats: HashSet<String> = self.categories.iter().cloned().collect();
            guard = guard.with_categories(cats);
        }

        guard
    }
}

// ---------------------------------------------------------------------------
// Built-in profiles
// ---------------------------------------------------------------------------

fn builtin_profiles() -> Vec<MaskingProfile> {
    vec![
        MaskingProfile {
            name: "PCI_PRODUCTION".to_string(),
            description: "PCI-DSS production — reject on detection".to_string(),
            presets: vec!["pci_dss".into()],
            categories: vec![],
            action: "reject".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.7,
            require_context: true,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "PCI_DEVELOPMENT".to_string(),
            description: "PCI-DSS development — obfuscate with fake data".to_string(),
            presets: vec!["pci_dss".into()],
            categories: vec![],
            action: "obfuscate".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.3,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "HIPAA_STRICT".to_string(),
            description: "HIPAA strict — reject healthcare data".to_string(),
            presets: vec!["healthcare".into()],
            categories: vec![],
            action: "reject".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.5,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "HIPAA_REDACT".to_string(),
            description: "HIPAA redact — redact healthcare data".to_string(),
            presets: vec!["healthcare".into()],
            categories: vec![],
            action: "redact".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.0,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "GDPR_COMPLIANCE".to_string(),
            description: "GDPR — tokenize PII and contact info".to_string(),
            presets: vec!["pii".into(), "contact_info".into()],
            categories: vec![],
            action: "tokenize".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.0,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "SOC2_SECRETS".to_string(),
            description: "SOC2 — reject credentials and secrets".to_string(),
            presets: vec!["credentials".into()],
            categories: vec![],
            action: "reject".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.0,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "FULL_SCAN".to_string(),
            description: "Full scan — flag all categories".to_string(),
            presets: vec!["pii".into(), "pci_dss".into(), "credentials".into(), "healthcare".into(), "contact_info".into()],
            categories: vec![],
            action: "flag".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.0,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "DEVELOPMENT".to_string(),
            description: "Development — obfuscate all with low threshold".to_string(),
            presets: vec!["pii".into(), "pci_dss".into(), "credentials".into(), "healthcare".into(), "contact_info".into()],
            categories: vec![],
            action: "obfuscate".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.3,
            require_context: false,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
        MaskingProfile {
            name: "CI_PIPELINE".to_string(),
            description: "CI/CD pipeline — reject with context required".to_string(),
            presets: vec!["pii".into(), "pci_dss".into(), "credentials".into(), "healthcare".into(), "contact_info".into()],
            categories: vec![],
            action: "reject".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.5,
            require_context: true,
            redaction_char: "X".to_string(),
            confidence_overrides: HashMap::new(),
        },
    ]
}

// ---------------------------------------------------------------------------
// ProfileRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry of masking profiles.
pub struct ProfileRegistry {
    profiles: Mutex<HashMap<String, MaskingProfile>>,
}

impl ProfileRegistry {
    /// Create a new registry pre-populated with built-in profiles.
    pub fn new() -> Self {
        let mut map = HashMap::new();
        for p in builtin_profiles() {
            map.insert(p.name.clone(), p);
        }
        Self {
            profiles: Mutex::new(map),
        }
    }

    /// Register or replace a profile.
    pub fn register(&self, profile: MaskingProfile) {
        let mut map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(profile.name.clone(), profile);
    }

    /// Get a profile by name.
    pub fn get(&self, name: &str) -> Option<MaskingProfile> {
        let map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        map.get(name).cloned()
    }

    /// List registered profile names (sorted).
    pub fn list(&self) -> Vec<String> {
        let map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<String> = map.keys().cloned().collect();
        names.sort();
        names
    }

    /// Remove a profile.
    pub fn remove(&self, name: &str) -> bool {
        let mut map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(name).is_some()
    }

    /// Load profiles from a JSON file (array or object).
    pub fn load_from_file(&self, path: &str) -> Result<(), String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let profiles: Vec<MaskingProfile> = if value.is_array() {
            serde_json::from_value(value).map_err(|e| e.to_string())?
        } else if value.is_object() {
            // Single profile
            vec![serde_json::from_value(value).map_err(|e| e.to_string())?]
        } else {
            return Err("Expected JSON array or object".to_string());
        };

        let mut map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        for p in profiles {
            map.insert(p.name.clone(), p);
        }
        Ok(())
    }

    /// Save all profiles to a JSON file.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let map = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        let profiles: Vec<&MaskingProfile> = map.values().collect();
        let json = serde_json::to_string_pretty(&profiles).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Module-level API
// ---------------------------------------------------------------------------

static DEFAULT_REGISTRY: once_cell::sync::Lazy<ProfileRegistry> =
    once_cell::sync::Lazy::new(ProfileRegistry::new);

/// Look up a profile in the default registry.
pub fn get_profile(name: &str) -> Option<MaskingProfile> {
    DEFAULT_REGISTRY.get(name)
}

/// List all profile names in the default registry.
pub fn list_profiles() -> Vec<String> {
    DEFAULT_REGISTRY.list()
}

/// Register a profile in the default registry.
pub fn register_profile(profile: MaskingProfile) {
    DEFAULT_REGISTRY.register(profile);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_profiles_exist() {
        let names = list_profiles();
        assert!(names.contains(&"PCI_PRODUCTION".to_string()));
        assert!(names.contains(&"HIPAA_STRICT".to_string()));
        assert!(names.contains(&"GDPR_COMPLIANCE".to_string()));
        assert!(names.contains(&"SOC2_SECRETS".to_string()));
        assert!(names.contains(&"FULL_SCAN".to_string()));
        assert!(names.contains(&"DEVELOPMENT".to_string()));
        assert!(names.contains(&"CI_PIPELINE".to_string()));
    }

    #[test]
    fn test_get_profile() {
        let p = get_profile("PCI_PRODUCTION").unwrap();
        assert_eq!(p.action, "reject");
        assert_eq!(p.min_confidence, 0.7);
        assert!(p.require_context);
    }

    #[test]
    fn test_to_guard() {
        let p = get_profile("FULL_SCAN").unwrap();
        let _guard = p.to_guard(); // should not panic
    }

    #[test]
    fn test_custom_profile() {
        let registry = ProfileRegistry::new();
        registry.register(MaskingProfile {
            name: "CUSTOM".to_string(),
            description: "Test".to_string(),
            presets: vec!["pii".into()],
            categories: vec![],
            action: "flag".to_string(),
            mode: "denylist".to_string(),
            min_confidence: 0.8,
            require_context: false,
            redaction_char: "*".to_string(),
            confidence_overrides: HashMap::new(),
        });
        assert!(registry.get("CUSTOM").is_some());
        assert!(registry.remove("CUSTOM"));
        assert!(registry.get("CUSTOM").is_none());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let path_str = path.to_str().unwrap();

        let registry = ProfileRegistry::new();
        registry.save_to_file(path_str).unwrap();

        let registry2 = ProfileRegistry::new();
        registry2.load_from_file(path_str).unwrap();
        assert!(!registry2.list().is_empty());
    }
}
