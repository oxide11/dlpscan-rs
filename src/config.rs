//! Configuration file loading.
//!
//! Walks the directory tree looking for `pyproject.toml` (with `[tool.siphon]` section)
//! or `.siphonrc` (JSON). CLI args take precedence over file settings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Config struct
// ---------------------------------------------------------------------------

/// Loaded configuration values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub min_confidence: f64,
    #[serde(default)]
    pub require_context: bool,
    #[serde(default = "default_true")]
    pub deduplicate: bool,
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default = "default_context_backend")]
    pub context_backend: String,
    /// File extensions to block during pipeline scanning. Files with these
    /// extensions are flagged and skipped. Defaults to cryptographic certificate
    /// formats (DER, P12, PFX, P7M, etc.) via `DEFAULT_BLOCKED_EXTENSIONS`.
    #[serde(default = "default_blocked_extensions")]
    pub blocked_extensions: Vec<String>,
    /// When true, block files with unknown or opaque binary extensions
    /// (executables, compiled objects, media) and encrypted containers
    /// (GPG, KeePass, VeraCrypt). Default: false.
    #[serde(default)]
    pub block_unreadable: bool,
    /// Entropy scan mode for high-entropy secret detection.
    /// Values: "off" (default), "gated" (context keywords required),
    /// "assignment" (assignment pattern required), "all" (flag everything).
    #[serde(default)]
    pub entropy_scan: String,
}

fn default_true() -> bool {
    true
}
fn default_max_matches() -> usize {
    50_000
}
fn default_format() -> String {
    "text".to_string()
}
fn default_context_backend() -> String {
    "regex".to_string()
}
fn default_blocked_extensions() -> Vec<String> {
    crate::extractors::DEFAULT_BLOCKED_EXTENSIONS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_confidence: 0.0,
            require_context: false,
            deduplicate: true,
            max_matches: 50_000,
            format: "text".to_string(),
            categories: None,
            allowlist: vec![],
            ignore_patterns: vec![],
            ignore_paths: vec![],
            context_backend: "regex".to_string(),
            blocked_extensions: default_blocked_extensions(),
            block_unreadable: false,
            entropy_scan: "off".to_string(),
        }
    }
}

/// Apply environment variable overrides to a config.
///
/// Supported env vars:
/// - `DLPSCAN_MIN_CONFIDENCE` — minimum confidence threshold (0.0-1.0)
/// - `DLPSCAN_REQUIRE_CONTEXT` — require context keywords (true/false)
/// - `DLPSCAN_FORMAT` — output format (text/json/csv/sarif)
/// - `DLPSCAN_CATEGORIES` — comma-separated category filter
/// - `DLPSCAN_MAX_MATCHES` — maximum matches per scan
/// - `DLPSCAN_DEDUPLICATE` — deduplicate overlapping matches (true/false)
pub fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("DLPSCAN_MIN_CONFIDENCE") {
        if let Ok(v) = val.parse::<f64>() {
            config.min_confidence = v.clamp(0.0, 1.0);
        }
    }
    if let Ok(val) = std::env::var("DLPSCAN_REQUIRE_CONTEXT") {
        config.require_context = val == "true" || val == "1";
    }
    if let Ok(val) = std::env::var("DLPSCAN_FORMAT") {
        if ["text", "json", "csv", "sarif"].contains(&val.as_str()) {
            config.format = val;
        }
    }
    if let Ok(val) = std::env::var("DLPSCAN_CATEGORIES") {
        let cats: Vec<String> = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !cats.is_empty() {
            config.categories = Some(cats);
        }
    }
    if let Ok(val) = std::env::var("DLPSCAN_MAX_MATCHES") {
        if let Ok(v) = val.parse::<usize>() {
            config.max_matches = v;
        }
    }
    if let Ok(val) = std::env::var("DLPSCAN_DEDUPLICATE") {
        config.deduplicate = val != "false" && val != "0";
    }
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Walk up the directory tree looking for a config file.
/// Returns the first match: pyproject.toml (with [tool.siphon]) or .siphonrc.
pub fn find_config_file(start_dir: Option<&Path>) -> Option<PathBuf> {
    let start = start_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let mut dir = start.as_path();
    loop {
        // Check pyproject.toml
        let pyproject = dir.join("pyproject.toml");
        if pyproject.is_file() {
            if let Ok(content) = std::fs::read_to_string(&pyproject) {
                if content.contains("[tool.siphon]") {
                    return Some(pyproject);
                }
            }
        }

        // Check .siphonrc
        let rc = dir.join(".siphonrc");
        if rc.is_file() {
            return Some(rc);
        }

        // Check dlpscan.yaml / dlpscan.yml
        for yaml_name in &["dlpscan.yaml", "dlpscan.yml"] {
            let yaml_path = dir.join(yaml_name);
            if yaml_path.is_file() {
                return Some(yaml_path);
            }
        }

        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse [tool.siphon] section from pyproject.toml.
const MAX_CONFIG_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

fn parse_pyproject_toml(path: &Path) -> Result<Config, String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(format!("Config file too large: {} bytes", metadata.len()));
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let table: toml::Value = toml::from_str(&content).map_err(|e| e.to_string())?;

    let section = table
        .get("tool")
        .and_then(|t| t.get("siphon"))
        .ok_or_else(|| "No [tool.siphon] section found".to_string())?;

    let json_str = serde_json::to_string(section).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Parse .siphonrc JSON file.
fn parse_siphonrc(path: &Path) -> Result<Config, String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(format!("Config file too large: {} bytes", metadata.len()));
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Parse YAML config file (requires `yaml-config` feature).
#[cfg(feature = "yaml-config")]
fn parse_yaml_config(path: &Path) -> Result<Config, String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(format!("Config file too large: {} bytes", metadata.len()));
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let config: Config = serde_yaml::from_str(&content).map_err(|e| e.to_string())?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load configuration, merging defaults with file settings.
/// If `path` is provided, loads from that file. Otherwise auto-discovers.
pub fn load_config(path: Option<&str>, start_dir: Option<&Path>) -> Config {
    let config_path = match path {
        Some(p) => Some(PathBuf::from(p)),
        None => find_config_file(start_dir),
    };

    let Some(config_path) = config_path else {
        return Config::default();
    };

    let ext = config_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let name = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let result = if name == "pyproject.toml" || ext == "toml" {
        parse_pyproject_toml(&config_path)
    } else if ext == "yaml" || ext == "yml" {
        #[cfg(feature = "yaml-config")]
        {
            parse_yaml_config(&config_path)
        }
        #[cfg(not(feature = "yaml-config"))]
        {
            Err("YAML config requires the 'yaml-config' feature".to_string())
        }
    } else {
        parse_siphonrc(&config_path)
    };

    match result {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!("Failed to parse config file {:?}: {}", config_path, e);
            Config::default()
        }
    }
}

/// Merge two configs: `file` provides defaults, `overrides` takes precedence for non-default values.
pub fn merge_configs(file: &Config, overrides: &HashMap<String, serde_json::Value>) -> Config {
    let mut merged = file.clone();

    if let Some(v) = overrides.get("min_confidence").and_then(|v| v.as_f64()) {
        merged.min_confidence = v;
    }
    if let Some(v) = overrides.get("require_context").and_then(|v| v.as_bool()) {
        merged.require_context = v;
    }
    if let Some(v) = overrides.get("deduplicate").and_then(|v| v.as_bool()) {
        merged.deduplicate = v;
    }
    if let Some(v) = overrides.get("max_matches").and_then(|v| v.as_u64()) {
        merged.max_matches = v as usize;
    }
    if let Some(v) = overrides.get("format").and_then(|v| v.as_str()) {
        merged.format = v.to_string();
    }

    // Validate config values
    if merged.min_confidence.is_nan() || merged.min_confidence.is_infinite() {
        merged.min_confidence = 0.0;
    }
    merged.min_confidence = merged.min_confidence.clamp(0.0, 1.0);
    if merged.max_matches == 0 {
        merged.max_matches = 50_000;
    }

    merged
}

/// Parse an entropy_scan config string to an EntropyMode.
pub fn parse_entropy_mode(s: &str) -> crate::scanner::EntropyMode {
    match s.to_lowercase().as_str() {
        "gated" | "context" => crate::scanner::EntropyMode::Gated,
        "assignment" | "assign" => crate::scanner::EntropyMode::Assignment,
        "all" | "true" | "1" => crate::scanner::EntropyMode::All,
        _ => crate::scanner::EntropyMode::Off,
    }
}

// ---------------------------------------------------------------------------
// Config discovery and JSON persistence (used by CLI and TUI)
// ---------------------------------------------------------------------------

/// Find the first existing config file, or return the default path.
pub fn find_config_path() -> String {
    for name in &[".siphonrc", "siphon.json"] {
        if std::path::Path::new(name).exists() {
            return name.to_string();
        }
    }
    ".siphonrc".to_string()
}

/// Load config from a JSON file, falling back to defaults.
pub fn load_config_json(path: &str) -> Config {
    if let Ok(content) = std::fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Config::default()
    }
}

/// Save config to a JSON file.
pub fn save_config_json(path: &str, config: &Config) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.min_confidence, 0.0);
        assert!(!config.require_context);
        assert!(config.deduplicate);
        assert_eq!(config.max_matches, 50_000);
        assert_eq!(config.format, "text");
        assert_eq!(config.context_backend, "regex");
    }

    #[test]
    fn test_parse_siphonrc() {
        let dir = tempfile::tempdir().unwrap();
        let rc_path = dir.path().join(".siphonrc");
        let mut f = std::fs::File::create(&rc_path).unwrap();
        writeln!(
            f,
            r#"{{"min_confidence": 0.5, "require_context": true, "format": "json"}}"#
        )
        .unwrap();

        let config = parse_siphonrc(&rc_path).unwrap();
        assert_eq!(config.min_confidence, 0.5);
        assert!(config.require_context);
        assert_eq!(config.format, "json");
    }

    #[test]
    fn test_parse_pyproject_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("pyproject.toml");
        let mut f = std::fs::File::create(&toml_path).unwrap();
        writeln!(
            f,
            r#"[tool.siphon]
min_confidence = 0.7
require_context = true
max_matches = 100
"#
        )
        .unwrap();

        let config = parse_pyproject_toml(&toml_path).unwrap();
        assert_eq!(config.min_confidence, 0.7);
        assert!(config.require_context);
        assert_eq!(config.max_matches, 100);
    }

    #[test]
    fn test_find_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let rc_path = dir.path().join(".siphonrc");
        std::fs::write(&rc_path, "{}").unwrap();

        let found = find_config_file(Some(dir.path()));
        assert!(found.is_some());
        assert_eq!(found.unwrap(), rc_path);
    }

    #[test]
    fn test_load_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = load_config(None, Some(dir.path()));
        // Should return defaults
        assert_eq!(config.min_confidence, 0.0);
    }

    #[test]
    fn test_config_default_blocked_extensions() {
        let config = Config::default();
        assert!(!config.blocked_extensions.is_empty());
        assert!(config.blocked_extensions.contains(&"der".to_string()));
        assert!(config.blocked_extensions.contains(&"p12".to_string()));
        assert!(config.blocked_extensions.contains(&"pfx".to_string()));
    }

    #[test]
    fn test_config_default_block_unreadable_off() {
        let config = Config::default();
        assert!(!config.block_unreadable);
    }
}
