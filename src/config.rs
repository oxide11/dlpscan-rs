//! Configuration file loading.
//!
//! Walks the directory tree looking for `pyproject.toml` (with `[tool.dlpscan]` section)
//! or `.dlpscanrc` (JSON). CLI args take precedence over file settings.

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
        }
    }
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Walk up the directory tree looking for a config file.
/// Returns the first match: pyproject.toml (with [tool.dlpscan]) or .dlpscanrc.
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
                if content.contains("[tool.dlpscan]") {
                    return Some(pyproject);
                }
            }
        }

        // Check .dlpscanrc
        let rc = dir.join(".dlpscanrc");
        if rc.is_file() {
            return Some(rc);
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

/// Parse [tool.dlpscan] section from pyproject.toml.
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
        .and_then(|t| t.get("dlpscan"))
        .ok_or_else(|| "No [tool.dlpscan] section found".to_string())?;

    let json_str = serde_json::to_string(section).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Parse .dlpscanrc JSON file.
fn parse_dlpscanrc(path: &Path) -> Result<Config, String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(format!("Config file too large: {} bytes", metadata.len()));
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
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
    } else {
        parse_dlpscanrc(&config_path)
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
    fn test_parse_dlpscanrc() {
        let dir = tempfile::tempdir().unwrap();
        let rc_path = dir.path().join(".dlpscanrc");
        let mut f = std::fs::File::create(&rc_path).unwrap();
        writeln!(
            f,
            r#"{{"min_confidence": 0.5, "require_context": true, "format": "json"}}"#
        )
        .unwrap();

        let config = parse_dlpscanrc(&rc_path).unwrap();
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
            r#"[tool.dlpscan]
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
        let rc_path = dir.path().join(".dlpscanrc");
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
}
