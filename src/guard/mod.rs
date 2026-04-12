//! InputGuard — high-level API for scanning and sanitizing inputs.
//!
//! Provides preset-based scanning, multiple actions (reject, redact, flag,
//! tokenize, obfuscate), and RBAC-controlled token vaults.

mod obfuscate;
mod presets;
mod tokenize;

pub use obfuscate::{obfuscate_match, obfuscate_matches, set_obfuscation_seed};
pub use presets::{Preset, PRESET_CATEGORIES};
pub use tokenize::TokenVault;

use std::collections::HashSet;

use crate::allowlist::Allowlist;
use crate::classification::{self, ClassificationLevel, DEFAULT_BLOCK_LEVEL};
use crate::models::Match;
use crate::scanner::{self, ScanConfig};

/// Action to take when sensitive data is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Raise an error.
    Reject,
    /// Replace sensitive data with redaction characters.
    Redact,
    /// Return findings but leave text unchanged.
    Flag,
    /// Replace with reversible tokens.
    Tokenize,
    /// Replace with realistic fake data.
    Obfuscate,
}

/// Scanning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block the listed categories (default).
    Denylist,
    /// Allow only the listed categories.
    Allowlist,
}

use serde::{Deserialize, Serialize};

/// Pattern categories that carry classification / sharing-control
/// markings. The guard force-includes these when a classification
/// block policy is active so the threshold cannot be bypassed by
/// choosing a preset that omits them.
const CLASSIFICATION_CATEGORIES: &[&str] = &[
    "Traffic Light Protocol",
    "Data Classification Labels",
    "Corporate Classification",
    "Legal Privileged Content",
    "Financial Regulatory Labels",
];

/// Result of an InputGuard scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Original input text.
    pub text: String,
    /// Whether the text is clean (no findings).
    pub is_clean: bool,
    /// List of sensitive data findings.
    pub findings: Vec<Match>,
    /// Transformed text (redacted/tokenized/obfuscated), if applicable.
    pub redacted_text: Option<String>,
    /// Set of categories found.
    pub categories_found: HashSet<String>,
    /// Whether the scan was truncated.
    pub scan_truncated: bool,
    /// Highest classification level among the findings, if any
    /// classification or TLP label was detected. Lets downstream
    /// policy layers apply their own thresholds on top of the
    /// guard's built-in block policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_level: Option<ClassificationLevel>,
}

impl ScanResult {
    /// Number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

/// InputGuard builder and scanner.
pub struct InputGuard {
    presets: Vec<Preset>,
    categories: Option<HashSet<String>>,
    mode: Mode,
    action: Action,
    min_confidence: f64,
    require_context: bool,
    redaction_char: char,
    allowlist: Option<Allowlist>,
    baseline_only: bool,
    /// Minimum classification level that triggers a blocking error.
    /// `Some(level)` — any finding at or above `level` returns
    /// `DlpError::ClassificationPolicyViolation` regardless of `action`.
    /// `None` — classification labels pass through as ordinary findings.
    /// Defaults to [`DEFAULT_BLOCK_LEVEL`] (Confidential / TLP:AMBER).
    block_classification_at_or_above: Option<ClassificationLevel>,
}

impl InputGuard {
    /// Create a new InputGuard with default settings.
    ///
    /// By default the guard blocks any input containing a
    /// classification label at or above `Confidential` (which
    /// includes TLP:AMBER and TLP:AMBER+STRICT). This is an
    /// enterprise-safe default — to allow confidential content
    /// through, call [`Self::with_block_classification`] with a
    /// higher threshold or disable blocking entirely with
    /// [`Self::without_classification_blocking`].
    pub fn new() -> Self {
        Self {
            presets: Vec::new(),
            categories: None,
            mode: Mode::Denylist,
            action: Action::Flag,
            min_confidence: 0.0,
            require_context: false,
            redaction_char: 'X',
            allowlist: None,
            baseline_only: false,
            block_classification_at_or_above: Some(DEFAULT_BLOCK_LEVEL),
        }
    }

    /// Set presets.
    pub fn with_presets(mut self, presets: Vec<Preset>) -> Self {
        self.presets = presets;
        self
    }

    /// Set categories to scan.
    pub fn with_categories(mut self, categories: HashSet<String>) -> Self {
        self.categories = Some(categories);
        self
    }

    /// Set scanning mode.
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Set action on detection.
    pub fn with_action(mut self, action: Action) -> Self {
        self.action = action;
        self
    }

    /// Set minimum confidence threshold.
    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Set context requirement.
    pub fn with_require_context(mut self, require: bool) -> Self {
        self.require_context = require;
        self
    }

    /// Set redaction character.
    pub fn with_redaction_char(mut self, ch: char) -> Self {
        self.redaction_char = ch;
        self
    }

    /// Set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Enable baseline-only mode: only run high-confidence (always-run) patterns.
    /// Skips all context-gated patterns for faster scanning with lower recall.
    pub fn with_baseline_only(mut self, baseline_only: bool) -> Self {
        self.baseline_only = baseline_only;
        self
    }

    /// Set the classification threshold at which the guard returns
    /// a blocking [`crate::errors::DlpError::ClassificationPolicyViolation`]
    /// error.
    ///
    /// Any finding mapped to a [`ClassificationLevel`] at or above
    /// `level` causes `scan()` to return an error regardless of the
    /// configured [`Action`]. Default: `Confidential`.
    ///
    /// ```
    /// use dlpscan::guard::InputGuard;
    /// use dlpscan::classification::ClassificationLevel;
    ///
    /// let guard = InputGuard::new()
    ///     .with_block_classification(ClassificationLevel::Secret);
    /// ```
    pub fn with_block_classification(mut self, level: ClassificationLevel) -> Self {
        self.block_classification_at_or_above = Some(level);
        self
    }

    /// Disable the classification blocking policy entirely.
    /// Classification and TLP labels will still be detected and
    /// reported as findings, but will not cause `scan()` to fail.
    pub fn without_classification_blocking(mut self) -> Self {
        self.block_classification_at_or_above = None;
        self
    }

    /// Resolve effective categories based on presets and mode.
    fn resolve_categories(&self) -> Option<HashSet<String>> {
        let mut cats = HashSet::new();

        // Add preset categories
        for preset in &self.presets {
            if let Some(preset_cats) = PRESET_CATEGORIES.get(preset) {
                cats.extend(preset_cats.iter().map(|s| s.to_string()));
            }
        }

        // Add explicit categories
        if let Some(ref explicit) = self.categories {
            cats.extend(explicit.iter().cloned());
        }

        if cats.is_empty() {
            return None; // Scan all
        }

        // When classification blocking is active we must always scan
        // the classification categories, even if the active presets
        // don't include them — otherwise the guard could let a
        // TLP:AMBER doc through simply because it was called with
        // `Preset::PciDss` only.
        if self.block_classification_at_or_above.is_some() {
            for c in CLASSIFICATION_CATEGORIES {
                cats.insert((*c).to_string());
            }
        }

        Some(cats)
    }

    /// Scan text and return a ScanResult.
    pub fn scan(&self, text: &str) -> crate::Result<ScanResult> {
        let config = ScanConfig {
            categories: self.resolve_categories(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            baseline_only: self.baseline_only,
            ..Default::default()
        };

        let mut findings = scanner::scan_text_with_config(text, &config)?;

        // Apply allowlist
        if let Some(ref allowlist) = self.allowlist {
            findings.retain(|m| !allowlist.is_suppressed(m));
        }

        // Classification policy: enforced BEFORE action processing so
        // a blocked doc can't be tokenized or obfuscated and leaked as
        // "clean" output. The threshold default is Confidential
        // (TLP:AMBER and above) — see InputGuard::new.
        let classification_level = classification::highest_level(findings.iter());
        if let (Some(threshold), Some(level)) =
            (self.block_classification_at_or_above, classification_level)
        {
            if level >= threshold {
                let labels: Vec<String> = findings
                    .iter()
                    .filter(|m| {
                        classification::classify(&m.category, &m.sub_category)
                            .map(|l| l >= threshold)
                            .unwrap_or(false)
                    })
                    .map(|m| format!("{}: {}", m.category, m.sub_category))
                    .collect();
                return Err(crate::errors::DlpError::ClassificationPolicyViolation {
                    level,
                    threshold,
                    labels,
                });
            }
        }

        let is_clean = findings.is_empty();
        let categories_found: HashSet<String> =
            findings.iter().map(|m| m.category.clone()).collect();

        let redacted_text = match self.action {
            Action::Redact => Some(self.redact_text(text, &findings)),
            Action::Obfuscate => Some(obfuscate_matches(text, &findings)),
            Action::Tokenize => Some(self.redact_text(text, &findings)),
            _ => None,
        };

        let result = ScanResult {
            text: text.to_string(),
            is_clean,
            findings,
            redacted_text,
            categories_found,
            scan_truncated: false,
            classification_level,
        };

        if self.action == Action::Reject && !result.is_clean {
            return Err(crate::errors::DlpError::SensitiveDataDetected {
                finding_count: result.finding_count(),
                categories: result.categories_found.iter().cloned().collect(),
            });
        }

        Ok(result)
    }

    /// Quick boolean check — returns true if text is clean.
    pub fn check(&self, text: &str) -> bool {
        self.scan(text).map(|r| r.is_clean).unwrap_or(false)
    }

    /// Return redacted text.
    pub fn sanitize(&self, text: &str) -> crate::Result<String> {
        let config = ScanConfig {
            categories: self.resolve_categories(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            baseline_only: self.baseline_only,
            ..Default::default()
        };
        let findings = scanner::scan_text_with_config(text, &config)?;
        Ok(self.redact_text(text, &findings))
    }

    /// Redact findings in text.
    fn redact_text(&self, text: &str, findings: &[Match]) -> String {
        if findings.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();
        // Process findings from end to start to maintain positions
        let mut sorted: Vec<&Match> = findings.iter().collect();
        sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));

        for finding in sorted {
            let (start, end) = finding.span;
            if start < result.len()
                && end <= result.len()
                && result.is_char_boundary(start)
                && result.is_char_boundary(end)
            {
                let span_byte_len = end - start;
                let redaction_byte_len = self.redaction_char.len_utf8();
                // Fill the exact byte span to preserve string offsets for
                // earlier (lower-index) findings processed afterward.
                let full_chars = span_byte_len / redaction_byte_len;
                let remainder = span_byte_len % redaction_byte_len;
                let mut replacement: String = std::iter::repeat(self.redaction_char)
                    .take(full_chars)
                    .collect();
                // Pad any remaining bytes with spaces to keep exact byte length
                for _ in 0..remainder {
                    replacement.push(' ');
                }
                result.replace_range(start..end, &replacement);
            }
        }

        result
    }
}

impl Default for InputGuard {
    fn default() -> Self {
        Self::new()
    }
}
