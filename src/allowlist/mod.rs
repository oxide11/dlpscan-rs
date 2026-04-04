//! Allowlist for suppressing known-good matches.

use crate::models::Match;

/// Allowlist configuration for suppressing specific matches.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Exact text values to suppress.
    texts: Vec<String>,
    /// Sub-category patterns to skip entirely.
    patterns: Vec<String>,
    /// File path globs to skip.
    paths: Vec<String>,
}

impl Allowlist {
    /// Create a new allowlist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add exact text values to suppress.
    pub fn with_texts(mut self, texts: Vec<String>) -> Self {
        self.texts = texts;
        self
    }

    /// Add sub-category patterns to skip.
    pub fn with_patterns(mut self, patterns: Vec<String>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Add file path globs to skip.
    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = paths;
        self
    }

    /// Check if a match should be suppressed.
    pub fn is_suppressed(&self, m: &Match) -> bool {
        // Check exact text matches
        if self.texts.iter().any(|t| t == &m.text) {
            return true;
        }

        // Check sub-category patterns
        if self
            .patterns
            .iter()
            .any(|p| p == &m.sub_category || p == &m.category)
        {
            return true;
        }

        false
    }

    /// Check if a file path should be skipped.
    pub fn should_skip_path(&self, path: &str) -> bool {
        for glob_pat in &self.paths {
            if path.contains(glob_pat) || glob_matches(glob_pat, path) {
                return true;
            }
        }
        false
    }

    /// Filter matches, keeping only non-suppressed ones.
    pub fn filter_matches(&self, matches: Vec<Match>) -> Vec<Match> {
        matches.into_iter().filter(|m| !self.is_suppressed(m)).collect()
    }

    /// Whether any rules are configured.
    pub fn is_empty(&self) -> bool {
        self.texts.is_empty() && self.patterns.is_empty() && self.paths.is_empty()
    }
}

const MAX_GLOB_RECURSION: usize = 1000;

/// Simple glob matching (supports * and ?).
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    glob_match_recursive(&pattern_chars, &text_chars, 0, 0, 0)
}

fn glob_match_recursive(pattern: &[char], text: &[char], pi: usize, ti: usize, depth: usize) -> bool {
    if depth > MAX_GLOB_RECURSION {
        return false; // Bail out to prevent DoS
    }
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    if pattern[pi] == '*' {
        // Try matching * with zero or more characters
        for i in ti..=text.len() {
            if glob_match_recursive(pattern, text, pi + 1, i, depth + 1) {
                return true;
            }
        }
        return false;
    }

    if ti == text.len() {
        return false;
    }

    if pattern[pi] == '?' || pattern[pi] == text[ti] {
        return glob_match_recursive(pattern, text, pi + 1, ti + 1, depth + 1);
    }

    false
}

/// Check for inline ignore directive in a line.
pub fn has_inline_ignore(line: &str) -> bool {
    line.contains("dlpscan:ignore")
}
