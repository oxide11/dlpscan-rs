//! Exact Data Match (EDM) — HMAC-SHA256 based matching against registered sensitive values.
//!
//! Register known sensitive values (SSNs, account numbers, etc.) by category.
//! Values are hashed with HMAC-SHA256 and stored as hex digests. During scanning,
//! text is tokenized and each token is checked against the hash set.

use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A match found by exact data matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDMMatch {
    pub value_hash: String,
    pub category: String,
    pub span: (usize, usize),
    pub matched_text: String,
    pub confidence: f64,
}

impl EDMMatch {
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "value_hash": self.value_hash,
            "category": self.category,
            "span": [self.span.0, self.span.1],
            "matched_text": self.matched_text,
            "confidence": self.confidence,
        })
    }
}

// ---------------------------------------------------------------------------
// Tokenizers
// ---------------------------------------------------------------------------

/// A tokenizer extracts candidate strings and their spans from text.
pub type Tokenizer = fn(&str) -> Vec<(String, (usize, usize))>;

/// Extract numeric sequences (digits, hyphens, dots, spaces) 5-20 chars.
fn tokenize_numeric(text: &str) -> Vec<(String, (usize, usize))> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d[\d\-. ]{3,18}\d").unwrap());
    RE.find_iter(text)
        .map(|m| (m.as_str().to_string(), (m.start(), m.end())))
        .collect()
}

/// Extract email addresses.
fn tokenize_emails(text: &str) -> Vec<(String, (usize, usize))> {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap());
    RE.find_iter(text)
        .map(|m| (m.as_str().to_string(), (m.start(), m.end())))
        .collect()
}

/// Extract individual words (1-grams).
fn tokenize_words_1(text: &str) -> Vec<(String, (usize, usize))> {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\w+\b").unwrap());
    RE.find_iter(text)
        .map(|m| (m.as_str().to_string(), (m.start(), m.end())))
        .collect()
}

/// Extract word bigrams.
fn tokenize_words_2(text: &str) -> Vec<(String, (usize, usize))> {
    let words: Vec<_> = tokenize_words_1(text);
    if words.len() < 2 {
        return vec![];
    }
    words
        .windows(2)
        .map(|w| {
            let combined = format!("{} {}", w[0].0, w[1].0);
            let span = (w[0].1 .0, w[1].1 .1);
            (combined, span)
        })
        .collect()
}

/// Extract word trigrams.
fn tokenize_words_3(text: &str) -> Vec<(String, (usize, usize))> {
    let words: Vec<_> = tokenize_words_1(text);
    if words.len() < 3 {
        return vec![];
    }
    words
        .windows(3)
        .map(|w| {
            let combined = format!("{} {} {}", w[0].0, w[1].0, w[2].0);
            let span = (w[0].1 .0, w[2].1 .1);
            (combined, span)
        })
        .collect()
}

/// Built-in tokenizer registry.
fn builtin_tokenizers() -> HashMap<&'static str, Tokenizer> {
    let mut m: HashMap<&'static str, Tokenizer> = HashMap::new();
    m.insert("numeric", tokenize_numeric);
    m.insert("email", tokenize_emails);
    m.insert("word_1gram", tokenize_words_1);
    m.insert("word_2gram", tokenize_words_2);
    m.insert("word_3gram", tokenize_words_3);
    m
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Normalize a value for consistent hashing.
fn normalize_value(value: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let normalized: String = value.nfkc().collect();
    let lower = normalized.to_lowercase();
    let trimmed = lower.trim();
    // Remove separators
    static SEP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\s\-./()]+").unwrap());
    SEP_RE.replace_all(trimmed, "").to_string()
}

// ---------------------------------------------------------------------------
// ExactDataMatcher
// ---------------------------------------------------------------------------

/// Hash-based exact data matcher.
#[derive(Clone)]
pub struct ExactDataMatcher {
    salt: Vec<u8>,
    hashes: HashMap<String, HashSet<String>>, // category → set of hex digests
    tokenizer_names: Vec<String>,
    tokenizers: HashMap<String, Tokenizer>,
}

impl ExactDataMatcher {
    /// Create a new matcher with optional salt and tokenizer names.
    pub fn new(salt: Option<&[u8]>, tokenizer_names: Option<Vec<&str>>) -> Self {
        let salt = salt.map(|s| s.to_vec()).unwrap_or_else(|| {
            let mut buf = vec![0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        });

        let names = tokenizer_names
            .map(|v| v.iter().map(|s| s.to_string()).collect())
            .unwrap_or_else(|| vec!["numeric".to_string(), "email".to_string()]);

        Self {
            salt,
            hashes: HashMap::new(),
            tokenizer_names: names,
            tokenizers: builtin_tokenizers()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    /// Compute HMAC-SHA256 hex digest for a value.
    fn hmac_hash(&self, value: &str) -> String {
        let normalized = normalize_value(value);
        let mut mac = HmacSha256::new_from_slice(&self.salt).expect("HMAC accepts any key length");
        mac.update(normalized.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Register sensitive values under a category. Returns total hash count.
    ///
    /// Warns when total hash count exceeds [`Self::MAX_CONSTANT_TIME_HASHES`],
    /// as constant-time scan performance degrades linearly with hash count.
    pub fn register_values(&mut self, category: &str, values: &[&str]) -> usize {
        let hashes: Vec<String> = values.iter().map(|v| self.hmac_hash(v)).collect();
        let entry = self.hashes.entry(category.to_string()).or_default();
        for hash in hashes {
            entry.insert(hash);
        }
        let cat_len = entry.len();
        let total = self.total_hashes();
        if total > Self::MAX_CONSTANT_TIME_HASHES {
            tracing::warn!(
                total_hashes = total,
                max = Self::MAX_CONSTANT_TIME_HASHES,
                "EDM hash count exceeds recommended maximum for constant-time scan — scan performance will degrade"
            );
        }
        cat_len
    }

    /// List registered categories.
    pub fn categories(&self) -> Vec<&str> {
        self.hashes.keys().map(|s| s.as_str()).collect()
    }

    /// Total hash count across all categories.
    pub fn total_hashes(&self) -> usize {
        self.hashes.values().map(|s| s.len()).sum()
    }

    /// Maximum total hashes across all categories for constant-time scan.
    /// Beyond this threshold, the O(tokens * hashes) scan becomes a DoS risk.
    const MAX_CONSTANT_TIME_HASHES: usize = 50_000;

    /// Constant-time comparison of two byte slices. Returns 1 if equal,
    /// 0 otherwise. A length mismatch is folded into the diff accumulator
    /// rather than producing an early branch — both arms of the comparison
    /// execute the same number of byte operations regardless of length.
    #[inline]
    fn ct_eq_bytes(a: &[u8], b: &[u8]) -> u8 {
        // Length difference becomes a non-zero contribution to diff.
        let len_diff = (a.len() ^ b.len()) as u8;
        let n = a.len().min(b.len());
        let mut diff = len_diff;
        for i in 0..n {
            diff |= a[i] ^ b[i];
        }
        // 1 iff diff == 0, branch-free
        ((diff as u16).wrapping_sub(1) >> 8) as u8 & 1
    }

    /// Scan text for registered values.
    ///
    /// Constant-time across category membership and registered-value count:
    /// every category and every hash is iterated regardless of the
    /// `categories` filter or whether an earlier hash already matched.
    /// Filtered-out categories still execute the full per-hash loop and
    /// XOR their result against zero, preventing timing inference of
    /// which categories are registered or how many entries each holds.
    pub fn scan(&self, text: &str, categories: Option<&HashSet<String>>) -> Vec<EDMMatch> {
        let mut matches = Vec::new();

        // Collect tokens using configured tokenizers
        let mut tokens: Vec<(String, (usize, usize))> = Vec::new();
        for name in &self.tokenizer_names {
            if let Some(tokenizer) = self.tokenizers.get(name.as_str()) {
                tokens.extend(tokenizer(text));
            }
        }

        for (token_text, span) in &tokens {
            let hash = self.hmac_hash(token_text);
            let hash_bytes = hash.as_bytes();

            for (category, hash_set) in &self.hashes {
                // Branch-free mask: 1 if this category is allowed, 0 otherwise.
                // We compute the mask but ALWAYS iterate the hash set, so the
                // observable work is identical for filtered and unfiltered
                // categories.
                let allowed_mask: u8 = match categories {
                    Some(cats) => cats.contains(category) as u8,
                    None => 1,
                };

                let mut found_acc: u8 = 0;
                for registered in hash_set.iter() {
                    found_acc |= Self::ct_eq_bytes(registered.as_bytes(), hash_bytes);
                }
                // Zero out matches in disallowed categories without branching
                // on the filter result.
                let found = (found_acc & allowed_mask) == 1;

                if found {
                    matches.push(EDMMatch {
                        value_hash: hash.clone(),
                        category: category.clone(),
                        span: *span,
                        matched_text: token_text.clone(),
                        confidence: 1.0,
                    });
                }
            }
        }

        matches
    }

    /// Check if a specific value is registered (constant-time comparison).
    ///
    /// Iterates every category and every hash regardless of the `category`
    /// argument — when a category is named, non-matching categories still
    /// execute the full comparison and XOR their result into a discarded
    /// mask. Closes the timing channel that would otherwise reveal which
    /// categories exist and how many values each contains.
    pub fn check_value(&self, value: &str, category: Option<&str>) -> bool {
        let hash = self.hmac_hash(value);
        let hash_bytes = hash.as_bytes();
        let mut found_acc: u8 = 0;
        for (cat_name, set) in &self.hashes {
            let allowed_mask: u8 = match category {
                Some(target) => (cat_name == target) as u8,
                None => 1,
            };
            let mut cat_found: u8 = 0;
            for registered in set.iter() {
                cat_found |= Self::ct_eq_bytes(registered.as_bytes(), hash_bytes);
            }
            found_acc |= cat_found & allowed_mask;
        }
        found_acc == 1
    }

    /// Clear hashes for a category, or all categories.
    pub fn clear(&mut self, category: Option<&str>) {
        match category {
            Some(cat) => {
                self.hashes.remove(cat);
            }
            None => {
                self.hashes.clear();
            }
        }
    }

    /// Save matcher state to JSON file.
    /// Rejects symlink paths to prevent symlink race attacks.
    pub fn save(&self, path: &str) -> Result<(), String> {
        if std::path::Path::new(path).is_symlink() {
            return Err(format!("Refusing to write EDM state to symlink: {path}"));
        }
        use base64::Engine;
        let data = serde_json::json!({
            "salt": base64::engine::general_purpose::STANDARD.encode(&self.salt),
            "hashes": self.hashes.iter().map(|(k, v)| {
                (k.clone(), v.iter().cloned().collect::<Vec<_>>())
            }).collect::<HashMap<String, Vec<String>>>(),
            "tokenizers": self.tokenizer_names,
        });
        let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("Failed to open {path}: {e}"))?
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("Failed to open {path}: {e}"))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write {path}: {e}"))?;
        Ok(())
    }

    /// Maximum state file size (100 MB).
    const MAX_STATE_FILE_SIZE: u64 = 100 * 1024 * 1024;

    /// Load matcher state from JSON file.
    pub fn load(path: &str) -> Result<Self, String> {
        use base64::Engine;
        let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        if meta.len() > Self::MAX_STATE_FILE_SIZE {
            return Err(format!(
                "EDM state file too large: {} bytes (max {})",
                meta.len(),
                Self::MAX_STATE_FILE_SIZE
            ));
        }
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let data: serde_json::Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let salt = data["salt"].as_str().ok_or("Missing salt")?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt)
            .map_err(|e| e.to_string())?;

        let mut hashes: HashMap<String, HashSet<String>> = HashMap::new();
        if let Some(obj) = data["hashes"].as_object() {
            for (k, v) in obj {
                let set: HashSet<String> = v
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect();
                hashes.insert(k.clone(), set);
            }
        }

        let tokenizer_names: Vec<String> = data["tokenizers"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|s| s.as_str().map(|s| s.to_string()))
            .collect();

        Ok(Self {
            salt,
            hashes,
            tokenizer_names,
            tokenizers: builtin_tokenizers()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_value() {
        assert_eq!(normalize_value("  123-45-6789 "), "123456789");
        assert_eq!(normalize_value("Hello World"), "helloworld");
    }

    #[test]
    fn test_register_and_check() {
        let mut matcher = ExactDataMatcher::new(Some(b"test-salt-12345678901234567890ab"), None);
        matcher.register_values("ssn", &["123-45-6789", "987-65-4321"]);
        assert_eq!(matcher.total_hashes(), 2);
        assert!(matcher.check_value("123-45-6789", Some("ssn")));
        assert!(matcher.check_value("123456789", Some("ssn"))); // normalized form
        assert!(!matcher.check_value("000-00-0000", Some("ssn")));
    }

    #[test]
    fn test_scan() {
        let mut matcher = ExactDataMatcher::new(Some(b"test-salt-12345678901234567890ab"), None);
        matcher.register_values("ssn", &["123-45-6789"]);

        let text = "My SSN is 123-45-6789 and that's it";
        let results = matcher.scan(text, None);
        assert!(!results.is_empty());
        assert_eq!(results[0].category, "ssn");
        assert_eq!(results[0].confidence, 1.0);
    }

    #[test]
    fn test_clear() {
        let mut matcher = ExactDataMatcher::new(Some(b"test-salt-12345678901234567890ab"), None);
        matcher.register_values("ssn", &["123-45-6789"]);
        assert_eq!(matcher.total_hashes(), 1);
        matcher.clear(None);
        assert_eq!(matcher.total_hashes(), 0);
    }

    #[test]
    fn test_tokenize_numeric() {
        let tokens = tokenize_numeric("SSN: 123-45-6789 end");
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].0, "123-45-6789");
    }

    #[test]
    fn test_tokenize_emails() {
        let tokens = tokenize_emails("Contact user@example.com for info");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, "user@example.com");
    }
}
