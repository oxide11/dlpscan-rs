//! Token vault for reversible tokenization.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum entries per vault to prevent unbounded memory growth.
const MAX_VAULT_ENTRIES: usize = 100_000;

/// Reversible token vault — maps sensitive values to deterministic tokens.
pub struct TokenVault {
    prefix: String,
    secret: Vec<u8>,
    forward: HashMap<String, String>, // value → token
    reverse: HashMap<String, String>, // token → value
}

/// Zeroize all sensitive data when the vault is dropped.
impl Drop for TokenVault {
    fn drop(&mut self) {
        // Zeroize secret key using the zeroize crate (compiler-barrier guaranteed)
        self.secret.zeroize();

        // Zeroize both keys AND values in the forward map
        // (forward keys contain the sensitive plaintext values)
        let forward = std::mem::take(&mut self.forward);
        for (mut key, mut value) in forward {
            key.zeroize();
            value.zeroize();
        }

        // Zeroize both keys AND values in the reverse map
        // (reverse values contain the sensitive plaintext values)
        let reverse = std::mem::take(&mut self.reverse);
        for (mut key, mut value) in reverse {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl TokenVault {
    /// Create a new token vault.
    pub fn new(prefix: &str, secret: Option<&[u8]>) -> Self {
        let secret = secret.map(|s| s.to_vec()).unwrap_or_else(|| {
            let mut key = vec![0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key);
            key
        });

        Self {
            prefix: prefix.to_string(),
            secret,
            forward: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    /// Tokenize a value, returning a deterministic token.
    ///
    /// Returns the existing token if the value was already tokenized.
    /// Enforces a maximum entry count to prevent unbounded memory growth.
    pub fn tokenize(&mut self, value: &str, category: &str) -> String {
        if let Some(token) = self.forward.get(value) {
            return token.clone();
        }

        // Enforce size limit
        if self.forward.len() >= MAX_VAULT_ENTRIES {
            tracing::warn!(
                "Token vault at capacity ({} entries), rejecting new tokenization",
                MAX_VAULT_ENTRIES
            );
            // Return a hash-only token without storing the mapping
            let mut mac =
                HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
            mac.update(value.as_bytes());
            let result = mac.finalize().into_bytes();
            let hash_hex: String = result.iter().take(16).map(|b| format!("{b:02x}")).collect();
            return format!("{}_OVERFLOW_{hash_hex}", self.prefix);
        }

        let cat_abbrev = category
            .split_whitespace()
            .map(|w| w.chars().next().unwrap_or('X'))
            .collect::<String>()
            .to_uppercase();

        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        let result = mac.finalize().into_bytes();
        let hash_hex: String = result.iter().take(16).map(|b| format!("{b:02x}")).collect();

        let token = format!("{}_{cat_abbrev}_{hash_hex}", self.prefix);

        self.forward.insert(value.to_string(), token.clone());
        self.reverse.insert(token.clone(), value.to_string());

        token
    }

    /// Recover original value from a token.
    pub fn detokenize(&self, token: &str) -> Option<&str> {
        self.reverse.get(token).map(|s| s.as_str())
    }

    /// Detokenize all tokens in a text string.
    ///
    /// This performs a single left-to-right pass over the input and, at
    /// each position, tries to match any known token before advancing.
    /// Tokens are tried longest-first so that a short token cannot hijack
    /// a longer one that shares a prefix. After a successful replacement
    /// the cursor advances past the token (not into the replacement), so
    /// a token whose plaintext value contains another token will NOT
    /// cascade into further substitutions.
    ///
    /// The previous implementation looped over the reverse map calling
    /// `String::replace` for each entry. That was unsafe in two ways:
    ///
    /// 1. HashMap iteration order is non-deterministic, so overlapping
    ///    tokens could produce different outputs across runs.
    /// 2. Each pass rescanned the *output* of the previous pass, meaning
    ///    a replacement whose plaintext happened to match a different
    ///    token (or part of one) could produce cross-token contamination
    ///    and partially recover unrelated plaintexts.
    pub fn detokenize_text(&self, text: &str) -> String {
        if self.reverse.is_empty() || text.is_empty() {
            return text.to_string();
        }

        // Longest-first: prevents a shorter token from matching when a
        // longer token starting at the same position would also match.
        let mut tokens: Vec<(&String, &String)> = self.reverse.iter().collect();
        tokens.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let mut result = String::with_capacity(text.len());
        let mut remaining = text;

        'outer: while !remaining.is_empty() {
            for (token, value) in &tokens {
                if remaining.starts_with(token.as_str()) {
                    result.push_str(value);
                    // Advance past the token, not into the replacement.
                    remaining = &remaining[token.len()..];
                    continue 'outer;
                }
            }
            // No token matched at this position; copy one char and advance.
            let ch = remaining
                .chars()
                .next()
                .expect("remaining is non-empty at this point");
            result.push(ch);
            remaining = &remaining[ch.len_utf8()..];
        }

        result
    }

    /// Number of stored mappings.
    pub fn size(&self) -> usize {
        self.forward.len()
    }

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.forward.clear();
        self.reverse.clear();
    }

    /// Export token→value mappings.
    pub fn export_map(&self) -> &HashMap<String, String> {
        &self.reverse
    }
}

impl Default for TokenVault {
    fn default() -> Self {
        Self::new("TOK", None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detokenize_round_trip() {
        let mut v = TokenVault::new("TOK", None);
        let t1 = v.tokenize("alice@example.com", "Email Address");
        let t2 = v.tokenize("4532015112830366", "Credit Card");
        let text = format!("User {t1} paid with {t2}.");
        let restored = v.detokenize_text(&text);
        assert_eq!(
            restored,
            "User alice@example.com paid with 4532015112830366."
        );
    }

    #[test]
    fn test_detokenize_does_not_cascade() {
        // Regression: the old String::replace loop rescanned the output of
        // each prior replacement. If a plaintext value happens to look like
        // another token, the second pass would corrupt it. Here we force
        // that exact collision by inserting a fake entry whose plaintext is
        // identical to a real token string.
        let mut v = TokenVault::new("TOK", None);
        let real_token = v.tokenize("secret-A", "Credential");
        // Simulate a plaintext value that collides with a token string by
        // directly seeding the reverse map.
        v.reverse
            .insert("TOK_X_collide".to_string(), real_token.clone());
        v.forward
            .insert(real_token.clone(), "TOK_X_collide".to_string());

        let out = v.detokenize_text("TOK_X_collide");
        // The collide entry must expand exactly once to its direct value,
        // NOT cascade into the real-token plaintext.
        assert_eq!(out, real_token);
    }

    #[test]
    fn test_detokenize_longest_first_prevents_prefix_hijack() {
        // If both "TOK_A_aa" and "TOK_A_aa_bb" exist, a text containing
        // "TOK_A_aa_bb" must map to the longer token's value.
        let mut v = TokenVault::new("TOK", None);
        v.reverse
            .insert("TOK_A_aa".to_string(), "short".to_string());
        v.reverse
            .insert("TOK_A_aa_bb".to_string(), "long".to_string());

        assert_eq!(v.detokenize_text("TOK_A_aa_bb"), "long");
        assert_eq!(v.detokenize_text("TOK_A_aa"), "short");
    }

    #[test]
    fn test_detokenize_handles_multibyte_text() {
        let mut v = TokenVault::new("TOK", None);
        let t = v.tokenize("alice@example.com", "Email");
        let text = format!("📧 {t} 🎯");
        let restored = v.detokenize_text(&text);
        assert_eq!(restored, "📧 alice@example.com 🎯");
    }

    #[test]
    fn test_detokenize_empty_vault_is_identity() {
        let v = TokenVault::new("TOK", None);
        assert_eq!(v.detokenize_text("hello world"), "hello world");
    }
}
