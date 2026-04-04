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
    forward: HashMap<String, String>,  // value → token
    reverse: HashMap<String, String>,  // token → value
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
    pub fn detokenize_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (token, value) in &self.reverse {
            result = result.replace(token, value);
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
