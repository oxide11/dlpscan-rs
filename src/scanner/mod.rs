//! Core scanning engine using RegexSet for two-phase matching.
//!
//! Phase 1: RegexSet identifies WHICH patterns match (single O(n) pass).
//! Phase 2: Individual Regex extracts spans for only the matched patterns.

use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::context;
use crate::models::{is_context_required, pattern_specificity, Match, PatternDef};
use crate::normalize;
use crate::patterns::PATTERNS;
use crate::scoring::{compute_confidence, deduplicate_overlapping};
use crate::validation::validate_text_input;

/// Maximum number of matches returned per scan.
pub const MAX_MATCHES: usize = 50_000;

/// Maximum scan time in seconds.
pub const MAX_SCAN_SECONDS: u64 = 120;

/// Maximum input size (10 MB).
pub const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Scanner configuration.
pub struct ScanConfig {
    /// Categories to scan (None = all).
    pub categories: Option<HashSet<String>>,
    /// Only return matches with context keywords.
    pub require_context: bool,
    /// Maximum matches to return.
    pub max_matches: usize,
    /// Whether to deduplicate overlapping matches.
    pub deduplicate: bool,
    /// Minimum confidence threshold.
    pub min_confidence: f64,
    /// Only run baseline (always-run) patterns — skip context-gated patterns entirely.
    pub baseline_only: bool,
    /// Entropy scan mode for detecting high-entropy secrets.
    pub entropy_scan: EntropyMode,
    /// Optional EDM (Exact Data Match) engine for known-value detection.
    pub edm: Option<Arc<crate::edm::ExactDataMatcher>>,
    /// Optional LSH (Locality-Sensitive Hashing) vault for document similarity.
    pub lsh: Option<Arc<crate::lsh::DocumentVault>>,
}

/// Entropy scanning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntropyMode {
    /// Disabled (default).
    #[default]
    Off,
    /// Only flag high-entropy tokens near context keywords
    /// (secret, key, token, password, auth, credential, etc.).
    Gated,
    /// Only flag high-entropy tokens in assignment patterns
    /// (key=VALUE, "token": "VALUE", export SECRET=VALUE).
    Assignment,
    /// Flag all high-entropy tokens regardless of context.
    All,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            categories: None,
            require_context: false,
            max_matches: MAX_MATCHES,
            deduplicate: true,
            min_confidence: 0.0,
            baseline_only: false,
            entropy_scan: EntropyMode::Off,
            edm: None,
            lsh: None,
        }
    }
}

impl std::fmt::Debug for ScanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanConfig")
            .field("categories", &self.categories)
            .field("require_context", &self.require_context)
            .field("max_matches", &self.max_matches)
            .field("deduplicate", &self.deduplicate)
            .field("min_confidence", &self.min_confidence)
            .field("baseline_only", &self.baseline_only)
            .field("entropy_scan", &self.entropy_scan)
            .field("edm", &self.edm.is_some())
            .field("lsh", &self.lsh.is_some())
            .finish()
    }
}

impl ScanConfig {
    /// Create a new ScanConfig with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict scanning to specific categories.
    pub fn with_categories<I, S>(mut self, categories: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.categories = Some(categories.into_iter().map(Into::into).collect());
        self
    }

    /// Require context keywords for all matches.
    pub fn with_require_context(mut self, require: bool) -> Self {
        self.require_context = require;
        self
    }

    /// Set maximum matches per scan.
    pub fn with_max_matches(mut self, max: usize) -> Self {
        self.max_matches = max;
        self
    }

    /// Enable or disable deduplication of overlapping matches.
    pub fn with_deduplicate(mut self, dedup: bool) -> Self {
        self.deduplicate = dedup;
        self
    }

    /// Set minimum confidence threshold (0.0-1.0).
    pub fn with_min_confidence(mut self, min: f64) -> Self {
        self.min_confidence = min.clamp(0.0, 1.0);
        self
    }

    /// Enable baseline-only mode (skip context-gated patterns).
    pub fn with_baseline_only(mut self, baseline: bool) -> Self {
        self.baseline_only = baseline;
        self
    }

    /// Set entropy scan mode.
    pub fn with_entropy_scan(mut self, mode: EntropyMode) -> Self {
        self.entropy_scan = mode;
        self
    }

    /// Attach an EDM (Exact Data Match) engine.
    pub fn with_edm(mut self, edm: Arc<crate::edm::ExactDataMatcher>) -> Self {
        self.edm = Some(edm);
        self
    }

    /// Attach an LSH (Document Similarity) vault.
    pub fn with_lsh(mut self, lsh: Arc<crate::lsh::DocumentVault>) -> Self {
        self.lsh = Some(lsh);
        self
    }
}

/// Compiled regex cache: one Regex per pattern, compiled once at startup.
struct CompiledPattern {
    regex: Regex,
    def: &'static PatternDef,
}

static COMPILED: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    let mut compiled = Vec::with_capacity(PATTERNS.len());

    for pat in PATTERNS.iter() {
        let regex_str = if pat.case_insensitive {
            format!("(?i){}", pat.regex)
        } else {
            pat.regex.to_string()
        };

        match Regex::new(&regex_str) {
            Ok(re) => {
                compiled.push(CompiledPattern {
                    regex: re,
                    def: pat,
                });
            }
            Err(e) => {
                tracing::warn!(
                    pattern = pat.sub_category,
                    error = %e,
                    "Failed to compile pattern, skipping"
                );
            }
        }
    }

    compiled
});

// ---------------------------------------------------------------------------
// Aho-Corasick prefilter: classify patterns as always-run vs context-gated
// ---------------------------------------------------------------------------

/// Specificity threshold — patterns at or above always run.
const SPECIFICITY_THRESHOLD: f64 = 0.85;

/// Curated set of patterns that always run regardless of specificity.
static CRITICAL_ALWAYS_RUN: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // US core
        "USA SSN",
        "USA ITIN",
        "USA EIN",
        "USA Passport",
        "USA Passport Card",
        "USA Routing Number",
        "US Phone Number",
        "US MBI",
        "US NPI",
        // Canada
        "Canada SIN",
        "Canada Passport",
        // UK
        "UK NIN",
        "British NHS",
        "UK Passport",
        // Europe
        "France NIR",
        "Germany Tax ID",
        "Netherlands BSN",
        "Spain DNI",
        "Italy Codice Fiscale",
        "Italy SSN",
        "Sweden PIN",
        "Poland PESEL",
        "Belgium NRN",
        "Denmark CPR",
        // Asia-Pacific
        "Australia TFN",
        "Australia Medicare",
        "Australia Passport",
        "India Aadhaar",
        "India PAN",
        "China Resident ID",
        "Japan My Number",
        "South Korea RRN",
        "Singapore NRIC",
        "Singapore FIN",
        "Hong Kong ID",
        // Latin America
        "Brazil CPF",
        "Brazil CNPJ",
        "Mexico CURP",
        "Argentina CUIL/CUIT",
        "Chile RUN/RUT",
        // Middle East
        "Israel Teudat Zehut",
        "UAE Emirates ID",
        "Saudi Arabia National ID",
        // Crypto
        "Bitcoin Address (Legacy)",
        "Bitcoin Address (Bech32)",
        "Ethereum Address",
        "Litecoin Address",
        "Bitcoin Cash Address",
        "Ripple Address",
        // Contact & network
        "E.164 Phone Number",
        "UK Phone Number",
        "IPv4 Address",
        "IPv6 Address",
        "MAC Address",
        // Secrets (important but below threshold)
        "Bearer Token",
        "Generic API Key",
        "Generic Secret Assignment",
        "Slack Webhook",
        // Structurally distinctive
        "GPS Coordinates",
        "PAN",
        "VIN",
        "IMEI",
        "IMEISV",
        "MEID",
        // Financial
        "ABA Routing Number",
        "CUSIP",
        "ISIN",
        "SEDOL",
        "LEI",
        "Ticker Symbol",
        // URLs with credentials
        "URL with Password",
        "URL with Token",
    ]
    .into_iter()
    .collect()
});

/// Returns true if a pattern should always run (never context-gated).
fn is_always_run(sub_category: &str) -> bool {
    let spec = pattern_specificity(sub_category);
    spec >= SPECIFICITY_THRESHOLD || CRITICAL_ALWAYS_RUN.contains(sub_category)
}

/// Scan text for sensitive data.
///
/// Uses Aho-Corasick prefilter to skip ~80% of regex patterns when their
/// context keywords aren't present, then runs remaining patterns in parallel.
pub fn scan_text(text: &str) -> crate::Result<Vec<Match>> {
    scan_text_with_config(text, &ScanConfig::default())
}

/// Scan text with custom configuration.
///
/// Uses parallel iteration over compiled regexes with Rayon for throughput.
pub fn scan_text_with_config(text: &str, config: &ScanConfig) -> crate::Result<Vec<Match>> {
    validate_text_input(text)?;

    let start = Instant::now();

    // Normalize text to defeat evasion
    let (normalized, offset_map) = normalize::normalize_text(text);

    // Build Aho-Corasick hit index for context matching
    let hit_index = context::build_hit_index(&normalized);

    let compiled = &*COMPILED;

    // Build set of context-gated (category, sub_category) pairs whose keywords
    // were found somewhere in the text. Patterns not in this set get skipped.
    let active_gated: HashSet<(&str, &str)> = if let Some(ref index) = hit_index {
        compiled
            .iter()
            .filter(|cp| !is_always_run(cp.def.sub_category))
            .filter(|cp| {
                index.has_hit_in_range(cp.def.category, cp.def.sub_category, 0, normalized.len())
            })
            .map(|cp| (cp.def.category, cp.def.sub_category))
            .collect()
    } else {
        HashSet::new()
    };

    let prefilter_active = hit_index.is_some();

    // Filter patterns: category filter + AC prefilter + baseline_only
    let active_patterns: Vec<&CompiledPattern> = compiled
        .iter()
        .filter(|cp| {
            // Category filter
            if let Some(ref cats) = config.categories {
                if !cats.contains(cp.def.category) {
                    return false;
                }
            }
            // Baseline-only mode: only run always-run patterns
            if config.baseline_only {
                return is_always_run(cp.def.sub_category);
            }
            // AC prefilter: skip context-gated patterns whose keywords aren't present
            if prefilter_active
                && !is_always_run(cp.def.sub_category)
                && !active_gated.contains(&(cp.def.category, cp.def.sub_category))
            {
                return false;
            }
            true
        })
        .collect();

    // Run each pattern in parallel, collect per-pattern match vecs
    let per_pattern_matches: Vec<Vec<Match>> = active_patterns
        .par_iter()
        .map(|cp| {
            let pat = cp.def;
            let mut local_matches = Vec::new();
            const MAX_MATCHES_PER_PATTERN: usize = 10_000;

            for mat in cp.regex.find_iter(&normalized) {
                if local_matches.len() >= MAX_MATCHES_PER_PATTERN {
                    break;
                }
                let norm_start = mat.start();
                let norm_end = mat.end();
                let matched_text = mat.as_str();

                // Structural validation (Luhn, SWIFT, CUSIP, SEDOL, TFN, SSN)
                if !crate::validation::validate_match(pat.category, pat.sub_category, matched_text)
                {
                    continue;
                }

                // Context checking
                let has_context = context::check_context(
                    &normalized,
                    norm_start,
                    norm_end,
                    pat.category,
                    pat.sub_category,
                    hit_index.as_ref(),
                );

                let ctx_required = is_context_required(pat.sub_category);

                if ctx_required && !has_context {
                    continue;
                }
                if config.require_context && !has_context {
                    continue;
                }

                let confidence = compute_confidence(pat.sub_category, has_context, ctx_required);
                if confidence < config.min_confidence {
                    continue;
                }

                // Map normalized positions back to original text
                let (orig_start, orig_end) = if !offset_map.is_empty() {
                    let os = if norm_start < offset_map.len() {
                        offset_map[norm_start]
                    } else {
                        text.len()
                    };
                    let oe = if norm_end > 0 && norm_end <= offset_map.len() {
                        offset_map[norm_end - 1] + 1
                    } else {
                        text.len()
                    };
                    (os, oe)
                } else {
                    (norm_start, norm_end)
                };

                // Safety: ensure slice boundaries are valid UTF-8 char boundaries
                let original_text = if orig_end <= text.len()
                    && orig_start <= orig_end
                    && text.is_char_boundary(orig_start)
                    && text.is_char_boundary(orig_end)
                {
                    &text[orig_start..orig_end]
                } else {
                    matched_text
                };

                let mut m = Match::new(
                    original_text.to_string(),
                    pat.category.to_string(),
                    pat.sub_category.to_string(),
                    has_context,
                    confidence,
                    (orig_start, orig_end),
                    ctx_required,
                );

                // BIN enrichment for credit card matches
                if pat.category == "Credit Card Numbers" {
                    if let Some((brand, card_type, country, issuer)) =
                        crate::validation::get_bin_info(matched_text)
                    {
                        m.metadata.insert("bin_brand".into(), brand);
                        m.metadata.insert("bin_card_type".into(), card_type);
                        m.metadata.insert("bin_country".into(), country);
                        if !issuer.is_empty() {
                            m.metadata.insert("bin_issuer".into(), issuer);
                        }
                        // Known BIN: small confidence boost
                        m.confidence = (m.confidence + 0.05).min(1.0);
                    }
                }

                local_matches.push(m);
            }

            local_matches
        })
        .collect();

    // Check if scan exceeded timeout
    if start.elapsed().as_secs() > MAX_SCAN_SECONDS {
        tracing::warn!(
            "Scan exceeded timeout of {}s, returning partial results",
            MAX_SCAN_SECONDS
        );
    }

    // Flatten primary matches
    let mut matches: Vec<Match> = per_pattern_matches
        .into_iter()
        .flatten()
        .take(config.max_matches)
        .collect();

    // Second pass: try alternative decodings (base32/64, ROT13, reversal)
    // Only if primary scan found few/no matches and text is short enough
    if matches.len() < 3 && text.len() < 4096 && start.elapsed().as_secs() < MAX_SCAN_SECONDS / 2 {
        let alternatives = normalize::generate_alternative_decodings(&normalized);
        for alt_text in &alternatives {
            if alt_text.is_empty() {
                continue;
            }
            let (alt_norm, _) = normalize::normalize_text(alt_text);
            for cp in compiled.iter() {
                if let Some(ref cats) = config.categories {
                    if !cats.contains(cp.def.category) {
                        continue;
                    }
                }
                for mat in cp.regex.find_iter(&alt_norm) {
                    let matched_text = mat.as_str();
                    if !crate::validation::validate_match(
                        cp.def.category,
                        cp.def.sub_category,
                        matched_text,
                    ) {
                        continue;
                    }
                    let confidence = compute_confidence(cp.def.sub_category, false, false);
                    if confidence < config.min_confidence {
                        continue;
                    }
                    matches.push(Match::new(
                        matched_text.to_string(),
                        cp.def.category.to_string(),
                        cp.def.sub_category.to_string(),
                        false,
                        confidence * 0.9, // slightly lower confidence for alternative decoding
                        (0, text.len()),
                        false,
                    ));
                }
            }
        }
    }

    // Deduplicate overlapping matches
    if config.deduplicate {
        deduplicate_overlapping(&mut matches);
    }

    // Entropy-based secret detection (optional)
    if config.entropy_scan != EntropyMode::Off && matches.len() < config.max_matches {
        let entropy_matches = scan_high_entropy_tokens(text, &normalized, &offset_map, config);
        for em in entropy_matches {
            if matches.len() >= config.max_matches {
                break;
            }
            // Skip if already covered by a regex match at the same span
            let dominated = matches
                .iter()
                .any(|m| m.span.0 <= em.span.0 && m.span.1 >= em.span.1);
            if !dominated {
                matches.push(em);
            }
        }
    }

    // EDM (Exact Data Match) — scan for known registered values
    // EDM matches are NEVER dominated by regex matches because they represent
    // confirmed known sensitive values, not pattern guesses.
    if let Some(ref edm) = config.edm {
        if matches.len() < config.max_matches {
            let edm_matches = edm.scan(text, config.categories.as_ref());
            for em in edm_matches {
                if matches.len() >= config.max_matches {
                    break;
                }
                {
                    matches.push(Match::new(
                        em.matched_text,
                        format!("EDM: {}", em.category),
                        "Exact Data Match".to_string(),
                        true, // always has context (it's an exact match)
                        em.confidence,
                        em.span,
                        false,
                    ));
                }
            }
        }
    }

    // LSH (Locality-Sensitive Hashing) — check for similar documents
    if let Some(ref lsh) = config.lsh {
        if matches.len() < config.max_matches {
            let sim_matches = lsh.query(text, None);
            for sm in sim_matches {
                if matches.len() >= config.max_matches {
                    break;
                }
                matches.push(Match::new(
                    format!("Similar to: {}", sm.doc_id),
                    "Document Similarity".to_string(),
                    sm.sensitivity.clone(),
                    true,
                    sm.similarity.clamp(0.0, 1.0),
                    (0, text.len().min(100)), // span is the whole text
                    false,
                ));
            }
        }
    }

    Ok(matches)
}

// ---------------------------------------------------------------------------
// Inline entropy-based secret detection
// ---------------------------------------------------------------------------

/// Minimum token length to consider for entropy analysis.
const ENTROPY_MIN_TOKEN_LEN: usize = 16;

/// Maximum token length (longer tokens are likely not secrets).
const ENTROPY_MAX_TOKEN_LEN: usize = 256;

/// Shannon entropy threshold for flagging a token as a potential secret.
/// Base64/hex-encoded random data typically has entropy >= 4.5 bits/char.
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Context keywords that indicate a high-entropy token is likely a secret.
const ENTROPY_CONTEXT_KEYWORDS: &[&str] = &[
    "secret",
    "key",
    "token",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "signing_key",
    "encryption_key",
    "bearer",
    "authorization",
    "connection_string",
    "conn_str",
    "database_url",
    "aws_secret",
    "github_token",
    "slack_token",
    // French
    "mot de passe",
    "clé privée",
    "clé api",
    "jeton",
    "identifiant",
    "chaîne de connexion",
    // Spanish
    "contraseña",
    "contrasena",
    "clave privada",
    "clave api",
    "credencial",
    // German
    "passwort",
    "kennwort",
    "zugangsdaten",
    "anmeldedaten",
    "privater schlüssel",
    "api-schlüssel",
    // Italian
    "credenziali",
    "chiave privata",
    "chiave api",
    // Portuguese
    "senha",
    "chave privada",
    "chave api",
];

/// Assignment patterns that precede a value (key=VALUE, "key": "VALUE", etc.).
/// Matches if the text before a token looks like an assignment.
/// Handles: KEY=, "key":, export KEY=, let key =, const KEY:, var key =
static ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*["']?\s*$"#)
        .expect("assignment regex must compile")
});

/// Scan for high-entropy tokens using the configured gating mode.
fn scan_high_entropy_tokens(
    original_text: &str,
    normalized: &str,
    offset_map: &[usize],
    config: &ScanConfig,
) -> Vec<Match> {
    let mut results = Vec::new();
    let normalized_lower = normalized.to_lowercase();

    // Tokenize by whitespace and common delimiters
    let delimiters = |c: char| -> bool {
        c.is_whitespace()
            || c == ','
            || c == ';'
            || c == '\''
            || c == '"'
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
            || c == '{'
            || c == '}'
            || c == '='
            || c == ':'
    };

    let mut pos = 0;
    for token in normalized.split(delimiters) {
        if token.is_empty() {
            continue;
        }

        // Track position in normalized text
        let norm_start = match normalized[pos..].find(token) {
            Some(offset) => pos + offset,
            None => {
                pos += 1;
                continue;
            }
        };
        let norm_end = norm_start + token.len();
        pos = norm_end;

        // Filter by length
        if token.len() < ENTROPY_MIN_TOKEN_LEN || token.len() > ENTROPY_MAX_TOKEN_LEN {
            continue;
        }

        // Skip tokens that are all digits (likely IDs, not secrets)
        if token
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == '.')
        {
            continue;
        }

        // Skip tokens that are common words (all lowercase alpha, no mixed case/digits)
        if token.chars().all(|c| c.is_ascii_lowercase()) {
            continue;
        }

        // Compute Shannon entropy per character
        let entropy = char_entropy(token);
        if entropy < ENTROPY_THRESHOLD {
            continue;
        }

        // Apply gating based on mode
        let (has_context, sub_category) = match config.entropy_scan {
            EntropyMode::Gated => {
                // Check if any context keyword appears within 80 chars
                let search_start = norm_start.saturating_sub(80);
                let search_end = (norm_end + 80).min(normalized_lower.len());
                let context_window = &normalized_lower[search_start..search_end];
                let found = ENTROPY_CONTEXT_KEYWORDS
                    .iter()
                    .any(|kw| context_window.contains(kw));
                if !found {
                    continue;
                }
                (true, "Potential Secret (Context)")
            }
            EntropyMode::Assignment => {
                // Check if preceded by an assignment pattern (key=, "key":, export KEY=)
                let prefix_start = norm_start.saturating_sub(60);
                let prefix = &normalized[prefix_start..norm_start];
                if !ASSIGNMENT_RE.is_match(prefix) {
                    continue;
                }
                (true, "Potential Secret (Assignment)")
            }
            EntropyMode::All => (false, "Potential Secret"),
            EntropyMode::Off => unreachable!(),
        };

        // Check minimum confidence
        let confidence = entropy_to_confidence(entropy);
        if confidence < config.min_confidence {
            continue;
        }

        // Map back to original text position
        let (orig_start, orig_end) = if !offset_map.is_empty() {
            let os = if norm_start < offset_map.len() {
                offset_map[norm_start]
            } else {
                continue;
            };
            let oe = if norm_end > 0 && norm_end <= offset_map.len() {
                offset_map[norm_end - 1] + 1
            } else {
                original_text.len()
            };
            (os, oe)
        } else {
            (norm_start, norm_end)
        };

        let matched_text = if orig_start < original_text.len()
            && orig_end <= original_text.len()
            && original_text.is_char_boundary(orig_start)
            && original_text.is_char_boundary(orig_end)
        {
            &original_text[orig_start..orig_end]
        } else {
            token
        };

        results.push(Match::new(
            matched_text.to_string(),
            "High Entropy".to_string(),
            sub_category.to_string(),
            has_context,
            confidence,
            (orig_start, orig_end),
            false,
        ));
    }

    results
}

/// Compute Shannon entropy per character of a string (bits per char).
fn char_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0u64) += 1;
    }
    let len = s.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Convert entropy score to a confidence value (0.0-1.0).
fn entropy_to_confidence(entropy: f64) -> f64 {
    // Map entropy 4.5-6.0 to confidence 0.40-0.90
    let clamped = entropy.clamp(4.5, 6.0);
    0.40 + (clamped - 4.5) / (6.0 - 4.5) * 0.50
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_empty() {
        assert!(scan_text("").is_err());
    }

    #[test]
    fn test_scan_clean_text() {
        let result = scan_text("Hello world, this is a test.").unwrap();
        // Clean text should have few or no matches
        assert!(result.len() < 5);
    }

    #[test]
    fn test_scan_email() {
        let result = scan_text("Contact us at test@example.com for info.").unwrap();
        assert!(result.iter().any(|m| m.sub_category == "Email Address"));
    }

    #[test]
    fn test_scan_credit_card() {
        // Valid Visa number (passes Luhn)
        let result = scan_text("Card: 4532015112830366").unwrap();
        assert!(result.iter().any(|m| m.sub_category == "Visa"));
    }

    #[test]
    fn test_scan_with_categories() {
        let config = ScanConfig {
            categories: Some(["Contact Information".to_string()].into_iter().collect()),
            ..Default::default()
        };
        let result =
            scan_text_with_config("Email: test@example.com SSN: 123-45-6789", &config).unwrap();
        assert!(result.iter().all(|m| m.category == "Contact Information"));
    }

    #[test]
    fn test_char_entropy_uniform() {
        // "aaaa" has zero entropy
        assert!(char_entropy("aaaaaaaaaaaaaaaa") < 0.01);
    }

    #[test]
    fn test_char_entropy_high() {
        // Random-looking hex string should have high entropy
        assert!(char_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") > 3.5);
    }

    #[test]
    fn test_entropy_to_confidence_range() {
        assert!(entropy_to_confidence(4.5) >= 0.39);
        assert!(entropy_to_confidence(6.0) >= 0.89);
        assert!(entropy_to_confidence(3.0) >= 0.39); // clamped
    }

    #[test]
    fn test_entropy_all_detects_random_secret() {
        let config = ScanConfig {
            entropy_scan: EntropyMode::All,
            min_confidence: 0.0,
            ..Default::default()
        };
        // This random string doesn't match any regex pattern
        let text = "value is xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs here";
        let result = scan_text_with_config(text, &config).unwrap();
        assert!(
            result.iter().any(|m| m.category == "High Entropy"),
            "Entropy All mode should detect random-looking token: {:?}",
            result
                .iter()
                .map(|m| (&m.category, &m.sub_category))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_entropy_gated_requires_keyword() {
        // With keyword "secret" nearby — should fire
        let config = ScanConfig {
            entropy_scan: EntropyMode::Gated,
            min_confidence: 0.0,
            ..Default::default()
        };
        let text = "my secret key is xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs here";
        let result = scan_text_with_config(text, &config).unwrap();
        assert!(
            result.iter().any(|m| m.category == "High Entropy"),
            "Gated entropy should fire when 'secret' keyword is nearby"
        );

        // Without keyword — should NOT fire
        let text_no_ctx = "the value is xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs stored here";
        let result2 = scan_text_with_config(text_no_ctx, &config).unwrap();
        assert!(
            !result2.iter().any(|m| m.category == "High Entropy"),
            "Gated entropy should NOT fire without context keyword"
        );
    }

    #[test]
    fn test_entropy_assignment_requires_pattern() {
        let config = ScanConfig {
            entropy_scan: EntropyMode::Assignment,
            min_confidence: 0.0,
            ..Default::default()
        };
        // With assignment pattern — should fire (token after = is high entropy)
        let text = "CUSTOM_KEY=xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs end";
        let result = scan_text_with_config(text, &config).unwrap();
        assert!(
            result
                .iter()
                .any(|m| m.category == "High Entropy" && m.sub_category.contains("Assignment")),
            "Assignment mode should fire on KEY=VALUE pattern: {:?}",
            result
                .iter()
                .map(|m| (&m.category, &m.sub_category))
                .collect::<Vec<_>>()
        );

        // Without assignment — should NOT fire
        let text_no_assign = "random text xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs embedded";
        let result2 = scan_text_with_config(text_no_assign, &config).unwrap();
        assert!(
            !result2.iter().any(|m| m.category == "High Entropy"),
            "Assignment mode should NOT fire without assignment pattern"
        );
    }

    #[test]
    fn test_entropy_ignores_normal_text() {
        let config = ScanConfig {
            entropy_scan: EntropyMode::All,
            min_confidence: 0.0,
            ..Default::default()
        };
        let text = "The quick brown fox jumps over the lazy dog near the river";
        let result = scan_text_with_config(text, &config).unwrap();
        assert!(
            !result.iter().any(|m| m.category == "High Entropy"),
            "Normal English text should NOT trigger entropy detection"
        );
    }

    #[test]
    fn test_entropy_off_by_default() {
        let config = ScanConfig::default();
        assert_eq!(config.entropy_scan, EntropyMode::Off);
        let text = "secret=xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs";
        let result = scan_text_with_config(text, &config).unwrap();
        assert!(
            !result.iter().any(|m| m.category == "High Entropy"),
            "Entropy should not fire when disabled"
        );
    }
}
