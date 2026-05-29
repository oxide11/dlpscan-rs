//! HTTP API server for DLP scanning.
//!
//! Provides REST endpoints for scanning, tokenization, and pattern management.
//! Requires the `async-support` feature flag for the full server.
//! Handler functions work without async for testing and embedding.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::RwLock;
use std::time::Instant;

use crate::guard::{Action, InputGuard, Preset, ScanResult, TokenVault};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    pub text: String,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub min_confidence: f64,
    #[serde(default)]
    pub require_context: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub is_clean: bool,
    pub finding_count: usize,
    pub categories_found: Vec<String>,
    pub redacted_text: Option<String>,
    pub findings: Vec<FindingResponse>,
}

#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub text: String,
    pub category: String,
    pub sub_category: String,
    pub confidence: f64,
    pub has_context: bool,
    pub span: (usize, usize),
}

#[derive(Debug, Deserialize)]
pub struct TokenizeRequest {
    pub text: String,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub min_confidence: f64,
}

#[derive(Debug, Serialize)]
pub struct TokenizeResponse {
    pub tokenized_text: String,
    pub token_count: usize,
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct DetokenizeRequest {
    pub text: String,
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
pub struct DetokenizeResponse {
    pub original_text: String,
}

#[derive(Debug, Deserialize)]
pub struct BatchScanRequest {
    pub items: Vec<ScanRequest>,
}

#[derive(Debug, Serialize)]
pub struct BatchScanResponse {
    pub results: Vec<ScanResponse>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_connections: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_ready: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PatternCreateRequest {
    pub name: String,
    pub pattern: String,
    pub category: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternResponse {
    pub name: String,
    pub pattern: String,
    pub category: String,
    pub confidence: f64,
}

fn default_action() -> String {
    "flag".to_string()
}

// ---------------------------------------------------------------------------
// Server State
// ---------------------------------------------------------------------------

/// Maximum number of custom patterns a user can register.
#[cfg(feature = "async-support")]
const MAX_CUSTOM_PATTERNS: usize = 100;

/// Maximum regex pattern length in characters.
#[cfg(feature = "async-support")]
const MAX_PATTERN_LENGTH: usize = 2048;

/// Maximum number of token vaults.
const MAX_VAULTS: usize = 1000;

/// Vault time-to-live in seconds (1 hour).
pub const VAULT_TTL_SECS: u64 = 3600;

/// Shared application state for the API server.
pub struct AppState {
    /// SHA-256 hash of the configured API key (never stores plaintext).
    /// Wrapped in RwLock to support runtime key rotation.
    pub api_key_hash: RwLock<Option<[u8; 32]>>,
    pub rate_limiter: RwLock<RateLimiter>,
    /// Optional distributed rate limiter backed by Redis. When present,
    /// it is consulted first; if the Redis call fails the in-memory
    /// limiter is used as a fallback so a Redis outage cannot take
    /// the API offline.
    #[cfg(feature = "redis-rate-limit")]
    pub redis_rate_limiter: Option<crate::redis_rate_limit::RedisRateLimiter>,
    pub vaults: RwLock<HashMap<String, VaultEntry>>,
    pub custom_patterns: RwLock<Vec<PatternResponse>>,
    pub start_time: Instant,
    pub is_shutting_down: std::sync::atomic::AtomicBool,
    /// Server-side API key hash-to-role mapping.
    pub api_key_roles: RwLock<HashMap<[u8; 32], crate::rbac::Role>>,
    /// Shared EDM engine for exact data matching (optional).
    pub edm: RwLock<Option<std::sync::Arc<crate::edm::ExactDataMatcher>>>,
    /// Shared LSH vault for document similarity (optional).
    pub lsh: RwLock<Option<std::sync::Arc<crate::lsh::DocumentVault>>>,
}

/// Rotate the API key at runtime without restart.
/// The old key is immediately invalidated.
pub fn rotate_api_key(state: &AppState, new_key: &str) {
    let hash = hash_api_key(new_key);
    if let Ok(mut guard) = state.api_key_hash.write() {
        *guard = Some(hash);
    }
    tracing::info!("API key rotated successfully");
}

/// Add or update an API key-to-role mapping at runtime.
pub fn set_api_key_role(state: &AppState, key: &str, role: crate::rbac::Role) {
    let hash = hash_api_key(key);
    if let Ok(mut guard) = state.api_key_roles.write() {
        guard.insert(hash, role);
    }
}

/// Remove an API key-to-role mapping at runtime.
pub fn revoke_api_key_role(state: &AppState, key: &str) {
    let hash = hash_api_key(key);
    if let Ok(mut guard) = state.api_key_roles.write() {
        guard.remove(&hash);
    }
}

pub struct VaultEntry {
    pub vault: TokenVault,
    pub created_at: Instant,
}

/// Per-client sliding-window rate limiter.
pub struct RateLimiter {
    clients: HashMap<String, Vec<Instant>>,
    max_requests: usize,
    window: std::time::Duration,
}

impl RateLimiter {
    /// Hard cap on the number of distinct client buckets the in-memory
    /// limiter will track. Defends against IP-rotation memory DoS where
    /// an attacker uses millions of unique source IPs to grow the map
    /// unboundedly. When the cap is hit we clear the map — this briefly
    /// resets the limiter (a known trade-off vs unbounded memory) and
    /// emits a warning so operators can tune the cap or move to the
    /// distributed Redis backend.
    pub const MAX_CLIENTS: usize = 100_000;

    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            clients: HashMap::new(),
            max_requests,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Check if a request from a client is allowed. Returns true if under limit.
    pub fn check(&mut self) -> bool {
        self.check_client("global")
    }

    /// Check if a request from a specific client (IP or API key hash) is allowed.
    pub fn check_client(&mut self, client_id: &str) -> bool {
        let now = Instant::now();
        let window = self.window;

        // Hard cap: if we're at the limit and this is a new client, evict
        // stale entries first; if still at cap, clear the entire map.
        if self.clients.len() >= Self::MAX_CLIENTS && !self.clients.contains_key(client_id) {
            self.clients.retain(|_, reqs| {
                reqs.retain(|&t| now.duration_since(t) < window);
                !reqs.is_empty()
            });
            if self.clients.len() >= Self::MAX_CLIENTS {
                tracing::warn!(
                    max_clients = Self::MAX_CLIENTS,
                    "Rate limiter client map at hard cap after cleanup — clearing to prevent unbounded growth (possible IP-rotation DoS)"
                );
                self.clients.clear();
            }
        }

        let requests = self.clients.entry(client_id.to_string()).or_default();
        requests.retain(|&t| now.duration_since(t) < window);
        if requests.len() < self.max_requests {
            requests.push(now);
            true
        } else {
            false
        }
    }

    /// Remaining requests in the current window for the default client.
    pub fn remaining(&self) -> usize {
        let now = Instant::now();
        let active = self
            .clients
            .get("global")
            .map(|reqs| {
                reqs.iter()
                    .filter(|&&t| now.duration_since(t) < self.window)
                    .count()
            })
            .unwrap_or(0);
        self.max_requests.saturating_sub(active)
    }

    /// Evict stale client entries to prevent memory growth.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.clients.retain(|_, reqs| {
            reqs.retain(|&t| now.duration_since(t) < window);
            !reqs.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// API Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub rate_limit: usize,
    pub cache_enabled: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8000,
            api_key: None,
            rate_limit: 100,
            cache_enabled: false,
        }
    }
}

impl ApiConfig {
    /// Load from environment variables.
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("DLPSCAN_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("DLPSCAN_API_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8000),
            api_key: std::env::var("DLPSCAN_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .or_else(|| {
                    tracing::warn!(
                        "DLPSCAN_API_KEY not set — API server running without authentication"
                    );
                    None
                }),
            rate_limit: std::env::var("DLPSCAN_API_RATE_LIMIT")
                .ok()
                .and_then(|r| r.parse().ok())
                .unwrap_or(100),
            cache_enabled: std::env::var("DLPSCAN_CACHE_ENABLED")
                .ok()
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions (work without async)
// ---------------------------------------------------------------------------

/// Process a scan request.
pub fn handle_scan(req: &ScanRequest) -> Result<ScanResponse, String> {
    let guard = build_guard(req)?;
    let result = guard.scan(&req.text).map_err(format_dlp_error)?;
    Ok(scan_result_to_response(&result))
}

/// Format a [`DlpError`] with a stable, sentinel-prefixed string so
/// that the HTTP route layer can map the classification-policy
/// violation to a distinct status code without needing every handler
/// to return a typed error.
///
/// Sentinels:
/// - `CLASSIFICATION_POLICY_VIOLATION: ...` → HTTP 422
/// - `SENSITIVE_DATA_DETECTED: ...` → HTTP 422 (Reject mode)
/// - (anything else) → HTTP 400
#[cfg(feature = "async-support")]
fn format_dlp_error(err: crate::errors::DlpError) -> String {
    use crate::errors::DlpError;
    match err {
        DlpError::ClassificationPolicyViolation { .. } => {
            format!("CLASSIFICATION_POLICY_VIOLATION: {err}")
        }
        DlpError::SensitiveDataDetected { .. } => {
            format!("SENSITIVE_DATA_DETECTED: {err}")
        }
        other => format!("{other}"),
    }
}

#[cfg(not(feature = "async-support"))]
fn format_dlp_error(err: crate::errors::DlpError) -> String {
    format!("{err}")
}

/// Map a formatted [`format_dlp_error`] string to an HTTP status code.
#[cfg(feature = "async-support")]
fn http_status_for_scan_error(err: &str) -> hyper::StatusCode {
    if err.starts_with("CLASSIFICATION_POLICY_VIOLATION")
        || err.starts_with("SENSITIVE_DATA_DETECTED")
    {
        hyper::StatusCode::UNPROCESSABLE_ENTITY
    } else {
        hyper::StatusCode::BAD_REQUEST
    }
}

/// Process a batch scan request.
pub fn handle_batch_scan(req: &BatchScanRequest) -> Result<BatchScanResponse, String> {
    const MAX_BATCH_ITEMS: usize = 1000;
    const MAX_TEXT_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if req.items.len() > MAX_BATCH_ITEMS {
        return Err(format!(
            "Batch size {} exceeds maximum {}",
            req.items.len(),
            MAX_BATCH_ITEMS
        ));
    }
    for item in &req.items {
        if item.text.len() > MAX_TEXT_SIZE {
            return Err(format!(
                "Text size {} exceeds maximum {}",
                item.text.len(),
                MAX_TEXT_SIZE
            ));
        }
    }

    use rayon::prelude::*;
    let results: Vec<Result<ScanResponse, String>> =
        req.items.par_iter().map(handle_scan).collect();

    let mut responses = Vec::new();
    for r in results {
        responses.push(r?);
    }
    Ok(BatchScanResponse { results: responses })
}

/// Process a tokenize request.
pub fn handle_tokenize(
    req: &TokenizeRequest,
    vaults: &RwLock<HashMap<String, VaultEntry>>,
) -> Result<TokenizeResponse, String> {
    // Build a scan config from request
    let scan_req = ScanRequest {
        text: req.text.clone(),
        presets: req.presets.clone(),
        categories: req.categories.clone(),
        action: "tokenize".to_string(),
        min_confidence: req.min_confidence,
        require_context: false,
    };
    let guard = build_guard(&scan_req)?;
    let result = guard.scan(&req.text).map_err(format_dlp_error)?;

    // Create a vault and tokenize all findings
    let vault_id = generate_id();
    let mut vault = TokenVault::new("TOK", None);
    let mut tokenized = req.text.clone();

    // Sort findings by position descending to replace from end to start
    let mut findings: Vec<_> = result.findings.iter().collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.span.0));

    for finding in &findings {
        let token = vault.tokenize(&finding.text, &finding.category);
        let (start, end) = finding.span;
        if start <= end
            && end <= tokenized.len()
            && tokenized.is_char_boundary(start)
            && tokenized.is_char_boundary(end)
        {
            tokenized.replace_range(start..end, &token);
        }
    }

    let token_count = vault.size();
    if let Ok(mut vaults) = vaults.write() {
        // Enforce vault count limit
        if vaults.len() >= MAX_VAULTS {
            return Err(format!("Maximum vault count ({MAX_VAULTS}) reached"));
        }
        vaults.insert(
            vault_id.clone(),
            VaultEntry {
                vault,
                created_at: Instant::now(),
            },
        );
    }

    Ok(TokenizeResponse {
        tokenized_text: tokenized,
        token_count,
        vault_id,
    })
}

/// Process a detokenize request.
pub fn handle_detokenize(
    req: &DetokenizeRequest,
    vaults: &RwLock<HashMap<String, VaultEntry>>,
) -> Result<DetokenizeResponse, String> {
    let vaults = vaults.read().map_err(|e| format!("{e}"))?;
    let entry = vaults.get(&req.vault_id).ok_or("Vault not found")?;
    // Enforce vault TTL
    if entry.created_at.elapsed().as_secs() > VAULT_TTL_SECS {
        return Err("Vault has expired".to_string());
    }
    let original = entry.vault.detokenize_text(&req.text);
    Ok(DetokenizeResponse {
        original_text: original,
    })
}

/// Evict expired vaults. Call periodically or before vault operations.
pub fn evict_expired_vaults(vaults: &RwLock<HashMap<String, VaultEntry>>) {
    if let Ok(mut vaults) = vaults.write() {
        vaults.retain(|_, entry| entry.created_at.elapsed().as_secs() <= VAULT_TTL_SECS);
    }
}

/// Process an obfuscate request.
pub fn handle_obfuscate(req: &ScanRequest) -> Result<ScanResponse, String> {
    let mut obf_req = req.clone();
    obf_req.action = "obfuscate".to_string();
    let guard = build_guard(&obf_req)?;
    let result = guard.scan(&obf_req.text).map_err(format_dlp_error)?;
    Ok(scan_result_to_response(&result))
}

/// Basic health check (used by tests and non-server contexts).
pub fn handle_health() -> HealthResponse {
    HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: None,
        pattern_count: None,
        active_connections: None,
        is_ready: None,
    }
}

/// Full health check with operational data.
#[allow(dead_code)]
fn handle_health_full(state: &AppState, active: usize) -> HealthResponse {
    let shutting_down = state.is_shutting_down.load(Ordering::SeqCst);
    HealthResponse {
        status: if shutting_down {
            "draining".to_string()
        } else {
            "ok".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: Some(state.start_time.elapsed().as_secs()),
        pattern_count: Some(crate::patterns::PATTERNS.len()),
        active_connections: Some(active),
        is_ready: Some(!shutting_down),
    }
}

/// Derive a short, stable bucket identifier for an API key, used as a
/// map key in rate limiting and as a user field in audit events.
///
/// This must use the SAME hash function as auth and RBAC (hash_api_key)
/// so that (a) there is a single canonical identity for a given key
/// across every code path and (b) rate-limit buckets cannot collide
/// with each other via a weaker hash. The previous implementation used
/// a custom FNV-1a (`md5_like_hash`) here while auth and RBAC used
/// SHA-256 via `hash_api_key`, creating two distinct identities for the
/// same key — a latent source of bucket collisions and an auditing
/// mismatch between auth and rate-limit events.
///
/// The returned string is the first 8 bytes (16 hex chars) of the
/// SHA-256 of the key, which gives 2^64 distinct buckets — far more
/// than enough to be collision-free for any realistic tenant count.
#[cfg(feature = "async-support")]
fn api_key_bucket(key: &str) -> String {
    let h = hash_api_key(key);
    let mut s = String::with_capacity(16);
    for b in &h[..8] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Whether `SIPHON_AUDIT_ANONYMIZE_KEYS` is enabled (cached after first read).
///
/// When enabled, audit-event user fields use a fresh random identifier
/// per event instead of the deterministic SHA-256-derived bucket. The
/// rate-limit bucket itself stays deterministic — this only affects what
/// gets written to the audit log, trading correlation across events for
/// a stronger guarantee that audit storage cannot be cross-referenced
/// to identify which API key took an action.
#[cfg(feature = "async-support")]
fn audit_anonymize_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    // 0 = unset, 1 = false, 2 = true
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let on = matches!(
                std::env::var("SIPHON_AUDIT_ANONYMIZE_KEYS")
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            );
            CACHED.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Build the audit-log `user` field for an authenticated request.
///
/// Default behaviour returns `key:<bucket>`, a deterministic SHA-256-derived
/// short identifier of the API key. This preserves cross-event correlation
/// (operators can group audit records by caller).
///
/// When `SIPHON_AUDIT_ANONYMIZE_KEYS` is set, returns `anon:<random-hex>`
/// — a fresh per-event random identifier with no link back to the API key
/// or to other events from the same caller. Use in high-sensitivity
/// deployments where audit-log correlation is itself a privacy concern.
///
/// `None` (no key header present) always returns `"anonymous"`.
#[cfg(feature = "async-support")]
fn audit_user_field(api_key_header: Option<&str>) -> String {
    match api_key_header {
        None => "anonymous".to_string(),
        Some(_) if audit_anonymize_enabled() => format!("anon:{}", generate_id()),
        Some(k) => format!("key:{}", api_key_bucket(k)),
    }
}

/// Generate a simple random ID (hex string).
fn generate_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hash an API key with SHA-256.
pub fn hash_api_key(key: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(key.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Verify API key (constant-time comparison of SHA-256 hashes).
pub fn verify_api_key_hash(expected_hash: &[u8; 32], provided: &str) -> bool {
    let provided_hash = hash_api_key(provided);
    let mut result = 0u8;
    for (a, b) in expected_hash.iter().zip(provided_hash.iter()) {
        result |= a ^ b;
    }
    result == 0
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_guard(req: &ScanRequest) -> Result<InputGuard, String> {
    let presets: Vec<Preset> = req
        .presets
        .iter()
        .filter_map(|s| match s.to_lowercase().replace('-', "_").as_str() {
            "pci_dss" => Some(Preset::PciDss),
            "ssn_sin" => Some(Preset::SsnSin),
            "pii" => Some(Preset::Pii),
            "pii_strict" => Some(Preset::PiiStrict),
            "credentials" => Some(Preset::Credentials),
            "financial" => Some(Preset::Financial),
            "healthcare" => Some(Preset::Healthcare),
            "contact_info" => Some(Preset::ContactInfo),
            _ => None,
        })
        .collect();

    let action = match req.action.to_lowercase().as_str() {
        "reject" => Action::Reject,
        "redact" => Action::Redact,
        "tokenize" => Action::Tokenize,
        "obfuscate" => Action::Obfuscate,
        _ => Action::Flag,
    };

    let mut guard = InputGuard::new()
        .with_presets(presets)
        .with_action(action)
        .with_min_confidence(req.min_confidence)
        .with_require_context(req.require_context);

    if !req.categories.is_empty() {
        let cats: HashSet<String> = req.categories.iter().cloned().collect();
        guard = guard.with_categories(cats);
    }

    Ok(guard)
}

/// Load EDM state from DLPSCAN_EDM_STATE env var path if set.
#[cfg(feature = "async-support")]
fn load_edm_from_env() -> Option<std::sync::Arc<crate::edm::ExactDataMatcher>> {
    let path = std::env::var("DLPSCAN_EDM_STATE").ok()?;
    match crate::edm::ExactDataMatcher::load(&path) {
        Ok(edm) => {
            tracing::info!(
                "Loaded EDM state from {path} ({} hashes)",
                edm.total_hashes()
            );
            Some(std::sync::Arc::new(edm))
        }
        Err(e) => {
            tracing::warn!("Failed to load EDM state from {path}: {e}");
            None
        }
    }
}

/// Load LSH state from DLPSCAN_LSH_STATE env var path if set.
#[cfg(feature = "async-support")]
fn load_lsh_from_env() -> Option<std::sync::Arc<crate::lsh::DocumentVault>> {
    let path = std::env::var("DLPSCAN_LSH_STATE").ok()?;
    match crate::lsh::DocumentVault::load(&path) {
        Ok(vault) => {
            tracing::info!(
                "Loaded LSH vault from {path} ({} documents)",
                vault.document_count()
            );
            Some(std::sync::Arc::new(vault))
        }
        Err(e) => {
            tracing::warn!("Failed to load LSH vault from {path}: {e}");
            None
        }
    }
}

fn scan_result_to_response(result: &ScanResult) -> ScanResponse {
    ScanResponse {
        is_clean: result.is_clean,
        finding_count: result.finding_count(),
        categories_found: result.categories_found.iter().cloned().collect(),
        redacted_text: result.redacted_text.clone(),
        findings: result
            .findings
            .iter()
            .map(|m| FindingResponse {
                // Always fully masked on the external API surface. Use
                // Match::masked_text() (not redacted_text()) so no portion
                // of the matched value leaks through the response body.
                text: m.masked_text(),
                category: m.category.clone(),
                sub_category: m.sub_category.clone(),
                confidence: m.confidence,
                has_context: m.has_context,
                span: m.span,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Server (requires async-support feature) — hyper-based HTTP/1.1 + HTTP/2
// ---------------------------------------------------------------------------

#[cfg(feature = "async-support")]
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Start the API server with HTTP/1.1 and HTTP/2 support via hyper.
#[cfg(feature = "async-support")]
pub async fn serve(config: ApiConfig) -> Result<(), Box<dyn std::error::Error>> {
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HttpBuilder;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(
        "dlpscan API server listening on {} (HTTP/1.1 + HTTP/2)",
        addr
    );

    // Load API key-to-role mapping (store hashed keys, never plaintext)
    let api_key_roles: HashMap<[u8; 32], crate::rbac::Role> =
        std::env::var("DLPSCAN_API_KEY_ROLES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, ':');
                let key = parts.next()?.trim().to_string();
                let role_str = parts.next()?.trim().to_lowercase();
                let role = match role_str.as_str() {
                    "admin" => crate::rbac::Role::Admin,
                    "analyst" => crate::rbac::Role::Analyst,
                    "operator" => crate::rbac::Role::Operator,
                    _ => crate::rbac::Role::Viewer,
                };
                if key.is_empty() {
                    None
                } else {
                    Some((hash_api_key(&key), role))
                }
            })
            .collect();

    // Store only the hash of the API key, never the plaintext
    let api_key_hash = config.api_key.as_deref().map(hash_api_key);

    // Optional Redis-backed distributed rate limiter. When
    // `DLPSCAN_RATE_LIMIT_REDIS_URL` is set we try to connect at
    // startup. A failure here is logged but does NOT abort startup —
    // the in-memory limiter keeps the API online.
    #[cfg(feature = "redis-rate-limit")]
    let redis_rate_limiter = match std::env::var("DLPSCAN_RATE_LIMIT_REDIS_URL") {
        Ok(url) if !url.is_empty() => {
            match crate::redis_rate_limit::RedisRateLimiter::new(&url, config.rate_limit, 60) {
                Ok(rl) => {
                    tracing::info!(
                        "Distributed rate limiting enabled (redis, {}/{}s per client)",
                        rl.max_requests(),
                        rl.window_secs()
                    );
                    Some(rl)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to connect to Redis for distributed rate limiting: {}. \
                         Falling back to in-memory limiter.",
                        e
                    );
                    None
                }
            }
        }
        _ => None,
    };

    let state = Arc::new(AppState {
        api_key_hash: RwLock::new(api_key_hash),
        rate_limiter: RwLock::new(RateLimiter::new(config.rate_limit, 60)),
        #[cfg(feature = "redis-rate-limit")]
        redis_rate_limiter,
        vaults: RwLock::new(HashMap::new()),
        custom_patterns: RwLock::new(Vec::new()),
        start_time: Instant::now(),
        is_shutting_down: std::sync::atomic::AtomicBool::new(false),
        api_key_roles: RwLock::new(api_key_roles),
        edm: RwLock::new(load_edm_from_env()),
        lsh: RwLock::new(load_lsh_from_env()),
    });

    // Background task: evict expired vaults every 60 seconds
    {
        let vaults = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Catch panics to prevent silent task death
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    evict_expired_vaults(&vaults.vaults);
                }))
                .is_err()
                {
                    tracing::error!("Vault eviction task panicked — recovering");
                }
            }
        });
    }

    // Background task: rate-limiter cleanup every 60 seconds, independent
    // of request traffic. Without this, idle clients accumulate stale
    // entries in the in-memory map and only get evicted when a request
    // happens to hit the inline cleanup path — meaning a low-traffic API
    // can hold onto memory for clients that have long since gone away.
    {
        let rl_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Ok(mut rl) = rl_state.rate_limiter.write() {
                    rl.cleanup();
                }
            }
        });
    }

    // Graceful shutdown signal
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }
    };
    tokio::pin!(shutdown);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    // Single shared HTTP builder reused across connections (matches the
    // upstream hyper-util `server_graceful` example).
    let _http_builder = HttpBuilder::new(TokioExecutor::new());

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("Accept error: {}", e);
                        continue;
                    }
                };
                let state = state.clone();
                let io = TokioIo::new(stream);
                let peer = peer_addr.to_string();

                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let peer = peer.clone();
                    async move {
                        let request_start = Instant::now();
                        let request_id = generate_id();
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();

                        let span = tracing::info_span!("http_request",
                            request_id = %request_id,
                            method = %method,
                            path = %path,
                            peer = %peer,
                        );
                        let _enter = span.enter();

                        // Extract API key header before consuming body
                        let api_key_header = req.headers()
                            .get("x-api-key")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());

                        // Pre-check Content-Length before reading body to avoid OOM
                        if let Some(cl) = req.headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok())
                        {
                            if cl > MAX_REQUEST_BODY_SIZE {
                                return Ok::<_, hyper::Error>(
                                    build_hyper_response(StatusCode::PAYLOAD_TOO_LARGE,
                                        r#"{"detail":"Request body too large"}"#,
                                        &request_id)
                                );
                            }
                        }

                        // Read body with size limit
                        let body_bytes = match req.collect().await {
                            Ok(collected) => {
                                let b = collected.to_bytes();
                                if b.len() > MAX_REQUEST_BODY_SIZE {
                                    return Ok::<_, hyper::Error>(
                                        build_hyper_response(StatusCode::PAYLOAD_TOO_LARGE,
                                            r#"{"detail":"Request body too large"}"#,
                                            &request_id)
                                    );
                                }
                                b
                            }
                            Err(_) => bytes::Bytes::new(),
                        };

                        let body_str = String::from_utf8_lossy(&body_bytes).to_string();

                        let (status_code, response_body) = hyper_route_request(
                            &method, &path, &body_str, api_key_header.as_deref(),
                            &state, &peer,
                        );

                        let duration_ms = request_start.elapsed().as_secs_f64() * 1000.0;
                        tracing::info!(
                            status = status_code.as_u16(),
                            duration_ms = duration_ms,
                            "request completed"
                        );

                        Ok(build_hyper_response(status_code, &response_body, &request_id))
                    }
                });

                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    // Create the builder inside the task so it owns it for
                    // the duration of the connection future.
                    let builder = HttpBuilder::new(hyper_util::rt::TokioExecutor::new());
                    let conn = builder.serve_connection_with_upgrades(io, svc);
                    let conn = watcher.watch(conn);
                    if let Err(e) = conn.await {
                        tracing::debug!("Connection error: {}", e);
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("Shutdown signal received, draining connections...");
                state.is_shutting_down.store(true, Ordering::SeqCst);
                let shutdown_future = graceful.shutdown();
                tokio::pin!(shutdown_future);
                tokio::select! {
                    _ = &mut shutdown_future => {
                        tracing::info!("All connections drained, shutting down");
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(25)) => {
                        tracing::warn!("Drain timeout reached, forcing shutdown");
                    }
                }
                return Ok(());
            }
        }
    }
}

/// Build an HTTP response with security headers.
#[cfg(feature = "async-support")]
fn build_hyper_response(
    status: hyper::StatusCode,
    body: &str,
    request_id: &str,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", "default-src 'none'")
        .header("cache-control", "no-store")
        .header("x-xss-protection", "0")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.to_string(),
        )))
        .unwrap_or_else(|_| {
            hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from("{}")))
        })
}

/// Check authentication. Returns the expected hash (for health endpoint auth check)
/// and an error response if auth fails.
#[cfg(feature = "async-support")]
fn check_auth(
    path: &str,
    api_key_header: Option<&str>,
    state: &AppState,
) -> (Option<[u8; 32]>, Option<(hyper::StatusCode, String)>) {
    let auth_exempt = path == "/health" || path == "/health/live" || path == "/health/ready";

    // Read the configured API key hash. The previous implementation
    // collapsed a poisoned lock to None via `.ok()`, which silently
    // bypassed authentication — a poisoned RwLock meant requests
    // looked identical to "no auth configured" and were allowed
    // through. Fail closed instead: on lock poisoning return
    // 503 Service Unavailable and refuse the request entirely.
    let expected_hash = match state.api_key_hash.read() {
        Ok(guard) => *guard,
        Err(_) => {
            tracing::error!(
                path = %path,
                "API key hash lock poisoned — refusing request to fail closed"
            );
            return (
                None,
                Some((
                    hyper::StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"detail":"Service in degraded state"}"#.to_string(),
                )),
            );
        }
    };

    if expected_hash.is_some() && !auth_exempt {
        if let Some(ref hash) = expected_hash {
            match api_key_header {
                Some(provided) if verify_api_key_hash(hash, provided) => {}
                _ => {
                    return (
                        expected_hash,
                        Some((
                            hyper::StatusCode::UNAUTHORIZED,
                            r#"{"detail":"Invalid or missing API key"}"#.to_string(),
                        )),
                    )
                }
            }
        }
    }
    (expected_hash, None)
}

/// Resolve RBAC role and check permission for the endpoint.
#[cfg(feature = "async-support")]
fn check_rbac(
    method: &str,
    path: &str,
    api_key_header: Option<&str>,
    state: &AppState,
) -> Result<crate::rbac::Role, (hyper::StatusCode, String)> {
    let role = api_key_header
        .and_then(|key| {
            let h = hash_api_key(key);
            state
                .api_key_roles
                .read()
                .ok()
                .and_then(|roles| roles.get(&h).copied())
        })
        .unwrap_or(crate::rbac::Role::Operator);

    let required_perm = match (method, path) {
        ("POST", "/v1/scan") => Some(crate::rbac::Permission::Scan),
        ("POST", "/v1/batch/scan") => Some(crate::rbac::Permission::BatchScan),
        ("POST", "/v1/patterns") => Some(crate::rbac::Permission::ManagePatterns),
        ("POST", "/v1/tokenize") => Some(crate::rbac::Permission::Scan),
        ("POST", "/v1/detokenize") => Some(crate::rbac::Permission::Detokenize),
        ("POST", "/v1/obfuscate") => Some(crate::rbac::Permission::Scan),
        ("GET", "/v1/patterns") => Some(crate::rbac::Permission::ManagePatterns),
        ("GET", "/metrics") => Some(crate::rbac::Permission::ViewStatus),
        ("POST", "/v1/edm/register") => Some(crate::rbac::Permission::AdminAction),
        ("GET", "/v1/edm/categories") => Some(crate::rbac::Permission::ViewStatus),
        ("POST", "/v1/lsh/register") => Some(crate::rbac::Permission::AdminAction),
        ("POST", "/v1/lsh/query") => Some(crate::rbac::Permission::Scan),
        ("GET", "/v1/lsh/documents") => Some(crate::rbac::Permission::ViewStatus),
        _ => None,
    };
    if let Some(perm) = required_perm {
        if !crate::rbac::role_has_permission(role, perm) {
            return Err((
                hyper::StatusCode::FORBIDDEN,
                r#"{"detail":"Insufficient permissions"}"#.to_string(),
            ));
        }
    }
    Ok(role)
}

/// Check rate limit. Returns error response if rate limited.
#[cfg(feature = "async-support")]
fn check_rate_limit(
    path: &str,
    api_key_header: Option<&str>,
    state: &AppState,
    client_ip: &str,
) -> Option<(hyper::StatusCode, String)> {
    let auth_exempt = path == "/health" || path == "/health/live" || path == "/health/ready";
    if auth_exempt {
        return None;
    }
    let rate_key = api_key_header
        .map(|k| format!("key:{}", api_key_bucket(k)))
        .unwrap_or_else(|| format!("ip:{client_ip}"));

    // Distributed path: consult the Redis limiter first if configured.
    // A Redis error falls through to the in-memory limiter so a Redis
    // outage does not take the API offline.
    #[cfg(feature = "redis-rate-limit")]
    {
        if let Some(ref redis_rl) = state.redis_rate_limiter {
            match redis_rl.check_client(&rate_key) {
                Ok(true) => return None,
                Ok(false) => {
                    tracing::warn!(client_ip = %client_ip, rate_key = %rate_key, path = %path, backend = "redis", "Rate limit exceeded");
                    if let Ok(event) = crate::audit::AuditEvent::new("REJECT") {
                        let event = event
                            .with_action("rate_limit")
                            .with_source_ip(client_ip)
                            .with_outcome("rejected")
                            .with_user(&audit_user_field(api_key_header))
                            .with_metadata("reason", serde_json::json!("rate_limit_exceeded"))
                            .with_metadata("backend", serde_json::json!("redis"))
                            .with_metadata("path", serde_json::json!(path));
                        crate::audit::audit_event(&event);
                    }
                    return Some((
                        hyper::StatusCode::TOO_MANY_REQUESTS,
                        r#"{"detail":"Rate limit exceeded"}"#.to_string(),
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Redis rate limiter error — falling back to in-memory limiter");
                }
            }
        }
    }

    if let Ok(mut rl) = state.rate_limiter.write() {
        if !rl.check_client(&rate_key) {
            tracing::warn!(client_ip = %client_ip, rate_key = %rate_key, path = %path, "Rate limit exceeded");
            if let Ok(event) = crate::audit::AuditEvent::new("REJECT") {
                let event = event
                    .with_action("rate_limit")
                    .with_source_ip(client_ip)
                    .with_outcome("rejected")
                    .with_user(&audit_user_field(api_key_header))
                    .with_metadata("reason", serde_json::json!("rate_limit_exceeded"))
                    .with_metadata("path", serde_json::json!(path));
                crate::audit::audit_event(&event);
            }
            return Some((
                hyper::StatusCode::TOO_MANY_REQUESTS,
                r#"{"detail":"Rate limit exceeded"}"#.to_string(),
            ));
        }
        // Cleanup runs on a 60s background task instead of inline per-request
        // so high-throughput requests don't pay the eviction cost and so
        // idle APIs still bound memory growth.
    }
    None
}

/// Route an HTTP request to the appropriate handler.
#[cfg(feature = "async-support")]
fn hyper_route_request(
    method: &str,
    path: &str,
    body: &str,
    api_key_header: Option<&str>,
    state: &AppState,
    client_ip: &str,
) -> (hyper::StatusCode, String) {
    use hyper::StatusCode;

    // 1. Auth
    let (expected_hash, auth_err) = check_auth(path, api_key_header, state);
    if let Some(err) = auth_err {
        return err;
    }

    // 2. RBAC
    let role = match check_rbac(method, path, api_key_header, state) {
        Ok(r) => r,
        Err(err) => return err,
    };

    // 3. Rate limiting
    if let Some(err) = check_rate_limit(path, api_key_header, state, client_ip) {
        return err;
    }

    // 4. Route dispatch
    match (method, path) {
        ("GET", "/health") => {
            // Authenticated users get full health details; unauthenticated get minimal.
            // When no API key is configured, return minimal response (defense-in-depth).
            let is_authed = match expected_hash.as_ref() {
                Some(h) => api_key_header
                    .map(|k| verify_api_key_hash(h, k))
                    .unwrap_or(false),
                None => false, // No key configured = minimal response
            };
            if is_authed {
                let resp = handle_health_full(state, 0);
                (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                )
            } else {
                (StatusCode::OK, r#"{"status":"ok"}"#.to_string())
            }
        }
        ("GET", "/health/live") => (StatusCode::OK, r#"{"status":"ok"}"#.to_string()),
        ("GET", "/health/ready") => {
            if state.is_shutting_down.load(Ordering::SeqCst) {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"status":"draining","is_ready":false}"#.to_string(),
                )
            } else {
                (
                    StatusCode::OK,
                    r#"{"status":"ok","is_ready":true}"#.to_string(),
                )
            }
        }
        #[cfg(feature = "metrics")]
        ("GET", "/metrics") => {
            let encoder = prometheus::TextEncoder::new();
            match encoder.encode_to_string(&prometheus::gather()) {
                Ok(output) => (StatusCode::OK, output),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
            }
        }
        #[cfg(not(feature = "metrics"))]
        ("GET", "/metrics") => (
            StatusCode::NOT_IMPLEMENTED,
            r#"{"detail":"Metrics not enabled"}"#.to_string(),
        ),
        ("POST", "/v1/scan") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_scan(&req) {
                Ok(resp) => (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    let status = http_status_for_scan_error(&e);
                    if status == StatusCode::UNPROCESSABLE_ENTITY {
                        tracing::info!("Scan rejected by policy: {}", e);
                        // Strip sentinel prefix for the client-facing message.
                        let detail = e
                            .strip_prefix("CLASSIFICATION_POLICY_VIOLATION: ")
                            .or_else(|| e.strip_prefix("SENSITIVE_DATA_DETECTED: "))
                            .unwrap_or(&e);
                        let body = serde_json::json!({
                            "detail": detail,
                            "code": if e.starts_with("CLASSIFICATION_POLICY_VIOLATION") {
                                "classification_policy_violation"
                            } else {
                                "sensitive_data_detected"
                            },
                        })
                        .to_string();
                        (status, body)
                    } else {
                        tracing::warn!("Scan error: {}", e);
                        (
                            StatusCode::BAD_REQUEST,
                            r#"{"detail":"Scan failed"}"#.to_string(),
                        )
                    }
                }
            },
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/batch/scan") => match serde_json::from_str::<BatchScanRequest>(body) {
            Ok(req) => match handle_batch_scan(&req) {
                Ok(resp) => (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Batch error: {}", e);
                    (
                        StatusCode::BAD_REQUEST,
                        r#"{"detail":"Batch scan failed"}"#.to_string(),
                    )
                }
            },
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/tokenize") => match serde_json::from_str::<TokenizeRequest>(body) {
            Ok(req) => match handle_tokenize(&req, &state.vaults) {
                Ok(resp) => (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Tokenize error: {}", e);
                    (
                        StatusCode::BAD_REQUEST,
                        r#"{"detail":"Tokenization failed"}"#.to_string(),
                    )
                }
            },
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/detokenize") => match serde_json::from_str::<DetokenizeRequest>(body) {
            Ok(req) => match handle_detokenize(&req, &state.vaults) {
                Ok(resp) => (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Detokenize error: {}", e);
                    (
                        StatusCode::BAD_REQUEST,
                        r#"{"detail":"Detokenization failed"}"#.to_string(),
                    )
                }
            },
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/obfuscate") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_obfuscate(&req) {
                Ok(resp) => (
                    StatusCode::OK,
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Obfuscate error: {}", e);
                    (
                        StatusCode::BAD_REQUEST,
                        r#"{"detail":"Obfuscation failed"}"#.to_string(),
                    )
                }
            },
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/patterns") => match serde_json::from_str::<PatternCreateRequest>(body) {
            Ok(req) => {
                if req.pattern.len() > MAX_PATTERN_LENGTH {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        r#"{"detail":"Pattern too long"}"#.to_string(),
                    );
                }
                // Compile with tight memory caps. The Rust regex crate is
                // ReDoS-safe by construction (linear-time, no backrefs),
                // but its default size_limit (10 MB) and dfa_size_limit
                // (2 MB) are generous enough that an adversary submitting
                // a deliberately-large pattern can still extract a sizable
                // memory allocation. Cap user-supplied patterns at 1 MB
                // compiled / 256 KB DFA — well above what any legitimate
                // detection pattern needs and small enough that hundreds
                // of patterns still fit in a process's RSS budget.
                if regex::RegexBuilder::new(&req.pattern)
                    .size_limit(1 << 20) // 1 MB compiled regex
                    .dfa_size_limit(256 * 1024) // 256 KB DFA cache
                    .build()
                    .is_err()
                {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        r#"{"detail":"Invalid or oversized regex"}"#.to_string(),
                    );
                }
                if let Ok(patterns) = state.custom_patterns.read() {
                    if patterns.len() >= MAX_CUSTOM_PATTERNS {
                        return (
                            StatusCode::CONFLICT,
                            r#"{"detail":"Maximum custom pattern limit reached"}"#.to_string(),
                        );
                    }
                }
                let resp = PatternResponse {
                    name: req.name,
                    pattern: req.pattern,
                    category: req.category,
                    confidence: req.confidence,
                };
                if let Ok(mut patterns) = state.custom_patterns.write() {
                    patterns.push(resp.clone());
                }
                (
                    StatusCode::CREATED,
                    serde_json::to_string(&resp).unwrap_or_default(),
                )
            }
            Err(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("GET", "/v1/patterns") => {
            let patterns = state
                .custom_patterns
                .read()
                .map(|p| p.clone())
                .unwrap_or_default();
            (
                StatusCode::OK,
                serde_json::to_string(&patterns).unwrap_or_default(),
            )
        }
        ("POST", "/v1/admin/rotate-key") => {
            // Admin-only: rotate the API key at runtime
            if !crate::rbac::role_has_permission(role, crate::rbac::Permission::AdminAction) {
                return (
                    StatusCode::FORBIDDEN,
                    r#"{"detail":"Admin role required"}"#.to_string(),
                );
            }
            #[derive(Deserialize)]
            struct RotateKeyRequest {
                new_key: String,
            }
            match serde_json::from_str::<RotateKeyRequest>(body) {
                Ok(req) => {
                    let trimmed = req.new_key.trim();
                    if trimmed.len() < 16 {
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            r#"{"detail":"Key must be at least 16 non-whitespace characters"}"#
                                .to_string(),
                        );
                    }
                    if !trimmed.bytes().any(|b| !b.is_ascii_alphanumeric()) && trimmed.len() < 24 {
                        return (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Key must be at least 24 characters if purely alphanumeric"}"#.to_string());
                    }
                    rotate_api_key(state, trimmed);
                    // Audit the rotation event
                    if let Ok(event) = crate::audit::AuditEvent::new("SCAN") {
                        let event = event
                            .with_action("rotate_api_key")
                            .with_source_ip(client_ip)
                            .with_outcome("success")
                            .with_user(&audit_user_field(api_key_header));
                        crate::audit::audit_event(&event);
                    }
                    (
                        StatusCode::OK,
                        r#"{"detail":"API key rotated"}"#.to_string(),
                    )
                }
                Err(_) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    r#"{"detail":"Invalid request body"}"#.to_string(),
                ),
            }
        }
        // EDM: register values
        ("POST", "/v1/edm/register") => {
            if !crate::rbac::role_has_permission(role, crate::rbac::Permission::AdminAction) {
                return (
                    StatusCode::FORBIDDEN,
                    r#"{"detail":"Admin role required"}"#.to_string(),
                );
            }
            #[derive(Deserialize)]
            struct EdmRegisterReq {
                category: String,
                values: Vec<String>,
            }
            match serde_json::from_str::<EdmRegisterReq>(body) {
                Ok(req) => {
                    let refs: Vec<&str> = req.values.iter().map(|s| s.as_str()).collect();
                    // Create or update the shared EDM engine
                    let mut edm_guard = match state.edm.write() {
                        Ok(g) => g,
                        Err(_) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                r#"{"detail":"EDM lock error"}"#.to_string(),
                            )
                        }
                    };
                    let edm = edm_guard.get_or_insert_with(|| {
                        std::sync::Arc::new(crate::edm::ExactDataMatcher::new(None, None))
                    });
                    // Arc::make_mut clones if needed for shared ownership
                    let edm_mut = std::sync::Arc::make_mut(edm);
                    let count = edm_mut.register_values(&req.category, &refs);
                    (
                        StatusCode::OK,
                        serde_json::json!({
                            "category": req.category,
                            "registered": req.values.len(),
                            "total_hashes": count,
                        })
                        .to_string(),
                    )
                }
                Err(_) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    r#"{"detail":"Invalid request body"}"#.to_string(),
                ),
            }
        }
        // EDM: list categories
        ("GET", "/v1/edm/categories") => {
            let edm_guard = state.edm.read().unwrap_or_else(|e| e.into_inner());
            match edm_guard.as_ref() {
                Some(edm) => {
                    let cats = edm.categories();
                    (
                        StatusCode::OK,
                        serde_json::json!({
                            "categories": cats,
                            "total_hashes": edm.total_hashes(),
                        })
                        .to_string(),
                    )
                }
                None => (
                    StatusCode::OK,
                    r#"{"categories":[],"total_hashes":0}"#.to_string(),
                ),
            }
        }
        // LSH: register document
        ("POST", "/v1/lsh/register") => {
            if !crate::rbac::role_has_permission(role, crate::rbac::Permission::AdminAction) {
                return (
                    StatusCode::FORBIDDEN,
                    r#"{"detail":"Admin role required"}"#.to_string(),
                );
            }
            #[derive(Deserialize)]
            struct LshRegisterReq {
                doc_id: String,
                text: String,
                #[serde(default = "default_sensitivity")]
                sensitivity: String,
            }
            fn default_sensitivity() -> String {
                "sensitive".to_string()
            }
            match serde_json::from_str::<LshRegisterReq>(body) {
                Ok(req) => {
                    let mut lsh_guard = match state.lsh.write() {
                        Ok(g) => g,
                        Err(_) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                r#"{"detail":"LSH lock error"}"#.to_string(),
                            )
                        }
                    };
                    let vault = lsh_guard.get_or_insert_with(|| {
                        std::sync::Arc::new(crate::lsh::DocumentVault::default_vault())
                    });
                    // DocumentVault::register takes &self (interior mutability
                    // via Mutex), so we can call it directly on the Arc deref
                    // without needing Arc::make_mut.
                    vault.register(&req.doc_id, &req.text, &req.sensitivity, None);
                    (
                        StatusCode::OK,
                        serde_json::json!({
                            "doc_id": req.doc_id,
                            "document_count": vault.document_count(),
                        })
                        .to_string(),
                    )
                }
                Err(_) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    r#"{"detail":"Invalid request body"}"#.to_string(),
                ),
            }
        }
        // LSH: query similar documents
        ("POST", "/v1/lsh/query") => {
            #[derive(Deserialize)]
            struct LshQueryReq {
                text: String,
                #[serde(default = "default_threshold")]
                threshold: f64,
            }
            fn default_threshold() -> f64 {
                0.8
            }
            match serde_json::from_str::<LshQueryReq>(body) {
                Ok(req) => {
                    let lsh_guard = state.lsh.read().unwrap_or_else(|e| e.into_inner());
                    match lsh_guard.as_ref() {
                        Some(vault) => {
                            let matches = vault.query(&req.text, Some(req.threshold));
                            let results: Vec<serde_json::Value> = matches
                                .iter()
                                .map(|m| {
                                    serde_json::json!({
                                        "doc_id": m.doc_id,
                                        "similarity": (m.similarity * 10000.0).round() / 10000.0,
                                        "sensitivity": m.sensitivity,
                                    })
                                })
                                .collect();
                            (
                                StatusCode::OK,
                                serde_json::json!({"matches": results}).to_string(),
                            )
                        }
                        None => (StatusCode::OK, r#"{"matches":[]}"#.to_string()),
                    }
                }
                Err(_) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    r#"{"detail":"Invalid request body"}"#.to_string(),
                ),
            }
        }
        // LSH: list documents
        ("GET", "/v1/lsh/documents") => {
            let lsh_guard = state.lsh.read().unwrap_or_else(|e| e.into_inner());
            match lsh_guard.as_ref() {
                Some(vault) => (
                    StatusCode::OK,
                    serde_json::json!({
                        "document_count": vault.document_count(),
                    })
                    .to_string(),
                ),
                None => (StatusCode::OK, r#"{"document_count":0}"#.to_string()),
            }
        }
        _ => (
            StatusCode::NOT_FOUND,
            r#"{"detail":"Not found"}"#.to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health() {
        let resp = handle_health();
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn test_scan_clean() {
        let req = ScanRequest {
            text: "Hello world".to_string(),
            presets: vec![],
            categories: vec![],
            action: "flag".to_string(),
            min_confidence: 0.0,
            require_context: false,
        };
        let resp = handle_scan(&req).unwrap();
        assert!(resp.is_clean);
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = RateLimiter::new(3, 60);
        assert!(rl.check());
        assert!(rl.check());
        assert!(rl.check());
        assert!(!rl.check()); // exceeded
    }

    #[test]
    fn test_verify_api_key() {
        let hash = hash_api_key("secret123");
        assert!(verify_api_key_hash(&hash, "secret123"));
        assert!(!verify_api_key_hash(&hash, "wrong"));
        let hash2 = hash_api_key("short");
        assert!(!verify_api_key_hash(&hash2, "longer_key"));
    }

    #[test]
    fn test_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8000);
        assert_eq!(config.rate_limit, 100);
    }

    #[test]
    fn test_hash_api_key_deterministic() {
        let h1 = hash_api_key("test-key");
        let h2 = hash_api_key("test-key");
        assert_eq!(h1, h2);
        let h3 = hash_api_key("different-key");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_verify_api_key_hash_wrong_key() {
        let hash = hash_api_key("correct-key");
        assert!(!verify_api_key_hash(&hash, ""));
        assert!(!verify_api_key_hash(&hash, "wrong"));
        assert!(!verify_api_key_hash(&hash, "correct-ke")); // prefix
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_api_key_bucket_matches_hash_api_key() {
        // Regression: rate-limit bucketing and audit user IDs used to go
        // through a custom FNV-1a (md5_like_hash) while auth/RBAC used
        // SHA-256 via hash_api_key. That meant the "identity" of a key
        // differed across code paths, allowing bucket collisions and
        // mismatched audit entries. api_key_bucket must now be derived
        // directly from hash_api_key so every code path sees the same
        // canonical key identity.
        let k = "api-key-42";
        let full = hash_api_key(k);
        let bucket = api_key_bucket(k);
        // Bucket is 16 hex chars = first 8 bytes of the SHA-256.
        assert_eq!(bucket.len(), 16);
        let expected: String = full[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(bucket, expected);
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_api_key_bucket_deterministic_and_distinct() {
        assert_eq!(api_key_bucket("same"), api_key_bucket("same"));
        assert_ne!(api_key_bucket("alpha"), api_key_bucket("beta"));
    }

    #[cfg(feature = "async-support")]
    fn make_test_app_state(api_key: Option<&str>) -> AppState {
        AppState {
            api_key_hash: RwLock::new(api_key.map(hash_api_key)),
            rate_limiter: RwLock::new(RateLimiter::new(10_000, 60)),
            redis_rate_limiter: None,
            vaults: RwLock::new(HashMap::new()),
            custom_patterns: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            is_shutting_down: std::sync::atomic::AtomicBool::new(false),
            api_key_roles: RwLock::new(HashMap::new()),
            edm: RwLock::new(None),
            lsh: RwLock::new(None),
        }
    }

    #[cfg(feature = "async-support")]
    fn poison_rwlock<T>(lock: &RwLock<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.write().unwrap();
            panic!("intentional poison for test");
        }));
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_check_auth_fails_closed_on_poisoned_lock() {
        // Regression: the old implementation collapsed a poisoned
        // api_key_hash lock to None via .ok(), which made it look like
        // "no auth configured" and silently allowed every request
        // through. After the fix a poisoned lock must return
        // 503 Service Unavailable and reject the request.
        let state = make_test_app_state(Some("some-secret-key"));
        poison_rwlock(&state.api_key_hash);
        let (hash, err) = check_auth("/v1/scan", Some("some-secret-key"), &state);
        assert!(hash.is_none(), "poisoned lock should not surface a hash");
        let (status, _body) = err.expect("poisoned lock must produce an error response");
        assert_eq!(status, hyper::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_check_auth_allows_when_no_key_configured() {
        // Sanity: with no API key configured the function must return
        // (None, None) — requests pass through untouched. This catches
        // any regression that lumps "no auth configured" into the new
        // fail-closed path.
        let state = make_test_app_state(None);
        let (hash, err) = check_auth("/v1/scan", None, &state);
        assert!(hash.is_none());
        assert!(err.is_none());
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_check_auth_rejects_bad_key() {
        let state = make_test_app_state(Some("correct-key"));
        let (_, err) = check_auth("/v1/scan", Some("wrong-key"), &state);
        let (status, _body) = err.expect("bad key must produce an error");
        assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_check_auth_accepts_good_key() {
        let state = make_test_app_state(Some("correct-key"));
        let (_, err) = check_auth("/v1/scan", Some("correct-key"), &state);
        assert!(err.is_none());
    }

    #[test]
    fn test_rate_limiter_per_client() {
        let mut rl = RateLimiter::new(2, 60);
        assert!(rl.check_client("ip:1.1.1.1"));
        assert!(rl.check_client("ip:1.1.1.1"));
        assert!(!rl.check_client("ip:1.1.1.1")); // exhausted
                                                 // Different client still has quota
        assert!(rl.check_client("ip:2.2.2.2"));
        assert!(rl.check_client("key:abc123"));
    }

    #[test]
    fn test_vault_ttl_enforcement() {
        let vaults: RwLock<HashMap<String, VaultEntry>> = RwLock::new(HashMap::new());
        let vault = crate::guard::TokenVault::new("TOK", None);
        // Insert a vault with created_at in the past (simulate expiry)
        vaults.write().unwrap().insert(
            "test-vault".to_string(),
            VaultEntry {
                vault,
                created_at: Instant::now() - std::time::Duration::from_secs(VAULT_TTL_SECS + 1),
            },
        );
        // Detokenize should fail for expired vault
        let req = DetokenizeRequest {
            text: "some text".to_string(),
            vault_id: "test-vault".to_string(),
        };
        let result = handle_detokenize(&req, &vaults);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_evict_expired_vaults() {
        let vaults: RwLock<HashMap<String, VaultEntry>> = RwLock::new(HashMap::new());
        // Insert expired vault
        vaults.write().unwrap().insert(
            "expired".to_string(),
            VaultEntry {
                vault: crate::guard::TokenVault::new("TOK", None),
                created_at: Instant::now() - std::time::Duration::from_secs(VAULT_TTL_SECS + 1),
            },
        );
        // Insert active vault
        vaults.write().unwrap().insert(
            "active".to_string(),
            VaultEntry {
                vault: crate::guard::TokenVault::new("TOK", None),
                created_at: Instant::now(),
            },
        );
        evict_expired_vaults(&vaults);
        let guard = vaults.read().unwrap();
        assert!(!guard.contains_key("expired"));
        assert!(guard.contains_key("active"));
    }

    #[cfg(feature = "async-support")]
    #[test]
    fn test_pattern_length_limit() {
        let long_pattern = "a".repeat(3000);
        assert_eq!(MAX_PATTERN_LENGTH, 2048);
        assert!(long_pattern.len() > MAX_PATTERN_LENGTH);
    }
}
