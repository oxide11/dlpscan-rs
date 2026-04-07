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
const VAULT_TTL_SECS: u64 = 3600;

/// Shared application state for the API server.
pub struct AppState {
    /// SHA-256 hash of the configured API key (never stores plaintext).
    pub api_key_hash: Option<[u8; 32]>,
    pub rate_limiter: RwLock<RateLimiter>,
    pub vaults: RwLock<HashMap<String, VaultEntry>>,
    pub custom_patterns: RwLock<Vec<PatternResponse>>,
    pub start_time: Instant,
    pub is_shutting_down: std::sync::atomic::AtomicBool,
    /// Server-side API key hash-to-role mapping. If populated, roles are derived
    /// from the authenticated key, not the client-supplied X-Role header.
    pub api_key_roles: HashMap<[u8; 32], crate::rbac::Role>,
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
    let result = guard.scan(&req.text).map_err(|e| format!("{e}"))?;
    Ok(scan_result_to_response(&result))
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
    let result = guard.scan(&req.text).map_err(|e| format!("{e}"))?;

    // Create a vault and tokenize all findings
    let vault_id = generate_id();
    let mut vault = TokenVault::new("TOK", None);
    let mut tokenized = req.text.clone();

    // Sort findings by position descending to replace from end to start
    let mut findings: Vec<_> = result.findings.iter().collect();
    findings.sort_by(|a, b| b.span.0.cmp(&a.span.0));

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
    let entry = vaults
        .get(&req.vault_id)
        .ok_or("Vault not found")?;
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
    let result = guard.scan(&obf_req.text).map_err(|e| format!("{e}"))?;
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


/// Quick hash for rate-limit key derivation (not cryptographic, just for bucketing).
#[cfg(feature = "async-support")]
fn md5_like_hash(input: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in input.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Generate a simple random ID (hex string).
fn generate_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
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
                text: m.redacted_text(),
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
    use hyper::server::conn::auto::Builder as HttpBuilder;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper::body::Incoming;
    use hyper_util::rt::TokioIo;
    use http_body_util::{BodyExt, Full};
    use bytes::Bytes;
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("dlpscan API server listening on {} (HTTP/1.1 + HTTP/2)", addr);

    // Load API key-to-role mapping (store hashed keys, never plaintext)
    let api_key_roles: HashMap<[u8; 32], crate::rbac::Role> = std::env::var("DLPSCAN_API_KEY_ROLES")
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
            if key.is_empty() { None } else { Some((hash_api_key(&key), role)) }
        })
        .collect();

    // Store only the hash of the API key, never the plaintext
    let api_key_hash = config.api_key.as_deref().map(hash_api_key);

    let state = Arc::new(AppState {
        api_key_hash,
        rate_limiter: RwLock::new(RateLimiter::new(config.rate_limit, 60)),
        vaults: RwLock::new(HashMap::new()),
        custom_patterns: RwLock::new(Vec::new()),
        start_time: Instant::now(),
        is_shutting_down: std::sync::atomic::AtomicBool::new(false),
        api_key_roles,
    });

    // Background task: evict expired vaults every 60 seconds
    {
        let vaults = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                evict_expired_vaults(&vaults.vaults);
            }
        });
    }

    // Graceful shutdown signal
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to install SIGTERM handler");
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

                let conn = HttpBuilder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc);
                let conn = graceful.watch(conn);

                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("Connection error: {}", e);
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("Shutdown signal received, draining connections...");
                state.is_shutting_down.store(true, Ordering::SeqCst);
                tokio::pin!(let shutdown_future = graceful.shutdown());
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
        .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
        .unwrap_or_else(|_| hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from("{}"))))
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

    // Auth check (exempt health probes only; metrics requires auth)
    let auth_exempt = path == "/health" || path == "/health/live"
        || path == "/health/ready";
    if state.api_key_hash.is_some() && !auth_exempt {
        if let Some(expected_hash) = &state.api_key_hash {
            match api_key_header {
                Some(provided) if verify_api_key_hash(expected_hash, provided) => {}
                _ => return (StatusCode::UNAUTHORIZED, r#"{"detail":"Invalid or missing API key"}"#.to_string()),
            }
        }
    }

    // RBAC (resolve role from hashed key)
    let role = {
        let resolved = api_key_header.and_then(|key| {
            let h = hash_api_key(key);
            state.api_key_roles.get(&h).copied()
        });
        resolved.unwrap_or(crate::rbac::Role::Operator)
    };
    let required_perm = match (method, path) {
        ("POST", "/v1/scan") => Some(crate::rbac::Permission::Scan),
        ("POST", "/v1/batch/scan") => Some(crate::rbac::Permission::BatchScan),
        ("POST", "/v1/patterns") => Some(crate::rbac::Permission::ManagePatterns),
        ("POST", "/v1/tokenize") => Some(crate::rbac::Permission::Scan),
        ("POST", "/v1/detokenize") => Some(crate::rbac::Permission::Detokenize),
        ("POST", "/v1/obfuscate") => Some(crate::rbac::Permission::Scan),
        _ => None,
    };
    if let Some(perm) = required_perm {
        if !crate::rbac::role_has_permission(role, perm) {
            return (StatusCode::FORBIDDEN, r#"{"detail":"Insufficient permissions"}"#.to_string());
        }
    }

    // Rate limiting (per API key when available, otherwise per IP)
    if !auth_exempt {
        let rate_key = api_key_header
            .map(|k| format!("key:{:x}", md5_like_hash(k)))
            .unwrap_or_else(|| format!("ip:{client_ip}"));
        if let Ok(mut rl) = state.rate_limiter.write() {
            if !rl.check_client(&rate_key) {
                return (StatusCode::TOO_MANY_REQUESTS, r#"{"detail":"Rate limit exceeded"}"#.to_string());
            }
            rl.cleanup();
        }
    }

    // Route dispatch
    match (method, path) {
        ("GET", "/health") => {
            let resp = handle_health_full(state, 0);
            (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default())
        }
        ("GET", "/health/live") => (StatusCode::OK, r#"{"status":"ok"}"#.to_string()),
        ("GET", "/health/ready") => {
            if state.is_shutting_down.load(Ordering::SeqCst) {
                (StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"draining","is_ready":false}"#.to_string())
            } else {
                (StatusCode::OK, r#"{"status":"ok","is_ready":true}"#.to_string())
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
        ("GET", "/metrics") => (StatusCode::NOT_IMPLEMENTED, r#"{"detail":"Metrics not enabled"}"#.to_string()),
        ("POST", "/v1/scan") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_scan(&req) {
                Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default()),
                Err(e) => { tracing::warn!("Scan error: {}", e); (StatusCode::BAD_REQUEST, r#"{"detail":"Scan failed"}"#.to_string()) }
            },
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("POST", "/v1/batch/scan") => match serde_json::from_str::<BatchScanRequest>(body) {
            Ok(req) => match handle_batch_scan(&req) {
                Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default()),
                Err(e) => { tracing::warn!("Batch error: {}", e); (StatusCode::BAD_REQUEST, r#"{"detail":"Batch scan failed"}"#.to_string()) }
            },
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("POST", "/v1/tokenize") => match serde_json::from_str::<TokenizeRequest>(body) {
            Ok(req) => match handle_tokenize(&req, &state.vaults) {
                Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default()),
                Err(e) => { tracing::warn!("Tokenize error: {}", e); (StatusCode::BAD_REQUEST, r#"{"detail":"Tokenization failed"}"#.to_string()) }
            },
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("POST", "/v1/detokenize") => match serde_json::from_str::<DetokenizeRequest>(body) {
            Ok(req) => match handle_detokenize(&req, &state.vaults) {
                Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default()),
                Err(e) => { tracing::warn!("Detokenize error: {}", e); (StatusCode::BAD_REQUEST, r#"{"detail":"Detokenization failed"}"#.to_string()) }
            },
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("POST", "/v1/obfuscate") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_obfuscate(&req) {
                Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_default()),
                Err(e) => { tracing::warn!("Obfuscate error: {}", e); (StatusCode::BAD_REQUEST, r#"{"detail":"Obfuscation failed"}"#.to_string()) }
            },
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("POST", "/v1/patterns") => match serde_json::from_str::<PatternCreateRequest>(body) {
            Ok(req) => {
                if req.pattern.len() > MAX_PATTERN_LENGTH {
                    return (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Pattern too long"}"#.to_string());
                }
                if regex::Regex::new(&req.pattern).is_err() {
                    return (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid regex"}"#.to_string());
                }
                if let Ok(patterns) = state.custom_patterns.read() {
                    if patterns.len() >= MAX_CUSTOM_PATTERNS {
                        return (StatusCode::CONFLICT, r#"{"detail":"Maximum custom pattern limit reached"}"#.to_string());
                    }
                }
                let resp = PatternResponse { name: req.name, pattern: req.pattern, category: req.category, confidence: req.confidence };
                if let Ok(mut patterns) = state.custom_patterns.write() { patterns.push(resp.clone()); }
                (StatusCode::CREATED, serde_json::to_string(&resp).unwrap_or_default())
            }
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, r#"{"detail":"Invalid request body"}"#.to_string()),
        },
        ("GET", "/v1/patterns") => {
            let patterns = state.custom_patterns.read().map(|p| p.clone()).unwrap_or_default();
            (StatusCode::OK, serde_json::to_string(&patterns).unwrap_or_default())
        }
        _ => (StatusCode::NOT_FOUND, r#"{"detail":"Not found"}"#.to_string()),
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
}
