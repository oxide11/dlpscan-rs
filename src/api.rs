//! HTTP API server for DLP scanning.
//!
//! Provides REST endpoints for scanning, tokenization, and pattern management.
//! Requires the `async-support` feature flag for the full server.
//! Handler functions work without async for testing and embedding.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
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
const MAX_CUSTOM_PATTERNS: usize = 100;

/// Maximum regex pattern length in characters.
const MAX_PATTERN_LENGTH: usize = 2048;

/// Maximum number of token vaults.
const MAX_VAULTS: usize = 1000;

/// Vault time-to-live in seconds (1 hour).
const VAULT_TTL_SECS: u64 = 3600;

/// Shared application state for the API server.
pub struct AppState {
    pub api_key: Option<String>,
    pub rate_limiter: RwLock<RateLimiter>,
    pub vaults: RwLock<HashMap<String, VaultEntry>>,
    pub custom_patterns: RwLock<Vec<PatternResponse>>,
    pub start_time: Instant,
    pub is_shutting_down: std::sync::atomic::AtomicBool,
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

    /// Check if a request from a specific client IP is allowed.
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
        let active = self.clients.get("global")
            .map(|reqs| reqs.iter().filter(|&&t| now.duration_since(t) < self.window).count())
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
                    tracing::warn!("DLPSCAN_API_KEY not set — API server running without authentication");
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
    let result = guard
        .scan(&req.text)
        .map_err(|e| format!("{e}"))?;
    Ok(scan_result_to_response(&result))
}

/// Process a batch scan request.
pub fn handle_batch_scan(req: &BatchScanRequest) -> Result<BatchScanResponse, String> {
    const MAX_BATCH_ITEMS: usize = 1000;
    const MAX_TEXT_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if req.items.len() > MAX_BATCH_ITEMS {
        return Err(format!("Batch size {} exceeds maximum {}", req.items.len(), MAX_BATCH_ITEMS));
    }
    for item in &req.items {
        if item.text.len() > MAX_TEXT_SIZE {
            return Err(format!("Text size {} exceeds maximum {}", item.text.len(), MAX_TEXT_SIZE));
        }
    }

    use rayon::prelude::*;
    let results: Vec<Result<ScanResponse, String>> =
        req.items.par_iter().map(|item| handle_scan(item)).collect();

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
        if start <= end && end <= tokenized.len()
            && tokenized.is_char_boundary(start)
            && tokenized.is_char_boundary(end)
        {
            tokenized.replace_range(start..end, &token);
        }
    }

    let token_count = vault.size();
    if let Ok(mut vaults) = vaults.write() {
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
        .ok_or_else(|| format!("Vault '{}' not found", req.vault_id))?;
    let original = entry.vault.detokenize_text(&req.text);
    Ok(DetokenizeResponse {
        original_text: original,
    })
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
fn handle_health_full(state: &AppState, active: usize) -> HealthResponse {
    let shutting_down = state.is_shutting_down.load(Ordering::SeqCst);
    HealthResponse {
        status: if shutting_down { "draining".to_string() } else { "ok".to_string() },
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: Some(state.start_time.elapsed().as_secs()),
        pattern_count: Some(crate::patterns::PATTERNS.len()),
        active_connections: Some(active),
        is_ready: Some(!shutting_down),
    }
}

/// Generate a simple random ID (hex string).
fn generate_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify API key (constant-time comparison via SHA-256 hashing).
pub fn verify_api_key(expected: &str, provided: &str) -> bool {
    use sha2::{Sha256, Digest};
    let expected_hash = Sha256::digest(expected.as_bytes());
    let provided_hash = Sha256::digest(provided.as_bytes());
    let mut result = 0u8;
    for (a, b) in expected_hash.iter().zip(provided_hash.iter()) {
        result |= a ^ b;
    }
    result == 0
}

// ---------------------------------------------------------------------------
// Server (requires async-support feature)
// ---------------------------------------------------------------------------

const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB

#[cfg(feature = "async-support")]
pub async fn serve(config: ApiConfig) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;

    // Optional TLS: if DLPSCAN_TLS_CERT and DLPSCAN_TLS_KEY are set, enable HTTPS
    #[cfg(feature = "tls")]
    let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = {
        match (
            std::env::var("DLPSCAN_TLS_CERT"),
            std::env::var("DLPSCAN_TLS_KEY"),
        ) {
            (Ok(cert_path), Ok(key_path)) => {
                let cert_file = std::fs::File::open(&cert_path)
                    .map_err(|e| format!("Failed to open TLS cert {}: {}", cert_path, e))?;
                let key_file = std::fs::File::open(&key_path)
                    .map_err(|e| format!("Failed to open TLS key {}: {}", key_path, e))?;

                let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                    .filter_map(|r| r.ok())
                    .collect();
                let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
                    .map_err(|e| format!("Failed to read TLS key: {}", e))?
                    .ok_or("No private key found in TLS key file")?;

                let tls_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| format!("TLS config error: {}", e))?;

                tracing::info!("TLS enabled with cert={}, key={}", cert_path, key_path);
                Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config)))
            }
            _ => {
                tracing::info!("TLS not configured (set DLPSCAN_TLS_CERT and DLPSCAN_TLS_KEY to enable)");
                None
            }
        }
    };

    let proto = if cfg!(feature = "tls") { "https" } else { "http" };
    tracing::info!("dlpscan API server listening on {}://{}", proto, addr);

    let state = Arc::new(AppState {
        api_key: config.api_key,
        rate_limiter: RwLock::new(RateLimiter::new(config.rate_limit, 60)),
        vaults: RwLock::new(HashMap::new()),
        custom_patterns: RwLock::new(Vec::new()),
        start_time: Instant::now(),
        is_shutting_down: std::sync::atomic::AtomicBool::new(false),
    });

    let active_connections = Arc::new(AtomicUsize::new(0));

    // Graceful shutdown: listen for SIGTERM/SIGINT
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            )
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

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut socket, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("Accept error: {}", e);
                        continue;
                    }
                };
                let state = state.clone();
                let active_connections = active_connections.clone();

                if active_connections.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
                    let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"detail\":\"Too many concurrent connections\"}";
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes()).await;
                    continue;
                }

                active_connections.fetch_add(1, Ordering::SeqCst);

                tokio::spawn(async move {
                    struct ConnGuard(Arc<AtomicUsize>);
                    impl Drop for ConnGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    let _guard = ConnGuard(active_connections);
                    let request_start = Instant::now();
                    let request_id = simple_uuid();

                    let mut buf = vec![0u8; 1024 * 1024];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);

                    // Parse method + path for tracing
                    let first_line = request.lines().next().unwrap_or("");
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("?");
                    let path = parts.get(1).copied().unwrap_or("/");
                    let peer = peer_addr.to_string();

                    let span = tracing::info_span!("http_request",
                        request_id = %request_id,
                        method = %method,
                        path = %path,
                        peer = %peer,
                    );
                    let _enter = span.enter();

                    // Check Content-Length header and reject oversized requests
                    let content_length = request
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.splitn(2, ':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok());
                    if let Some(cl) = content_length {
                        if cl > MAX_REQUEST_BODY_SIZE {
                            let body = r#"{"detail":"Request body too large"}"#;
                            let response = format!(
                                "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body,
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            return;
                        }
                    }

                    let (status, body) = route_request(&request, &state);

                    let duration_ms = request_start.elapsed().as_secs_f64() * 1000.0;
                    tracing::info!(
                        status = %status,
                        duration_ms = duration_ms,
                        "request completed"
                    );

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Request-ID: {request_id}\r\n\r\n{body}",
                        body.len(),
                    );

                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
            _ = &mut shutdown => {
                tracing::info!("Shutdown signal received, draining connections...");
                state.is_shutting_down.store(true, Ordering::SeqCst);

                // Wait for in-flight connections to finish (max 25s)
                let drain_deadline = tokio::time::Instant::now()
                    + tokio::time::Duration::from_secs(25);
                loop {
                    let active = active_connections.load(Ordering::SeqCst);
                    if active == 0 {
                        tracing::info!("All connections drained, shutting down");
                        break;
                    }
                    if tokio::time::Instant::now() >= drain_deadline {
                        tracing::warn!(
                            "Drain timeout reached with {} active connections, forcing shutdown",
                            active
                        );
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                return Ok(());
            }
        }
    }
}

#[cfg(feature = "async-support")]
fn route_request(raw: &str, state: &AppState) -> (String, String) {
    let first_line = raw.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("/");

    // Extract body (after \r\n\r\n)
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");

    // Check API key if configured (exempt health and metrics endpoints)
    let auth_exempt = path == "/health" || path == "/health/live"
        || path == "/health/ready" || path == "/metrics";
    if state.api_key.is_some() && !auth_exempt {
        let api_key_header = raw
            .lines()
            .find(|l| l.to_lowercase().starts_with("x-api-key:"))
            .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim());

        if let Some(expected) = &state.api_key {
            match api_key_header {
                Some(provided) if verify_api_key(expected, provided) => {}
                _ => {
                    return (
                        "401 Unauthorized".to_string(),
                        r#"{"detail":"Invalid or missing API key"}"#.to_string(),
                    );
                }
            }
        }
    }

    // RBAC enforcement
    let role = crate::rbac::extract_role(raw);
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
            return (
                "403 Forbidden".to_string(),
                r#"{"detail":"Insufficient permissions"}"#.to_string(),
            );
        }
    }

    // Rate limiting (exempt health/metrics endpoints)
    if path != "/health" && path != "/health/live" && path != "/health/ready" && path != "/metrics"
    {
        if let Ok(mut rl) = state.rate_limiter.write() {
            if !rl.check() {
                return (
                    "429 Too Many Requests".to_string(),
                    r#"{"detail":"Rate limit exceeded"}"#.to_string(),
                );
            }
            rl.cleanup();
        }
        // Evict expired vaults
        if let Ok(mut vaults) = state.vaults.write() {
            let now = Instant::now();
            vaults.retain(|_, entry| {
                now.duration_since(entry.created_at).as_secs() < VAULT_TTL_SECS
            });
        }
    }

    match (method, path) {
        ("GET", "/health") => {
            let resp = handle_health_full(state, 0);
            (
                "200 OK".to_string(),
                serde_json::to_string(&resp).unwrap_or_default(),
            )
        }
        ("GET", "/health/live") => (
            "200 OK".to_string(),
            r#"{"status":"ok"}"#.to_string(),
        ),
        ("GET", "/health/ready") => {
            if state.is_shutting_down.load(Ordering::SeqCst) {
                (
                    "503 Service Unavailable".to_string(),
                    r#"{"status":"draining","is_ready":false}"#.to_string(),
                )
            } else {
                (
                    "200 OK".to_string(),
                    r#"{"status":"ok","is_ready":true}"#.to_string(),
                )
            }
        }
        #[cfg(feature = "metrics")]
        ("GET", "/metrics") => {
            let encoder = prometheus::TextEncoder::new();
            let metric_families = prometheus::gather();
            match encoder.encode_to_string(&metric_families) {
                Ok(output) => ("200 OK".to_string(), output),
                Err(e) => {
                    tracing::warn!("Failed to encode metrics: {}", e);
                    ("500 Internal Server Error".to_string(), String::new())
                }
            }
        }
        #[cfg(not(feature = "metrics"))]
        ("GET", "/metrics") => (
            "501 Not Implemented".to_string(),
            r#"{"detail":"Metrics feature not enabled"}"#.to_string(),
        ),
        ("POST", "/v1/scan") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_scan(&req) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Scan error: {}", e);
                    (
                        "400 Bad Request".to_string(),
                        r#"{"detail":"Scan failed. Check input size and format."}"#.to_string(),
                    )
                }
            },
            Err(_e) => (
                "422 Unprocessable Entity".to_string(),
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/batch/scan") => match serde_json::from_str::<BatchScanRequest>(body) {
            Ok(req) => match handle_batch_scan(&req) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Batch scan error: {}", e);
                    (
                        "400 Bad Request".to_string(),
                        r#"{"detail":"Batch scan failed. Check input size and format."}"#.to_string(),
                    )
                }
            },
            Err(_e) => (
                "422 Unprocessable Entity".to_string(),
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/patterns") => match serde_json::from_str::<PatternCreateRequest>(body) {
            Ok(req) => {
                // Enforce pattern length limit
                if req.pattern.len() > MAX_PATTERN_LENGTH {
                    return (
                        "422 Unprocessable Entity".to_string(),
                        serde_json::json!({"detail": format!(
                            "Pattern too long: {} chars (max {})", req.pattern.len(), MAX_PATTERN_LENGTH
                        )}).to_string(),
                    );
                }
                // Enforce pattern count limit
                if let Ok(patterns) = state.custom_patterns.read() {
                    if patterns.len() >= MAX_CUSTOM_PATTERNS {
                        return (
                            "429 Too Many Requests".to_string(),
                            serde_json::json!({"detail": format!(
                                "Maximum custom patterns reached ({})", MAX_CUSTOM_PATTERNS
                            )}).to_string(),
                        );
                    }
                }
                // Validate regex compiles
                if regex::Regex::new(&req.pattern).is_err() {
                    return (
                        "422 Unprocessable Entity".to_string(),
                        r#"{"detail":"Invalid regex pattern"}"#.to_string(),
                    );
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
                    "201 Created".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                )
            }
            Err(e) => (
                "422 Unprocessable Entity".to_string(),
                serde_json::json!({"detail": e.to_string()}).to_string(),
            ),
        },
        ("POST", "/v1/tokenize") => match serde_json::from_str::<TokenizeRequest>(body) {
            Ok(req) => match handle_tokenize(&req, &state.vaults) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Tokenize error: {}", e);
                    (
                        "400 Bad Request".to_string(),
                        r#"{"detail":"Tokenization failed"}"#.to_string(),
                    )
                }
            },
            Err(_e) => (
                "422 Unprocessable Entity".to_string(),
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/detokenize") => match serde_json::from_str::<DetokenizeRequest>(body) {
            Ok(req) => match handle_detokenize(&req, &state.vaults) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Detokenize error: {}", e);
                    (
                        "400 Bad Request".to_string(),
                        r#"{"detail":"Detokenization failed"}"#.to_string(),
                    )
                }
            },
            Err(_e) => (
                "422 Unprocessable Entity".to_string(),
                r#"{"detail":"Invalid request body"}"#.to_string(),
            ),
        },
        ("POST", "/v1/obfuscate") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_obfuscate(&req) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => {
                    tracing::warn!("Obfuscate error: {}", e);
                    (
                        "400 Bad Request".to_string(),
                        r#"{"detail":"Obfuscation failed"}"#.to_string(),
                    )
                }
            },
            Err(_e) => (
                "422 Unprocessable Entity".to_string(),
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
                "200 OK".to_string(),
                serde_json::to_string(&patterns).unwrap_or_default(),
            )
        }
        _ => (
            "404 Not Found".to_string(),
            r#"{"detail":"Not found"}"#.to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
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

#[cfg(feature = "async-support")]
fn simple_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.gen::<u32>(),
        rng.gen::<u16>(),
        rng.gen::<u16>() & 0x0FFF,
        (rng.gen::<u16>() & 0x3FFF) | 0x8000,
        rng.gen::<u64>() & 0xFFFFFFFFFFFF,
    )
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
        assert!(verify_api_key("secret123", "secret123"));
        assert!(!verify_api_key("secret123", "wrong"));
        assert!(!verify_api_key("short", "longer_key"));
    }

    #[test]
    fn test_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8000);
        assert_eq!(config.rate_limit, 100);
    }
}
