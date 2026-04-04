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

#[derive(Debug, Deserialize)]
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

/// Shared application state for the API server.
pub struct AppState {
    pub api_key: Option<String>,
    pub rate_limiter: RwLock<RateLimiter>,
    pub vaults: RwLock<HashMap<String, VaultEntry>>,
    pub custom_patterns: RwLock<Vec<PatternResponse>>,
}

pub struct VaultEntry {
    pub vault: TokenVault,
    pub created_at: Instant,
}

/// Simple sliding-window rate limiter.
pub struct RateLimiter {
    requests: Vec<Instant>,
    max_requests: usize,
    window: std::time::Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Vec::new(),
            max_requests,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Check if a request is allowed. Returns true if under limit.
    pub fn check(&mut self) -> bool {
        let now = Instant::now();
        self.requests.retain(|&t| now.duration_since(t) < self.window);
        if self.requests.len() < self.max_requests {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    /// Remaining requests in the current window.
    pub fn remaining(&self) -> usize {
        let now = Instant::now();
        let active = self
            .requests
            .iter()
            .filter(|&&t| now.duration_since(t) < self.window)
            .count();
        self.max_requests.saturating_sub(active)
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
            host: std::env::var("DLPSCAN_API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
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

/// Health check.
pub fn handle_health() -> HealthResponse {
    HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
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
    tracing::info!("dlpscan API server listening on {}", addr);

    let state = Arc::new(AppState {
        api_key: config.api_key,
        rate_limiter: RwLock::new(RateLimiter::new(config.rate_limit, 60)),
        vaults: RwLock::new(HashMap::new()),
        custom_patterns: RwLock::new(Vec::new()),
    });

    let active_connections = Arc::new(AtomicUsize::new(0));

    loop {
        let (mut socket, _) = listener.accept().await?;
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

            let mut buf = vec![0u8; 1024 * 1024];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);

            // Check Content-Length header and reject oversized requests
            let content_length = request
                .lines()
                .find(|l| l.to_lowercase().starts_with("content-length:"))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok());
            if let Some(cl) = content_length {
                if cl > MAX_REQUEST_BODY_SIZE {
                    let detail = serde_json::json!({"detail": format!("Request body size {} exceeds maximum {}", cl, MAX_REQUEST_BODY_SIZE)});
                    let body = detail.to_string();
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

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Request-ID: {}\r\n\r\n{body}",
                body.len(),
                simple_uuid(),
            );

            let _ = socket.write_all(response.as_bytes()).await;
        });
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

    // Check API key if configured
    if state.api_key.is_some() && path != "/health" {
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

    // Rate limiting
    if path != "/health" {
        if let Ok(mut rl) = state.rate_limiter.write() {
            if !rl.check() {
                return (
                    "429 Too Many Requests".to_string(),
                    r#"{"detail":"Rate limit exceeded"}"#.to_string(),
                );
            }
        }
    }

    match (method, path) {
        ("GET", "/health") => {
            let resp = handle_health();
            (
                "200 OK".to_string(),
                serde_json::to_string(&resp).unwrap_or_default(),
            )
        }
        ("POST", "/v1/scan") => match serde_json::from_str::<ScanRequest>(body) {
            Ok(req) => match handle_scan(&req) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => (
                    "400 Bad Request".to_string(),
                    serde_json::json!({"detail": e.to_string()}).to_string(),
                ),
            },
            Err(e) => (
                "422 Unprocessable Entity".to_string(),
                serde_json::json!({"detail": e.to_string()}).to_string(),
            ),
        },
        ("POST", "/v1/batch/scan") => match serde_json::from_str::<BatchScanRequest>(body) {
            Ok(req) => match handle_batch_scan(&req) {
                Ok(resp) => (
                    "200 OK".to_string(),
                    serde_json::to_string(&resp).unwrap_or_default(),
                ),
                Err(e) => (
                    "400 Bad Request".to_string(),
                    serde_json::json!({"detail": e.to_string()}).to_string(),
                ),
            },
            Err(e) => (
                "422 Unprocessable Entity".to_string(),
                serde_json::json!({"detail": e.to_string()}).to_string(),
            ),
        },
        ("POST", "/v1/patterns") => match serde_json::from_str::<PatternCreateRequest>(body) {
            Ok(req) => {
                // Validate regex
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
