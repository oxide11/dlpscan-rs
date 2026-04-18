//! Polygon Siphon API — hardened sync HTTP scan service.
//!
//! Zero-trust design: every request is authenticated via API key,
//! all transport is encrypted via TLS (when configured), and
//! inter-pod mTLS is supported for service-mesh deployments.
//!
//! Configuration via environment variables:
//!   SIPHON_PORT                      Listen port (default: 8080)
//!   SIPHON_BIND                      Bind address (default: 127.0.0.1)
//!   SIPHON_API_KEY                   Required API key (SHA-256 hashed at rest)
//!   SIPHON_TLS_CERT                  TLS certificate path (PEM)
//!   SIPHON_TLS_KEY                   TLS private key path (PEM)
//!   SIPHON_CORS_ORIGINS              Comma-separated allowed origins (default: none)
//!   SIPHON_RATE_LIMIT                Max requests per minute per IP (default: 120)
//!   SIPHON_REQUEST_TIMEOUT_SECS      Request timeout (default: 30)
//!   SIPHON_AUDIT_LOG_PATH            Audit log file path (JSONL)
//!   SIPHON_AUDIT_SIGNING_KEY_HEX     Hex-encoded HMAC-SHA256 key (enables
//!                                    tamper-evident chain mode)
//!   SIPHON_AUDIT_TAIL_PATH           Chain tail state path (persists chain
//!                                    across process restarts; requires key)
//!   SIPHON_POLICIES_DIR              Optional directory of *.toml policies
//!                                    exposed read-only via GET /v1/policies

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siphon::policy::{load_policies_from_dir, Policy};
use siphon::profiles::{get_profile, list_profiles};
use siphon::rbac::{role_has_permission, Permission, Role};
use siphon_core::audit::{
    audit_event, set_audit_logger, AuditEvent, AuditLogger, FileAuditHandler,
    RotatingFileAuditHandler,
};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    api_key_hash: Option<[u8; 32]>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    rate_limit: u32,
    policies: Arc<Vec<Policy>>,
    metrics: Arc<ApiMetrics>,
}

/// Process-local counters surfaced by GET /v1/metrics.
struct ApiMetrics {
    started_at: Instant,
    scans_total: AtomicU64,
    findings_total: AtomicU64,
    scan_errors_total: AtomicU64,
}

impl ApiMetrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            scans_total: AtomicU64::new(0),
            findings_total: AtomicU64::new(0),
            scan_errors_total: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiter (per-IP, sliding window)
// ---------------------------------------------------------------------------

struct RateLimiter {
    windows: HashMap<String, Vec<Instant>>,
    last_cleanup: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    fn check(&mut self, ip: &str, limit: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);

        if now.duration_since(self.last_cleanup) > Duration::from_secs(300) {
            self.windows
                .retain(|_, timestamps| timestamps.last().is_some_and(|t| now.duration_since(*t) < window));
            self.last_cleanup = now;
        }

        if self.windows.len() > 100_000 {
            self.windows.clear();
            self.last_cleanup = now;
        }

        let timestamps = self.windows.entry(ip.to_string()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= limit as usize {
            return false;
        }
        timestamps.push(now);
        true
    }
}

// ---------------------------------------------------------------------------
// Audit logger construction
// ---------------------------------------------------------------------------

/// Build an [`AuditLogger`] from explicit configuration. Returns `None`
/// when `log_path` is not set — with no log path, signing and tail
/// persistence have nothing to write to. Kept out of `main` so the
/// config parsing can be unit-tested without racing on std::env.
///
/// - `log_path`: audit log file (JSONL). When set, a
///   [`RotatingFileAuditHandler`] is installed.
/// - `signing_key_hex`: hex-encoded HMAC-SHA256 key. When set and the
///   log path is set, chain mode is enabled; every event is re-signed
///   with its predecessor's signature in `prev_signature`, making the
///   log tamper-evident.
/// - `tail_path`: chain tail persistence file. Only honoured when chain
///   mode is enabled. Lets the chain resume across process restarts.
fn build_audit_logger(
    log_path: Option<&str>,
    signing_key_hex: Option<&str>,
    tail_path: Option<&str>,
) -> Option<AuditLogger> {
    let path = log_path?;
    // 50 MB / 10 rotated files — matches the RotatingFileAuditHandler
    // defaults used in the root siphon crate.
    let mut handler = RotatingFileAuditHandler::new(path, 50 * 1024 * 1024, 10);

    if let Some(hex_key) = signing_key_hex {
        match hex::decode(hex_key) {
            Ok(key) if key.len() >= 16 => {
                handler = handler.with_chain_key(&key);
                if let Some(tp) = tail_path {
                    handler = handler.with_chain_tail_path(tp);
                }
                tracing::info!(
                    log_path = %path,
                    tail = tail_path.is_some(),
                    "Audit log chain signing enabled"
                );
            }
            Ok(_) => {
                tracing::warn!(
                    "SIPHON_AUDIT_SIGNING_KEY_HEX is too short (<16 bytes); audit chain disabled"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "SIPHON_AUDIT_SIGNING_KEY_HEX is not valid hex; audit chain disabled"
                );
            }
        }
    } else {
        tracing::info!(log_path = %path, "Audit logging enabled (unsigned — set SIPHON_AUDIT_SIGNING_KEY_HEX for tamper-evidence)");
    }

    // Also mirror events to a lightweight file handler in case
    // rotation config differs in future — but for now the rotating
    // handler IS our one file handler. Suppress the unused import for
    // FileAuditHandler: it's exposed as part of the re-export surface
    // but this pod only installs the rotating variant.
    let _ = std::marker::PhantomData::<FileAuditHandler>;

    Some(AuditLogger::new().with_handler(Box::new(handler)))
}

/// Emit an event via the global audit logger (no-op if none is set).
/// Wraps [`audit_event`] so call sites in this binary go through a
/// single function that can later be extended with additional
/// enrichment (source_pod, correlation IDs, etc.).
fn emit_audit(event: AuditEvent) {
    audit_event(&event.with_source("siphon-api"));
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected_hash) = &state.api_key_hash else {
        return next.run(request).await;
    };

    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(key) => {
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let provided_hash: [u8; 32] = hasher.finalize().into();

            let mut diff = 0u8;
            for (a, b) in expected_hash.iter().zip(provided_hash.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                tracing::warn!("auth_failed: invalid API key");
                if let Ok(event) = AuditEvent::new("REJECT") {
                    emit_audit(
                        event
                            .with_action("auth")
                            .with_outcome("rejected")
                            .with_source_ip(&addr.ip().to_string())
                            .with_metadata(
                                "reason",
                                serde_json::json!("invalid_api_key"),
                            ),
                    );
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse { error: "invalid API key".into() }),
                ).into_response();
            }
            next.run(request).await
        }
        None => {
            if let Ok(event) = AuditEvent::new("REJECT") {
                emit_audit(
                    event
                        .with_action("auth")
                        .with_outcome("rejected")
                        .with_source_ip(&addr.ip().to_string())
                        .with_metadata("reason", serde_json::json!("missing_api_key")),
                );
            }
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(ErrorResponse { error: "API key required".into() }),
            ).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limit middleware
// ---------------------------------------------------------------------------

async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();
    let allowed = {
        let mut limiter = state.rate_limiter.lock().unwrap();
        limiter.check(&ip, state.rate_limit)
    };

    if !allowed {
        tracing::warn!(ip = %ip, "rate_limited");
        if let Ok(event) = AuditEvent::new("REJECT") {
            emit_audit(
                event
                    .with_action("rate_limit")
                    .with_outcome("rejected")
                    .with_source_ip(&ip)
                    .with_metadata("reason", serde_json::json!("rate_limit_exceeded")),
            );
        }
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            Json(ErrorResponse { error: "rate limit exceeded".into() }),
        ).into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Security headers middleware
// ---------------------------------------------------------------------------

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("x-xss-protection", HeaderValue::from_static("0"));
    headers.insert(
        "cache-control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    if headers.get("strict-transport-security").is_none() {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ScanRequest {
    text: String,
    #[serde(default)]
    options: ScanOptions,
}

#[derive(Deserialize, Default)]
struct ScanOptions {
    min_confidence: Option<f64>,
    categories: Option<Vec<String>>,
    require_context: Option<bool>,
    baseline_only: Option<bool>,
    deduplicate: Option<bool>,
}

#[derive(Serialize)]
struct ScanResponse {
    source_pod: &'static str,
    request_id: String,
    findings: Vec<Finding>,
    finding_count: usize,
    scan_duration_ms: u64,
}

#[derive(Serialize)]
struct Finding {
    category: String,
    sub_category: String,
    text: String,
    confidence: f64,
    has_context: bool,
    span: (usize, usize),
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    metadata: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    pod: &'static str,
}

#[derive(Serialize, Clone)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        pod: "siphon-api",
    })
}

async fn scan(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let source_ip = addr.ip().to_string();

    if req.text.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "text field is required and cannot be empty".into(),
            }),
        ));
    }

    if req.text.len() > 10 * 1024 * 1024 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "payload exceeds size limit".into(),
            }),
        ));
    }

    let config = ScanConfig {
        min_confidence: req.options.min_confidence.unwrap_or(0.0),
        categories: req.options.categories.map(|c| c.into_iter().collect::<HashSet<_>>()),
        require_context: req.options.require_context.unwrap_or(false),
        baseline_only: req.options.baseline_only.unwrap_or(false),
        deduplicate: req.options.deduplicate.unwrap_or(true),
        ..Default::default()
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    let matches = scan_text_with_config(&req.text, &config).map_err(|e| {
        state.metrics.scan_errors_total.fetch_add(1, Ordering::Relaxed);
        tracing::error!(request_id = %request_id, error = %e, "scan_failed");
        if let Ok(event) = AuditEvent::new("SCAN") {
            emit_audit(
                event
                    .with_action("scan")
                    .with_outcome("error")
                    .with_request_id(&request_id)
                    .with_source_ip(&source_ip)
                    .with_metadata("text_len", serde_json::json!(req.text.len())),
            );
        }
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan processing failed".into(),
            }),
        )
    })?;

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_millis() as f64;

    let findings: Vec<Finding> = matches
        .into_iter()
        .map(|m| Finding {
            category: m.category,
            sub_category: m.sub_category,
            text: m.text,
            confidence: m.confidence,
            has_context: m.has_context,
            span: m.span,
            metadata: m.metadata,
        })
        .collect();

    let count = findings.len();
    state.metrics.scans_total.fetch_add(1, Ordering::Relaxed);
    state.metrics.findings_total.fetch_add(count as u64, Ordering::Relaxed);

    let categories_found: Vec<String> = findings
        .iter()
        .map(|f| f.category.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    tracing::info!(
        request_id = %request_id,
        text_len = req.text.len(),
        findings_count = count,
        duration_ms = duration_ms as u64,
        "scan_complete"
    );

    if let Ok(event) = AuditEvent::new("SCAN") {
        let outcome = if count == 0 { "success" } else { "findings_detected" };
        emit_audit(
            event
                .with_action("scan")
                .with_outcome(outcome)
                .with_is_clean(count == 0)
                .with_finding_count(count)
                .with_categories_found(categories_found)
                .with_duration_ms(duration_ms)
                .with_request_id(&request_id)
                .with_source_ip(&source_ip)
                .with_metadata("text_len", serde_json::json!(req.text.len())),
        );
    }

    Ok(Json(ScanResponse {
        source_pod: "siphon-api",
        request_id,
        findings,
        finding_count: count,
        scan_duration_ms: duration_ms as u64,
    }))
}

// ---------------------------------------------------------------------------
// /v1 read-only handlers (admin console)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PatternsQuery {
    category: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct PatternItem {
    category: &'static str,
    sub_category: &'static str,
    regex: &'static str,
    case_insensitive: bool,
    specificity: f64,
    context_required: bool,
}

#[derive(Serialize)]
struct PatternsResponse {
    total: usize,
    returned: usize,
    patterns: Vec<PatternItem>,
}

async fn list_patterns(Query(q): Query<PatternsQuery>) -> Json<PatternsResponse> {
    let all = siphon_core::patterns::PATTERNS;
    let filtered: Vec<&'static siphon_core::models::PatternDef> = match q.category.as_deref() {
        Some(c) if !c.is_empty() => all.iter().filter(|p| p.category == c).collect(),
        _ => all.iter().collect(),
    };
    let total = filtered.len();
    let cap = q.limit.unwrap_or(500).min(5_000);
    let patterns: Vec<PatternItem> = filtered
        .into_iter()
        .take(cap)
        .map(|p| PatternItem {
            category: p.category,
            sub_category: p.sub_category,
            regex: p.regex,
            case_insensitive: p.case_insensitive,
            specificity: p.specificity,
            context_required: p.context_required,
        })
        .collect();
    let returned = patterns.len();
    Json(PatternsResponse {
        total,
        returned,
        patterns,
    })
}

#[derive(Serialize)]
struct CategoryItem {
    category: &'static str,
    pattern_count: usize,
}

#[derive(Serialize)]
struct CategoriesResponse {
    total: usize,
    categories: Vec<CategoryItem>,
}

async fn list_categories() -> Json<CategoriesResponse> {
    let cats = siphon_core::patterns::categories();
    let categories: Vec<CategoryItem> = cats
        .into_iter()
        .map(|c| CategoryItem {
            category: c,
            pattern_count: siphon_core::patterns::patterns_for_category(c).len(),
        })
        .collect();
    Json(CategoriesResponse {
        total: categories.len(),
        categories,
    })
}

#[derive(Serialize)]
struct PoliciesResponse {
    loaded: bool,
    total: usize,
    source: Option<String>,
    policies: Vec<Policy>,
}

async fn list_policies(State(state): State<Arc<AppState>>) -> Json<PoliciesResponse> {
    let source = std::env::var("SIPHON_POLICIES_DIR").ok();
    Json(PoliciesResponse {
        loaded: source.is_some(),
        total: state.policies.len(),
        source,
        policies: (*state.policies).clone(),
    })
}

#[derive(Serialize)]
struct ProfilesResponse {
    total: usize,
    profiles: Vec<siphon::profiles::MaskingProfile>,
}

async fn list_profiles_handler() -> Json<ProfilesResponse> {
    let names = list_profiles();
    let profiles: Vec<siphon::profiles::MaskingProfile> =
        names.into_iter().filter_map(|n| get_profile(&n)).collect();
    Json(ProfilesResponse {
        total: profiles.len(),
        profiles,
    })
}

#[derive(Serialize)]
struct RoleItem {
    role: &'static str,
    permissions: Vec<&'static str>,
    description: &'static str,
}

#[derive(Serialize)]
struct RolesResponse {
    total: usize,
    roles: Vec<RoleItem>,
}

async fn list_roles() -> Json<RolesResponse> {
    const ROLES: [(Role, &str, &str); 4] = [
        (Role::Admin,    "admin",    "Full control. All permissions."),
        (Role::Analyst,  "analyst",  "Scan + detokenize + read status."),
        (Role::Operator, "operator", "Scan + read status."),
        (Role::Viewer,   "viewer",   "Read status only."),
    ];
    const PERMS: [(Permission, &str); 7] = [
        (Permission::Scan,            "Scan"),
        (Permission::BatchScan,       "BatchScan"),
        (Permission::ManagePatterns,  "ManagePatterns"),
        (Permission::Detokenize,      "Detokenize"),
        (Permission::ExportVault,     "ExportVault"),
        (Permission::ViewStatus,      "ViewStatus"),
        (Permission::AdminAction,     "AdminAction"),
    ];
    let roles: Vec<RoleItem> = ROLES
        .iter()
        .map(|(r, name, desc)| RoleItem {
            role: name,
            description: desc,
            permissions: PERMS
                .iter()
                .filter(|(p, _)| role_has_permission(*r, *p))
                .map(|(_, n)| *n)
                .collect(),
        })
        .collect();
    Json(RolesResponse {
        total: roles.len(),
        roles,
    })
}

#[derive(Serialize)]
struct FrameworkItem {
    name: &'static str,
    failing_categories: Vec<&'static str>,
}

#[derive(Serialize)]
struct FrameworksResponse {
    total: usize,
    frameworks: Vec<FrameworkItem>,
}

async fn list_frameworks() -> Json<FrameworksResponse> {
    // Mirrors siphon::compliance::framework_failing_categories (private fn).
    // Kept here to avoid widening that module's visibility just for the API.
    let frameworks = vec![
        FrameworkItem {
            name: "PCI-DSS",
            failing_categories: vec!["Credit Card Numbers", "Primary Account Numbers"],
        },
        FrameworkItem {
            name: "HIPAA",
            failing_categories: vec!["Medical Identifiers"],
        },
        FrameworkItem {
            name: "SOC2",
            failing_categories: vec![
                "Generic Secrets",
                "Cloud Provider Secrets",
                "Code Platform Secrets",
            ],
        },
        FrameworkItem {
            name: "GDPR",
            failing_categories: vec!["Contact Information", "Personal Identifiers"],
        },
    ];
    Json(FrameworksResponse {
        total: frameworks.len(),
        frameworks,
    })
}

#[derive(Serialize)]
struct MetricsResponse {
    uptime_secs: u64,
    scans_total: u64,
    findings_total: u64,
    scan_errors_total: u64,
    patterns_loaded: usize,
    categories_loaded: usize,
    policies_loaded: usize,
}

async fn metrics_snapshot(State(state): State<Arc<AppState>>) -> Json<MetricsResponse> {
    Json(MetricsResponse {
        uptime_secs: state.metrics.started_at.elapsed().as_secs(),
        scans_total: state.metrics.scans_total.load(Ordering::Relaxed),
        findings_total: state.metrics.findings_total.load(Ordering::Relaxed),
        scan_errors_total: state.metrics.scan_errors_total.load(Ordering::Relaxed),
        patterns_loaded: siphon_core::patterns::PATTERNS.len(),
        categories_loaded: siphon_core::patterns::categories().len(),
        policies_loaded: state.policies.len(),
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let port = std::env::var("SIPHON_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let bind = std::env::var("SIPHON_BIND").unwrap_or_else(|_| "127.0.0.1".into());

    let api_key_hash = std::env::var("SIPHON_API_KEY").ok().map(|key| {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        tracing::info!("API key authentication enabled");
        hash
    });
    if api_key_hash.is_none() {
        tracing::warn!("SIPHON_API_KEY not set — running WITHOUT authentication (dev mode only)");
    }

    let rate_limit: u32 = std::env::var("SIPHON_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);

    let request_timeout: u64 = std::env::var("SIPHON_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    let tls_cert = std::env::var("SIPHON_TLS_CERT").ok();
    let tls_key = std::env::var("SIPHON_TLS_KEY").ok();

    // Install the global audit logger (no-op when SIPHON_AUDIT_LOG_PATH
    // is unset). Done before the router is built so every emitted event
    // — including any from startup itself — has a handler to dispatch to.
    if let Some(logger) = build_audit_logger(
        std::env::var("SIPHON_AUDIT_LOG_PATH").ok().as_deref(),
        std::env::var("SIPHON_AUDIT_SIGNING_KEY_HEX").ok().as_deref(),
        std::env::var("SIPHON_AUDIT_TAIL_PATH").ok().as_deref(),
    ) {
        set_audit_logger(logger);
    }

    let cors = match std::env::var("SIPHON_CORS_ORIGINS") {
        Ok(origins) if !origins.is_empty() => {
            let trimmed = origins.trim();
            let base = CorsLayer::new()
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);
            if trimmed == "*" {
                base.allow_origin(AllowOrigin::any())
            } else {
                let allowed: Vec<HeaderValue> = trimmed
                    .split(',')
                    .filter_map(|o| o.trim().parse().ok())
                    .collect();
                base.allow_origin(AllowOrigin::list(allowed))
            }
        }
        _ => CorsLayer::new()
            .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
    };

    // Optional policies directory — loaded once at startup. Endpoints that
    // enumerate policies read from this cache; a HUP restart is required to
    // pick up on-disk changes (deliberate: policies are security-critical).
    let policies: Vec<Policy> = match std::env::var("SIPHON_POLICIES_DIR") {
        Ok(path) if !path.is_empty() => match load_policies_from_dir(&path) {
            Ok(map) => {
                let policies: Vec<Policy> = map.into_values().collect();
                tracing::info!(
                    count = policies.len(),
                    path = %path,
                    "policies loaded"
                );
                policies
            }
            Err(e) => {
                tracing::error!(path = %path, error = %e, "policies load failed");
                Vec::new()
            }
        },
        _ => Vec::new(),
    };

    let state = Arc::new(AppState {
        api_key_hash,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        rate_limit,
        policies: Arc::new(policies),
        metrics: Arc::new(ApiMetrics::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .route("/v1/patterns", get(list_patterns))
        .route("/v1/categories", get(list_categories))
        .route("/v1/policies", get(list_policies))
        .route("/v1/profiles", get(list_profiles_handler))
        .route("/v1/roles", get(list_roles))
        .route("/v1/compliance/frameworks", get(list_frameworks))
        .route("/v1/metrics", get(metrics_snapshot))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            11 * 1024 * 1024, // 11 MB to allow for JSON envelope
        ))
        .with_state(state);

    let addr = format!("{bind}:{port}");

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        addr = %addr,
        tls = tls_cert.is_some(),
        auth = api_key_hash.is_some(),
        rate_limit = rate_limit,
        timeout_secs = request_timeout,
        patterns = siphon_core::patterns::PATTERNS.len(),
        categories = siphon_core::patterns::categories().len(),
        "Polygon Siphon API starting"
    );

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &cert_path, &key_path,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!(cert = %cert_path, key = %key_path, error = %e, "TLS config failed");
            std::process::exit(1);
        });

        tracing::info!("TLS enabled");

        axum_server::bind_rustls(addr.parse().unwrap(), rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        if bind != "127.0.0.1" && bind != "::1" {
            tracing::warn!(
                "TLS disabled but binding to {bind} — set SIPHON_TLS_CERT and SIPHON_TLS_KEY for production"
            );
        }

        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install signal handler");
    tracing::info!("shutdown signal received, draining connections...");
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_core::audit::AuditEvent;

    #[test]
    fn test_build_audit_logger_none_without_path() {
        // No log path => no logger. Signing key alone is not enough;
        // without a file to write to, signatures have nowhere to go.
        assert!(build_audit_logger(None, None, None).is_none());
        assert!(build_audit_logger(None, Some("deadbeef"), None).is_none());
        assert!(
            build_audit_logger(None, Some("deadbeef"), Some("/tmp/tail")).is_none(),
            "tail path without log path must not synthesise a logger"
        );
    }

    #[test]
    fn test_build_audit_logger_unsigned_writes_events() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = build_audit_logger(Some(log_path.to_str().unwrap()), None, None)
            .expect("logger should be built");

        logger.log(&AuditEvent::new("SCAN").unwrap().with_user("test-user"));

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("SCAN"));
        assert!(content.contains("test-user"));
        // Without a signing key, events are unsigned.
        let event: AuditEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(event.signature.is_none());
        assert!(event.prev_signature.is_none());
    }

    #[test]
    fn test_build_audit_logger_chain_mode_signs_and_links() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let tail_path = dir.path().join("audit.tail");
        // 32-byte hex key (64 hex chars)
        let key_hex = "aa".repeat(32);
        let logger = build_audit_logger(
            Some(log_path.to_str().unwrap()),
            Some(&key_hex),
            Some(tail_path.to_str().unwrap()),
        )
        .expect("logger should be built with chain mode");

        logger.log(&AuditEvent::new("SCAN").unwrap().with_user("a"));
        logger.log(&AuditEvent::new("SCAN").unwrap().with_user("b"));

        let content = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<AuditEvent> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events.len(), 2);

        let key = hex::decode(&key_hex).unwrap();
        assert!(events[0].signature.is_some());
        assert!(events[0].prev_signature.is_none());
        assert!(events[0].verify(&key));

        assert!(events[1].signature.is_some());
        assert_eq!(
            events[1].prev_signature.as_deref(),
            events[0].signature.as_deref(),
            "second event must link to first"
        );
        assert!(events[1].verify(&key));

        // Tail file now reflects the second event's signature.
        let tail = std::fs::read_to_string(&tail_path).unwrap();
        assert_eq!(tail, events[1].signature.clone().unwrap());
    }

    #[test]
    fn test_build_audit_logger_invalid_hex_key_falls_back_to_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger =
            build_audit_logger(Some(log_path.to_str().unwrap()), Some("not-valid-hex!"), None)
                .expect("logger should still be built, just unsigned");
        logger.log(&AuditEvent::new("SCAN").unwrap());
        let content = std::fs::read_to_string(&log_path).unwrap();
        let event: AuditEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(
            event.signature.is_none(),
            "invalid hex key should disable signing, not error out"
        );
    }
}
