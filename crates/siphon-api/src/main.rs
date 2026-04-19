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
//!   SIPHON_ALLOWLIST_PATH            Optional JSON file {texts,patterns,paths}
//!                                    exposed read-only via GET /v1/allowlist
//!   SIPHON_AUDIT_RING_CAP            In-memory audit ring capacity (default: 500)
//!   SIPHON_FINDINGS_RING_CAP         In-memory findings ring capacity (default: 1000)

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
use siphon::allowlist::Allowlist;
use siphon::policy::{load_policies_from_dir, Policy};
use siphon::profiles::{get_profile, list_profiles};
use siphon::rbac::{role_has_permission, Permission, Role};
use siphon_core::audit::{
    audit_event, iso8601_now, set_audit_logger, AuditEvent, AuditHandler, AuditLogger,
    FileAuditHandler, RotatingFileAuditHandler,
};
use siphon_core::findings_ring::{
    filter_findings, severity_for, FindingRecord, FindingsRing,
};
use siphon_core::overrides::{PatternOverride, PatternOverrides, RuntimePattern};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::{HashMap, HashSet, VecDeque};
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
    audit_ring: Arc<Mutex<VecDeque<AuditEvent>>>,
    audit_ring_cap: usize,
    allowlist: Arc<Allowlist>,
    findings: Arc<FindingsRing>,
    /// Pre-computed disabled-patterns set from the loaded
    /// PatternOverrides file. Each /scan request clones the Arc into
    /// its ScanConfig. Built once at startup; refreshing means a roll
    /// (Phase 6).
    disabled_patterns: Arc<HashSet<(String, String)>>,
    /// Pre-computed (category, sub_category) → PatternOverride map
    /// from PatternOverrides::override_lookup(). Phase 3c honours
    /// specificity + context_required.
    pattern_field_overrides: Arc<HashMap<(String, String), PatternOverride>>,
    /// Compiled runtime patterns from custom_categories. Evaluated
    /// after the static scan loop (Phase 3d.1).
    runtime_patterns: Arc<Vec<RuntimePattern>>,
}

// FindingsRing + FindingRecord + severity_for now live in
// siphon_core::findings_ring so siphon-fs can keep its own
// independent ring with identical shape. Phase 2c moves findings
// from 'siphon-api is the aggregator' to 'each pod owns its ring +
// admin console unions client-side'.

// ---------------------------------------------------------------------------
// Ring-buffer audit handler — keeps last N events in memory so /v1/audit
// can surface them without re-reading the rotating log files.
// ---------------------------------------------------------------------------

struct RingBufferAuditHandler {
    buf: Arc<Mutex<VecDeque<AuditEvent>>>,
    cap: usize,
}

impl RingBufferAuditHandler {
    fn new(buf: Arc<Mutex<VecDeque<AuditEvent>>>, cap: usize) -> Self {
        Self { buf, cap }
    }
}

impl AuditHandler for RingBufferAuditHandler {
    fn handle(&self, event: &AuditEvent) {
        let mut guard = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= self.cap {
            guard.pop_front();
        }
        guard.push_back(event.clone());
    }
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

    /// Snapshot of current rate-limiter state — used by GET /v1/ratelimit.
    fn snapshot(&self) -> (usize, usize) {
        let total_slots: usize = self.windows.values().map(|v| v.len()).sum();
        (self.windows.len(), total_slots)
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
    /// When true, the response includes a `trace` array — a per-stage
    /// log of every candidate that touched the pipeline (regex hits,
    /// validation results, context checks, confidence decisions, emit
    /// events). Used by the admin console's Live Scan trace view.
    trace: Option<bool>,
}

#[derive(Serialize)]
struct ScanResponse {
    source_pod: &'static str,
    request_id: String,
    findings: Vec<Finding>,
    finding_count: usize,
    scan_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<Vec<siphon_core::scanner::StageEvent>>,
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

    let trace_requested = req.options.trace.unwrap_or(false);
    let trace_sink: Option<Arc<Mutex<Vec<siphon_core::scanner::StageEvent>>>> = if trace_requested {
        Some(Arc::new(Mutex::new(Vec::new())))
    } else {
        None
    };

    let config = ScanConfig {
        min_confidence: req.options.min_confidence.unwrap_or(0.0),
        categories: req.options.categories.map(|c| c.into_iter().collect::<HashSet<_>>()),
        require_context: req.options.require_context.unwrap_or(false),
        baseline_only: req.options.baseline_only.unwrap_or(false),
        deduplicate: req.options.deduplicate.unwrap_or(true),
        trace: trace_sink.clone(),
        // Apply the pod-loaded overrides on every scan. Cheap clones —
        // each field is an Arc, not the underlying collection.
        disabled_patterns: Some(state.disabled_patterns.clone()),
        pattern_field_overrides: Some(state.pattern_field_overrides.clone()),
        runtime_patterns: Some(state.runtime_patterns.clone()),
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

    // Push each finding into the in-memory ring so /v1/findings can surface
    // the live stream without touching disk. Reuse the audit module's
    // iso8601 timestamp so the frontend renders a single consistent format.
    let ts_now = iso8601_now();
    for (idx, f) in findings.iter().enumerate() {
        let short_req = request_id.split('-').next().unwrap_or(&request_id);
        state.findings.push(FindingRecord {
            id: format!("f-{short_req}-{idx:02x}"),
            ts: ts_now.clone(),
            request_id: request_id.clone(),
            source_ip: source_ip.clone(),
            source_pod: "siphon-api".to_string(),
            category: f.category.clone(),
            sub_category: f.sub_category.clone(),
            text: f.text.clone(),
            confidence: f.confidence,
            has_context: f.has_context,
            span: f.span,
            metadata: f.metadata.clone(),
            severity: severity_for(&f.category, f.confidence),
        });
    }

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

    // Drain the trace sink (if tracing was requested). Cloning out of
    // the Arc<Mutex> keeps the response owned.
    let trace = trace_sink.as_ref().and_then(|s| {
        s.lock().ok().map(|g| g.clone())
    });

    Ok(Json(ScanResponse {
        source_pod: "siphon-api",
        request_id,
        findings,
        finding_count: count,
        scan_duration_ms: duration_ms as u64,
        trace,
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
    // Phase 1b: context keywords + proximity window, pulled from
    // siphon_core::context::CONTEXT_KEYWORDS for the matching
    // (category, sub_category) tuple. Empty Vec + default distance
    // means no dedicated keyword list for this pattern.
    context_keywords: Vec<&'static str>,
    proximity_chars: usize,
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

    // Build a (category, sub_category) → ContextEntry lookup once per
    // request. Linear scan over CONTEXT_KEYWORDS for every pattern
    // would be O(n²); this keeps it O(n). ContextEntry is Copy so the
    // map value is owned.
    let ctx_lookup: std::collections::HashMap<
        (&'static str, &'static str),
        siphon_core::context::ContextEntry,
    > = siphon_core::context::CONTEXT_KEYWORDS
        .iter()
        .map(|&(cat, sub, entry)| ((cat, sub), entry))
        .collect();
    // Fallback proximity when a pattern has no dedicated keyword entry.
    // Mirrors DEFAULT_DISTANCE in siphon_core::context.
    const DEFAULT_PROXIMITY: usize = 50;

    let patterns: Vec<PatternItem> = filtered
        .into_iter()
        .take(cap)
        .map(|p| {
            let (context_keywords, proximity_chars) =
                match ctx_lookup.get(&(p.category, p.sub_category)) {
                    Some(entry) => (entry.keywords.to_vec(), entry.distance),
                    None => (Vec::new(), DEFAULT_PROXIMITY),
                };
            PatternItem {
                category: p.category,
                sub_category: p.sub_category,
                regex: p.regex,
                case_insensitive: p.case_insensitive,
                specificity: p.specificity,
                context_required: p.context_required,
                context_keywords,
                proximity_chars,
            }
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
    // All sub_category names inside this category — gives the admin
    // console enough data to implement client-side search across
    // sub-categories without needing to pull the full pattern list.
    sub_categories: Vec<&'static str>,
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
        .map(|c| {
            let pats = siphon_core::patterns::patterns_for_category(c);
            let sub_categories: Vec<&'static str> =
                pats.iter().map(|p| p.sub_category).collect();
            CategoryItem {
                category: c,
                pattern_count: pats.len(),
                sub_categories,
            }
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

#[derive(Serialize)]
struct VersionResponse {
    api_version: &'static str,
    core_version: &'static str,
    target_triple: &'static str,
    rust_version: &'static str,
    build_profile: &'static str,
    patterns_loaded: usize,
    categories_loaded: usize,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        api_version: env!("CARGO_PKG_VERSION"),
        core_version: siphon_core::VERSION,
        target_triple: option_env!("TARGET").unwrap_or("unknown"),
        rust_version: option_env!("RUSTC_VERSION").unwrap_or(env!("CARGO_PKG_RUST_VERSION")),
        build_profile: if cfg!(debug_assertions) { "debug" } else { "release" },
        patterns_loaded: siphon_core::patterns::PATTERNS.len(),
        categories_loaded: siphon_core::patterns::categories().len(),
    })
}

// ---------------------------------------------------------------------------
// Bundled documentation — every markdown file in docs/ (plus README) is
// baked into the binary at compile time. The admin console renders
// these via GET /v1/docs (index) and GET /v1/docs/content?path=... .
// ---------------------------------------------------------------------------

const DOCS_INDEX: &[(&str, &str)] = &[
    ("README.md", include_str!("../../../README.md")),
    ("docs/ARCHITECTURE.md", include_str!("../../../docs/ARCHITECTURE.md")),
    ("docs/BENCHMARKS.md", include_str!("../../../docs/BENCHMARKS.md")),
    ("docs/CHANGELOG.md", include_str!("../../../docs/CHANGELOG.md")),
    ("docs/KEYWORDS.md", include_str!("../../../docs/KEYWORDS.md")),
    ("docs/PATTERNS.md", include_str!("../../../docs/PATTERNS.md")),
    ("docs/advanced_techniques.md", include_str!("../../../docs/advanced_techniques.md")),
    ("docs/api-reference.md", include_str!("../../../docs/api-reference.md")),
    ("docs/architecture/context-matching.md", include_str!("../../../docs/architecture/context-matching.md")),
    ("docs/architecture/extending.md", include_str!("../../../docs/architecture/extending.md")),
    ("docs/architecture/microservices.md", include_str!("../../../docs/architecture/microservices.md")),
    ("docs/architecture/normalization.md", include_str!("../../../docs/architecture/normalization.md")),
    ("docs/architecture/pipeline.md", include_str!("../../../docs/architecture/pipeline.md")),
    ("docs/architecture/validation.md", include_str!("../../../docs/architecture/validation.md")),
    ("docs/architecture/zero-trust.md", include_str!("../../../docs/architecture/zero-trust.md")),
    ("docs/baselines/ABOUT-BASELINES.md", include_str!("../../../docs/baselines/ABOUT-BASELINES.md")),
    ("docs/baselines/BASELINE-CONFIGURATION-REFERENCE.md", include_str!("../../../docs/baselines/BASELINE-CONFIGURATION-REFERENCE.md")),
    ("docs/baselines/confidential-documents.md", include_str!("../../../docs/baselines/confidential-documents.md")),
    ("docs/baselines/index.md", include_str!("../../../docs/baselines/index.md")),
    ("docs/baselines/internal-financial.md", include_str!("../../../docs/baselines/internal-financial.md")),
    ("docs/baselines/pci.md", include_str!("../../../docs/baselines/pci.md")),
    ("docs/baselines/phi-keywords.md", include_str!("../../../docs/baselines/phi-keywords.md")),
    ("docs/baselines/phi-patterns.md", include_str!("../../../docs/baselines/phi-patterns.md")),
    ("docs/baselines/phi.md", include_str!("../../../docs/baselines/phi.md")),
    ("docs/baselines/pii-keywords.md", include_str!("../../../docs/baselines/pii-keywords.md")),
    ("docs/baselines/pii-patterns.md", include_str!("../../../docs/baselines/pii-patterns.md")),
    ("docs/baselines/pii.md", include_str!("../../../docs/baselines/pii.md")),
    ("docs/baselines/source-code-secrets.md", include_str!("../../../docs/baselines/source-code-secrets.md")),
    ("docs/deployment/cicd.md", include_str!("../../../docs/deployment/cicd.md")),
    ("docs/deployment/docker.md", include_str!("../../../docs/deployment/docker.md")),
    ("docs/deployment/pre-commit.md", include_str!("../../../docs/deployment/pre-commit.md")),
    ("docs/deployment/pypi.md", include_str!("../../../docs/deployment/pypi.md")),
    ("docs/enterprise/api.md", include_str!("../../../docs/enterprise/api.md")),
    ("docs/enterprise/audit.md", include_str!("../../../docs/enterprise/audit.md")),
    ("docs/enterprise/batch.md", include_str!("../../../docs/enterprise/batch.md")),
    ("docs/enterprise/classification.md", include_str!("../../../docs/enterprise/classification.md")),
    ("docs/enterprise/compliance.md", include_str!("../../../docs/enterprise/compliance.md")),
    ("docs/enterprise/env-config.md", include_str!("../../../docs/enterprise/env-config.md")),
    ("docs/enterprise/observability.md", include_str!("../../../docs/enterprise/observability.md")),
    ("docs/enterprise/rate-limiting.md", include_str!("../../../docs/enterprise/rate-limiting.md")),
    ("docs/enterprise/rbac.md", include_str!("../../../docs/enterprise/rbac.md")),
    ("docs/enterprise/security.md", include_str!("../../../docs/enterprise/security.md")),
    ("docs/enterprise/siem.md", include_str!("../../../docs/enterprise/siem.md")),
    ("docs/evasion_defenses.md", include_str!("../../../docs/evasion_defenses.md")),
    ("docs/evasion_techniques.md", include_str!("../../../docs/evasion_techniques.md")),
    ("docs/getting-started/concepts.md", include_str!("../../../docs/getting-started/concepts.md")),
    ("docs/getting-started/configuration.md", include_str!("../../../docs/getting-started/configuration.md")),
    ("docs/getting-started/installation.md", include_str!("../../../docs/getting-started/installation.md")),
    ("docs/getting-started/quickstart.md", include_str!("../../../docs/getting-started/quickstart.md")),
];

fn doc_by_path(path: &str) -> Option<&'static str> {
    DOCS_INDEX.iter().find(|(p, _)| *p == path).map(|(_, c)| *c)
}

#[derive(Serialize)]
struct DocResponse {
    path: &'static str,
    format: &'static str,
    content: &'static str,
    bytes: usize,
}

/// Pull the first `#` heading out of a markdown document as a human title,
/// falling back to the basename when no heading is found.
fn doc_title(content: &str, path: &str) -> String {
    for line in content.lines().take(30) {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('#') {
            // swallow leading '#' chars
            let rest = rest.trim_start_matches('#').trim();
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn doc_section(path: &str) -> &'static str {
    if path == "README.md" { return "root"; }
    let rest = path.strip_prefix("docs/").unwrap_or(path);
    if let Some(slash) = rest.find('/') {
        match &rest[..slash] {
            "architecture" => "architecture",
            "baselines"    => "baselines",
            "deployment"   => "deployment",
            "enterprise"   => "enterprise",
            "getting-started" => "getting-started",
            _ => "other",
        }
    } else {
        "top"
    }
}

#[derive(Serialize)]
struct DocIndexEntry {
    path: String,
    title: String,
    section: &'static str,
    bytes: usize,
}

#[derive(Serialize)]
struct DocIndexResponse {
    total: usize,
    entries: Vec<DocIndexEntry>,
}

async fn docs_index() -> Json<DocIndexResponse> {
    let entries: Vec<DocIndexEntry> = DOCS_INDEX
        .iter()
        .map(|(path, content)| DocIndexEntry {
            path: (*path).to_string(),
            title: doc_title(content, path),
            section: doc_section(path),
            bytes: content.len(),
        })
        .collect();
    Json(DocIndexResponse {
        total: entries.len(),
        entries,
    })
}

#[derive(Deserialize)]
struct DocContentQuery {
    path: String,
}

async fn docs_content(
    Query(q): Query<DocContentQuery>,
) -> Result<Json<DocResponse>, (StatusCode, Json<ErrorResponse>)> {
    match doc_by_path(&q.path) {
        Some(content) => Ok(Json(DocResponse {
            path: match DOCS_INDEX.iter().find(|(p, _)| *p == q.path) {
                Some((p, _)) => p,
                None => "",
            },
            format: "markdown",
            content,
            bytes: content.len(),
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("doc not bundled: {}", q.path),
            }),
        )),
    }
}

// Legacy shortcut handlers — kept so older UI callers don't break.
async fn doc_changelog() -> Json<DocResponse> {
    let c = doc_by_path("docs/CHANGELOG.md").unwrap_or("");
    Json(DocResponse { path: "docs/CHANGELOG.md", format: "markdown", content: c, bytes: c.len() })
}
async fn doc_architecture() -> Json<DocResponse> {
    let c = doc_by_path("docs/ARCHITECTURE.md").unwrap_or("");
    Json(DocResponse { path: "docs/ARCHITECTURE.md", format: "markdown", content: c, bytes: c.len() })
}
async fn doc_readme() -> Json<DocResponse> {
    let c = doc_by_path("README.md").unwrap_or("");
    Json(DocResponse { path: "README.md", format: "markdown", content: c, bytes: c.len() })
}

// ---------------------------------------------------------------------------
// Tier 2 — process-state endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AuditResponse {
    total: usize,
    returned: usize,
    capacity: usize,
    events: Vec<AuditEvent>,
}

async fn list_audit_events(
    Query(q): Query<AuditQuery>,
    State(state): State<Arc<AppState>>,
) -> Json<AuditResponse> {
    let guard = state.audit_ring.lock().unwrap_or_else(|e| e.into_inner());
    let total = guard.len();
    let cap = q.limit.unwrap_or(200).min(state.audit_ring_cap);
    // newest last in the ring; return newest-first
    let events: Vec<AuditEvent> = guard.iter().rev().take(cap).cloned().collect();
    let returned = events.len();
    Json(AuditResponse {
        total,
        returned,
        capacity: state.audit_ring_cap,
        events,
    })
}

#[derive(Serialize)]
struct CacheStatsResponse {
    enabled: bool,
    hits: u64,
    misses: u64,
    size: usize,
    hit_rate: f64,
}

async fn cache_stats() -> Json<CacheStatsResponse> {
    let cell = siphon::cache::get_default_cache();
    let guard = cell.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_ref() {
        let s = cache.stats();
        let total = s.hits + s.misses;
        let hit_rate = if total == 0 { 0.0 } else { s.hits as f64 / total as f64 };
        Json(CacheStatsResponse {
            enabled: true,
            hits: s.hits,
            misses: s.misses,
            size: s.size,
            hit_rate,
        })
    } else {
        Json(CacheStatsResponse {
            enabled: false,
            hits: 0,
            misses: 0,
            size: 0,
            hit_rate: 0.0,
        })
    }
}

#[derive(Serialize)]
struct RateLimitResponse {
    window_secs: u64,
    per_ip_limit: u32,
    max_buckets: usize,
    active_buckets: usize,
    total_recent_requests: usize,
}

async fn rate_limit_status(State(state): State<Arc<AppState>>) -> Json<RateLimitResponse> {
    let guard = state.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
    let (active, slots) = guard.snapshot();
    Json(RateLimitResponse {
        window_secs: 60,
        per_ip_limit: state.rate_limit,
        max_buckets: 100_000,
        active_buckets: active,
        total_recent_requests: slots,
    })
}

#[derive(Serialize)]
struct TokenizeStatusResponse {
    global_vault: bool,
    note: &'static str,
}

async fn tokenize_status() -> Json<TokenizeStatusResponse> {
    // TokenVault is constructed per-scanner, not held globally in
    // siphon-api. We surface that honestly rather than faking a vault.
    Json(TokenizeStatusResponse {
        global_vault: false,
        note: "TokenVault is per-ScanConfig; siphon-api does not currently hold a shared vault.",
    })
}

#[derive(Serialize)]
struct IntegrationItem {
    kind: String,
    configured: bool,
    target: Option<String>,
}

#[derive(Serialize)]
struct IntegrationsResponse {
    total: usize,
    configured: usize,
    integrations: Vec<IntegrationItem>,
}

async fn list_integrations() -> Json<IntegrationsResponse> {
    // Honest read of env vars that siem.rs inspects. We don't try to
    // instantiate the adapters here (that lives in create_siem_from_env).
    let siem_type = std::env::var("DLPSCAN_SIEM_TYPE").ok();
    let url = std::env::var("DLPSCAN_SIEM_URL").ok();
    let host = std::env::var("DLPSCAN_SIEM_HOST").ok();
    let all: Vec<(&str, fn() -> Option<String>)> = vec![
        ("splunk",        || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("elasticsearch", || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("syslog",        || std::env::var("DLPSCAN_SIEM_HOST").ok()),
        ("webhook",       || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("datadog",       || std::env::var("DLPSCAN_SIEM_SITE").ok()),
    ];
    let active = siem_type.as_deref();
    let integrations: Vec<IntegrationItem> = all
        .iter()
        .map(|(kind, tgt)| IntegrationItem {
            kind: kind.to_string(),
            configured: active == Some(kind),
            target: if active == Some(kind) { tgt() } else { None },
        })
        .collect();
    let configured = integrations.iter().filter(|i| i.configured).count();
    // keep url/host used so rustc doesn't warn; they're intentionally
    // referenced above via closures.
    let _ = (url, host);
    Json(IntegrationsResponse {
        total: integrations.len(),
        configured,
        integrations,
    })
}

#[derive(Serialize)]
struct AllowlistResponse {
    loaded_from: Option<String>,
    text_count: usize,
    pattern_count: usize,
    path_count: usize,
    entries: AllowlistEntries,
}

#[derive(Serialize)]
struct AllowlistEntries {
    texts: Vec<String>,
    patterns: Vec<String>,
    paths: Vec<String>,
}

async fn list_allowlist(State(state): State<Arc<AppState>>) -> Json<AllowlistResponse> {
    let a = &state.allowlist;
    Json(AllowlistResponse {
        loaded_from: std::env::var("SIPHON_ALLOWLIST_PATH").ok(),
        text_count: a.texts().len(),
        pattern_count: a.patterns().len(),
        path_count: a.paths().len(),
        entries: AllowlistEntries {
            texts: a.texts().to_vec(),
            patterns: a.patterns().to_vec(),
            paths: a.paths().to_vec(),
        },
    })
}

#[derive(Serialize)]
struct VaultStubResponse {
    loaded: bool,
    vaults: Vec<&'static str>,
    note: &'static str,
}

async fn list_edm_vaults() -> Json<VaultStubResponse> {
    // ExactDataMatcher is constructed per ScanConfig. Surface that
    // honestly so the UI can show "not globally loaded" instead of
    // fabricating a list.
    Json(VaultStubResponse {
        loaded: false,
        vaults: vec![],
        note: "ExactDataMatcher is per-ScanConfig; no global EDM registry in siphon-api yet.",
    })
}

async fn list_lsh_vaults() -> Json<VaultStubResponse> {
    Json(VaultStubResponse {
        loaded: false,
        vaults: vec![],
        note: "DocumentVault is per-ScanConfig; no global LSH registry in siphon-api yet.",
    })
}

#[derive(Deserialize)]
struct FindingsQuery {
    limit: Option<usize>,
    category: Option<String>,
    severity: Option<String>,
    contains: Option<String>,
    since: Option<String>,
}

#[derive(Serialize)]
struct FindingsResponse {
    total: usize,
    returned: usize,
    capacity: usize,
    findings: Vec<FindingRecord>,
}

async fn list_findings(
    Query(q): Query<FindingsQuery>,
    State(state): State<Arc<AppState>>,
) -> Json<FindingsResponse> {
    let snapshot = state.findings.snapshot();
    let total = snapshot.len();
    let capacity = state.findings.capacity();

    let filtered = filter_findings(
        &snapshot,
        q.category.as_deref(),
        q.severity.as_deref(),
        q.contains.as_deref(),
        q.since.as_deref(),
    );

    let cap = q.limit.unwrap_or(200).min(capacity);
    let findings: Vec<FindingRecord> = filtered.into_iter().take(cap).cloned().collect();
    let returned = findings.len();
    Json(FindingsResponse {
        total,
        returned,
        capacity,
        findings,
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

    // In-memory ring buffer for /v1/audit. Always installed so the UI
    // has something to show even when no SIPHON_AUDIT_LOG_PATH is set.
    let audit_ring_cap: usize = std::env::var("SIPHON_AUDIT_RING_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);
    let audit_ring: Arc<Mutex<VecDeque<AuditEvent>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(audit_ring_cap)));

    // Install the global audit logger with the ring handler always, and
    // the rotating-file handler if SIPHON_AUDIT_LOG_PATH is set.
    let ring_handler: Box<dyn AuditHandler> = Box::new(
        RingBufferAuditHandler::new(audit_ring.clone(), audit_ring_cap),
    );
    let logger = match build_audit_logger(
        std::env::var("SIPHON_AUDIT_LOG_PATH").ok().as_deref(),
        std::env::var("SIPHON_AUDIT_SIGNING_KEY_HEX").ok().as_deref(),
        std::env::var("SIPHON_AUDIT_TAIL_PATH").ok().as_deref(),
    ) {
        Some(mut l) => {
            l.add_handler(ring_handler);
            l
        }
        None => AuditLogger::new().with_handler(ring_handler),
    };
    set_audit_logger(logger);

    // Optional allowlist — a JSON file with { texts, patterns, paths }.
    // Exposed read-only via GET /v1/allowlist.
    let allowlist: Allowlist = match std::env::var("SIPHON_ALLOWLIST_PATH") {
        Ok(path) if !path.is_empty() => match std::fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(v) => {
                    let texts = v.get("texts").and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let patterns = v.get("patterns").and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let paths = v.get("paths").and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let texts: Vec<String> = texts;
                    let patterns: Vec<String> = patterns;
                    let paths: Vec<String> = paths;
                    tracing::info!(
                        path = %path,
                        texts = texts.len(),
                        patterns = patterns.len(),
                        paths_n = paths.len(),
                        "allowlist loaded"
                    );
                    Allowlist::new()
                        .with_texts(texts)
                        .with_patterns(patterns)
                        .with_paths(paths)
                }
                Err(e) => {
                    tracing::error!(path = %path, error = %e, "allowlist parse failed");
                    Allowlist::new()
                }
            },
            Err(e) => {
                tracing::error!(path = %path, error = %e, "allowlist read failed");
                Allowlist::new()
            }
        },
        _ => Allowlist::new(),
    };

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

    let findings_cap: usize = std::env::var("SIPHON_FINDINGS_RING_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let findings = Arc::new(FindingsRing::new(findings_cap));

    // Load deployable PatternOverrides from the file k8s mounts the
    // siphon-overrides ConfigMap into. Missing → empty (compile-time
    // defaults); parse error → empty + logged. Phase 6's auto-roll
    // will reject overrides that don't parse before they reach this
    // path by gating on /ready.
    let overrides_path = std::env::var("SIPHON_OVERRIDES_PATH")
        .unwrap_or_else(|_| "/etc/siphon/overrides.json".to_string());
    let overrides = PatternOverrides::from_file_or_empty(&overrides_path);
    let overrides_summary = overrides.summary();
    let disabled_patterns = Arc::new(overrides.disabled_set());
    let pattern_field_overrides = Arc::new(overrides.override_lookup());
    let runtime_patterns = Arc::new(overrides.compile_runtime_patterns());
    let runtime_pattern_count = runtime_patterns.len();
    tracing::info!(
        path = %overrides_path,
        version = overrides_summary.version,
        disabled = overrides_summary.disabled_patterns,
        field_overrides = overrides_summary.pattern_overrides,
        custom_categories = overrides_summary.custom_categories,
        runtime_patterns_compiled = runtime_pattern_count,
        "PatternOverrides loaded"
    );

    let state = Arc::new(AppState {
        api_key_hash,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        rate_limit,
        policies: Arc::new(policies),
        metrics: Arc::new(ApiMetrics::new()),
        audit_ring,
        audit_ring_cap,
        allowlist: Arc::new(allowlist),
        findings,
        disabled_patterns,
        pattern_field_overrides,
        runtime_patterns,
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
        .route("/v1/audit", get(list_audit_events))
        .route("/v1/cache/stats", get(cache_stats))
        .route("/v1/ratelimit", get(rate_limit_status))
        .route("/v1/tokenize/status", get(tokenize_status))
        .route("/v1/integrations", get(list_integrations))
        .route("/v1/allowlist", get(list_allowlist))
        .route("/v1/edm", get(list_edm_vaults))
        .route("/v1/lsh", get(list_lsh_vaults))
        .route("/v1/findings", get(list_findings))
        .route("/v1/version", get(version))
        .route("/v1/docs", get(docs_index))
        .route("/v1/docs/content", get(docs_content))
        .route("/v1/docs/changelog", get(doc_changelog))
        .route("/v1/docs/architecture", get(doc_architecture))
        .route("/v1/docs/readme", get(doc_readme))
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

        // axum-server uses a Handle-based graceful shutdown rather than
        // axum::serve's with_graceful_shutdown future. Spawn a task that
        // waits on shutdown_signal() and then asks the server to drain.
        // 30s drain budget — Deployment grace period (45s) covers that
        // plus startup-of-replacement-pod overhead.
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        axum_server::bind_rustls(addr.parse().unwrap(), rustls_config)
            .handle(handle)
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

// Shutdown trigger — completes when EITHER SIGINT (Ctrl-C, dev) or
// SIGTERM (k8s pod termination) arrives. axum's with_graceful_shutdown
// holds new accepts off and waits for in-flight requests to complete
// before returning. The Deployment's terminationGracePeriodSeconds (45s
// for siphon-api) caps how long k8s will wait before SIGKILL.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c   => tracing::info!(signal = "SIGINT",  "shutdown signal received, draining connections..."),
        _ = terminate => tracing::info!(signal = "SIGTERM", "shutdown signal received, draining connections..."),
    }
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
