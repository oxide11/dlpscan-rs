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
use siphon_core::findings_ring::{filter_findings, severity_for, FindingRecord, FindingsRing};
use siphon_core::overrides::{
    CompiledList, PatternOverride, PatternOverrides, Regex, RuntimePattern,
};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// All the pre-computed views of the PatternOverrides file the
/// scanner consults on the hot path. Bundled as a single struct so
/// apply/reload can atomically swap the whole block under one write
/// lock instead of juggling field-level locks. Cheap to Clone — every
/// field is already an Arc.
#[derive(Clone)]
struct LiveOverrides {
    /// Categories + sub-categories the scanner must never emit.
    disabled_patterns: Arc<HashSet<(String, String)>>,
    /// Per-(category, sub_category) field overrides (specificity,
    /// context_required).
    pattern_field_overrides: Arc<HashMap<(String, String), PatternOverride>>,
    /// Runtime patterns compiled from custom_categories.
    runtime_patterns: Arc<Vec<RuntimePattern>>,
    /// Per-pattern regex overrides keyed by (category, sub_category).
    pattern_regex_overrides: Arc<HashMap<(String, String), Regex>>,
    /// Scanner-active list bindings resolved from
    /// active_list_bindings.
    list_bindings: Arc<Vec<(String, CompiledList)>>,
    /// Per-(category, sub_category) distinct-value thresholds
    /// (Phase 9).
    unique_thresholds: Arc<HashMap<(String, String), usize>>,
    /// Raw parsed document. Served verbatim by GET
    /// /v1/overrides/current so the admin console can diff.
    loaded_overrides: Arc<PatternOverrides>,
}

impl LiveOverrides {
    /// Build a fresh LiveOverrides by parsing the file at `path`.
    /// Missing / unparseable → empty (additive-principle from the
    /// startup loader). Returns the summary for logging/tracing.
    fn from_path(path: &std::path::Path) -> Self {
        let overrides = PatternOverrides::from_file_or_empty(&path.display().to_string());
        Self::from_doc(overrides)
    }

    fn from_doc(overrides: PatternOverrides) -> Self {
        Self {
            disabled_patterns: Arc::new(overrides.disabled_set()),
            pattern_field_overrides: Arc::new(overrides.override_lookup()),
            runtime_patterns: Arc::new(overrides.compile_runtime_patterns()),
            pattern_regex_overrides: Arc::new(overrides.compile_pattern_regex_overrides()),
            list_bindings: Arc::new(overrides.compile_active_list_bindings()),
            unique_thresholds: Arc::new(overrides.compile_unique_thresholds()),
            loaded_overrides: Arc::new(overrides),
        }
    }
}

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
    /// Pre-computed views the scanner consults per-scan. Bundled
    /// behind an RwLock so /v1/overrides/apply can atomically swap
    /// the whole block without a pod restart. Scan handlers take a
    /// read lock, clone the cheap Arc-only struct, release.
    live_overrides: Arc<RwLock<LiveOverrides>>,
    /// Stable identifier for this pod instance. Generated once at
    /// startup; surfaced via /health so the C2 can deduplicate
    /// replicas of the same Service.
    pod_id: Arc<String>,
    /// Wall-clock startup timestamp (ISO8601). Returned by /health.
    started_at_iso: String,
    /// Monotonic startup mark for uptime calculation.
    started_at: Instant,
    /// Path on disk to the overrides file. Apply + disk-read handlers
    /// use this directly; no writes happen anywhere else.
    overrides_path: Arc<std::path::PathBuf>,
    /// Runtime, per-pod pipeline-stage overrides. Each entry in the
    /// set forces the corresponding stage into its most permissive
    /// behaviour, regardless of what the caller sent in req.options
    /// or what's baked into the policy/overrides. Controlled via
    /// GET/PATCH /v1/pipeline/stages. Not persisted — restart clears.
    /// Diagnostic-only; production pods should leave this empty.
    disabled_stages: Arc<RwLock<HashSet<String>>>,
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
            self.windows.retain(|_, timestamps| {
                timestamps
                    .last()
                    .is_some_and(|t| now.duration_since(*t) < window)
            });
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
                            .with_metadata("reason", serde_json::json!("invalid_api_key")),
                    );
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid API key".into(),
                    }),
                )
                    .into_response();
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
                Json(ErrorResponse {
                    error: "API key required".into(),
                }),
            )
                .into_response()
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
            Json(ErrorResponse {
                error: "rate limit exceeded".into(),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Security headers middleware
// ---------------------------------------------------------------------------

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
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
// Identity + capability snapshot returned by /health. The C2 fans
// out across pod URLs and uses pod_id to deduplicate replicas + uses
// pod_type to label them in the topology view. version + core_version
// give analysts at-a-glance compatibility info; started_at +
// uptime_secs help spot recent restarts (e.g. after a Phase 6 roll).
struct HealthResponse {
    status: &'static str,
    pod: &'static str, // legacy alias — kept so older
    // C2 builds keep parsing
    pod_type: &'static str,     // "siphon-api" | "siphon-fs"
    pod_id: String,             // uuidv4, generated at startup
    version: &'static str,      // crate version of this binary
    core_version: &'static str, // siphon-core crate version
    started_at: String,         // ISO8601, captured at startup
    uptime_secs: u64,
}

#[derive(Serialize, Clone)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        pod: "siphon-api",
        pod_type: "siphon-api",
        pod_id: state.pod_id.to_string(),
        version: env!("CARGO_PKG_VERSION"),
        core_version: siphon_core::VERSION,
        started_at: state.started_at_iso.clone(),
        uptime_secs: state.started_at.elapsed().as_secs(),
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

    // Snapshot the runtime stage-disable set once per scan so a
    // concurrent PATCH /v1/pipeline/stages can't flip a toggle
    // mid-scan and leave us with an inconsistent config. Read-lock +
    // clone of the small HashSet is cheap.
    let stage_disabled: HashSet<String> = state
        .disabled_stages
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    // Snapshot the hot-reloadable overrides once per scan. Read lock
    // released immediately — the cloned Arcs are stable for the
    // scan's lifetime even if Apply swaps the block in the middle.
    let ov = {
        let g = state
            .live_overrides
            .read()
            .expect("live_overrides lock poisoned");
        g.clone()
    };

    let mut config = ScanConfig {
        min_confidence: req.options.min_confidence.unwrap_or(0.0),
        categories: req
            .options
            .categories
            .map(|c| c.into_iter().collect::<HashSet<_>>()),
        require_context: req.options.require_context.unwrap_or(false),
        baseline_only: req.options.baseline_only.unwrap_or(false),
        deduplicate: req.options.deduplicate.unwrap_or(true),
        trace: trace_sink.clone(),
        // Apply the pod-loaded overrides on every scan. Cheap clones —
        // each field is an Arc, not the underlying collection.
        disabled_patterns: Some(ov.disabled_patterns.clone()),
        pattern_field_overrides: Some(ov.pattern_field_overrides.clone()),
        runtime_patterns: Some(ov.runtime_patterns.clone()),
        pattern_regex_overrides: Some(ov.pattern_regex_overrides.clone()),
        list_bindings: Some(ov.list_bindings.clone()),
        max_unique_per_subcategory: Some(ov.unique_thresholds.clone()),
        ..Default::default()
    };
    // Force each disabled stage into its most permissive behaviour.
    // Done AFTER req.options so the toggle can't be bypassed by a
    // caller setting require_context=true — analyst-facing
    // diagnostic switch wins.
    if stage_disabled.contains("min_confidence") {
        config.min_confidence = 0.0;
    }
    if stage_disabled.contains("require_context") {
        config.require_context = false;
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    let matches = scan_text_with_config(&req.text, &config).map_err(|e| {
        state
            .metrics
            .scan_errors_total
            .fetch_add(1, Ordering::Relaxed);
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
    state
        .metrics
        .findings_total
        .fetch_add(count as u64, Ordering::Relaxed);

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
        let outcome = if count == 0 {
            "success"
        } else {
            "findings_detected"
        };
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
    let trace = trace_sink
        .as_ref()
        .and_then(|s| s.lock().ok().map(|g| g.clone()));

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
            let sub_categories: Vec<&'static str> = pats.iter().map(|p| p.sub_category).collect();
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
        (Role::Admin, "admin", "Full control. All permissions."),
        (Role::Analyst, "analyst", "Scan + detokenize + read status."),
        (Role::Operator, "operator", "Scan + read status."),
        (Role::Viewer, "viewer", "Read status only."),
    ];
    const PERMS: [(Permission, &str); 7] = [
        (Permission::Scan, "Scan"),
        (Permission::BatchScan, "BatchScan"),
        (Permission::ManagePatterns, "ManagePatterns"),
        (Permission::Detokenize, "Detokenize"),
        (Permission::ExportVault, "ExportVault"),
        (Permission::ViewStatus, "ViewStatus"),
        (Permission::AdminAction, "AdminAction"),
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
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        patterns_loaded: siphon_core::patterns::PATTERNS.len(),
        categories_loaded: siphon_core::patterns::categories().len(),
    })
}

// ─── /v1/capabilities (Phase 5b.1) ──────────────────────────────
//
// Every pod answers the same capability question: "what can you
// actually do?". The admin console polls this to:
//   · surface a per-pod detail view in the pod-registry panel
//   · detect capability skew between replicas (e.g. one pod was
//     rebuilt with different features)
//   · decide which pods to target for a specific scan (Phase 5b.3)
//
// Shape is deliberately shared between siphon-api and siphon-fs —
// Optional fields cover the two disjoint feature sets (api has
// policies_loaded; fs has supported_extensions). Serde skips None
// so the wire stays clean.

#[derive(Serialize)]
struct CapabilitiesResponse {
    // Identity (duplicates /health so a single call answers 'who are
    // you and what can you do').
    pod_type: &'static str,
    pod_id: String,
    version: &'static str,
    core_version: &'static str,
    // Pipeline facts.
    scanner_pipeline: Vec<&'static str>,
    entropy_modes: Vec<&'static str>,
    overrides_features: Vec<&'static str>,
    // Quantitative snapshot.
    patterns_loaded: usize,
    categories_loaded: usize,
    findings_ring_capacity: usize,
    overrides_summary: siphon_core::overrides::OverridesSummary,
    // siphon-api specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    policies_loaded: Option<usize>,
    // siphon-fs specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    supported_extensions: Option<Vec<String>>,
}

async fn capabilities(State(state): State<Arc<AppState>>) -> Json<CapabilitiesResponse> {
    Json(CapabilitiesResponse {
        pod_type: "siphon-api",
        pod_id: state.pod_id.to_string(),
        version: env!("CARGO_PKG_VERSION"),
        core_version: siphon_core::VERSION,
        // Pipeline stages in the order a candidate traverses them.
        // Matches PS_STAGES in the admin-console simulator so the UI
        // can line them up without a mapping table.
        scanner_pipeline: vec![
            "regex",
            "validation",
            "context",
            "ctx_required",
            "require_context",
            "min_confidence",
            "emit",
        ],
        entropy_modes: vec!["off", "gated", "assignment", "all"],
        // Which overrides axes this build understands + enforces.
        // Lines up with PatternOverrides fields that actually flow
        // into the scanner today.
        overrides_features: vec![
            "disabled_patterns",
            "pattern_overrides",
            "custom_categories",
            "regex_overrides",
            "list_bindings",
        ],
        patterns_loaded: siphon_core::patterns::PATTERNS.len(),
        categories_loaded: siphon_core::patterns::categories().len(),
        findings_ring_capacity: state.findings.capacity(),
        overrides_summary: state
            .live_overrides
            .read()
            .map(|g| g.loaded_overrides.summary())
            .unwrap_or_else(|_| siphon_core::overrides::PatternOverrides::empty().summary()),
        policies_loaded: Some(state.policies.len()),
        supported_extensions: None,
    })
}

// ---------------------------------------------------------------------------
// /v1/overrides — read what the pod is enforcing, read what's on disk,
// apply new state. Phase 4.
//
// Sharp edge: "applied" means the file has been written atomically; it
// does NOT mean the scanner sees the change. Pods load overrides once
// at startup, so the admin console must trigger a rolling restart
// (Phase 6 automates that via kube-rs; until then it's a manual step).
// The response always carries restart_required + an honest note.
// ---------------------------------------------------------------------------
// Per-pod pipeline stage toggles (Phase 9c)
// ---------------------------------------------------------------------------
// Runtime diagnostic knob — lets an operator force a specific scanner
// stage into its most permissive behaviour on one pod without
// redeploying. Useful for A/B comparisons ("same doc scanned with and
// without require_context") and for quickly widening detection during
// incident response. Not persisted; restart clears.

/// Stages the pod recognises as toggleable. Mirrored by
/// /v1/capabilities.scanner_pipeline so the admin console doesn't
/// have to hardcode a list.
const TOGGLEABLE_STAGES: &[&str] = &["min_confidence", "require_context"];

#[derive(Serialize)]
struct StageState {
    stage: &'static str,
    /// `true` when the stage runs normally. `false` means it's been
    /// bypassed by an operator PATCH and every scan gets the stage's
    /// permissive default (min_confidence=0.0, require_context=false).
    enabled: bool,
}

#[derive(Serialize)]
struct StagesResponse {
    total: usize,
    stages: Vec<StageState>,
}

async fn pipeline_stages_get(State(state): State<Arc<AppState>>) -> Json<StagesResponse> {
    let disabled: HashSet<String> = state
        .disabled_stages
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let stages: Vec<StageState> = TOGGLEABLE_STAGES
        .iter()
        .map(|s| StageState {
            stage: s,
            enabled: !disabled.contains(*s),
        })
        .collect();
    Json(StagesResponse {
        total: stages.len(),
        stages,
    })
}

#[derive(Deserialize)]
struct StagesPatchRequest {
    stage: String,
    enabled: bool,
}

async fn pipeline_stages_patch(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<StagesPatchRequest>,
) -> Response {
    if !TOGGLEABLE_STAGES.contains(&req.stage.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "stage {:?} is not toggleable; accepted: {:?}",
                    req.stage, TOGGLEABLE_STAGES
                ),
            }),
        )
            .into_response();
    }
    {
        let mut guard = match state.disabled_stages.write() {
            Ok(g) => g,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "disabled_stages lock poisoned".into(),
                    }),
                )
                    .into_response();
            }
        };
        if req.enabled {
            guard.remove(&req.stage);
        } else {
            guard.insert(req.stage.clone());
        }
    }
    tracing::warn!(
        stage = %req.stage,
        enabled = req.enabled,
        source_ip = %addr.ip(),
        "pipeline stage toggled"
    );
    if let Ok(event) = AuditEvent::new("CONFIG") {
        emit_audit(
            event
                .with_action("pipeline_stage_toggle")
                .with_outcome(if req.enabled { "enabled" } else { "disabled" })
                .with_source_ip(&addr.ip().to_string())
                .with_metadata("stage", serde_json::json!(req.stage)),
        );
    }
    // Rebuild inline rather than re-invoking pipeline_stages_get — no
    // need to take another lock when we already know the final state.
    let disabled: HashSet<String> = state
        .disabled_stages
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let stages: Vec<StageState> = TOGGLEABLE_STAGES
        .iter()
        .map(|s| StageState {
            stage: s,
            enabled: !disabled.contains(*s),
        })
        .collect();
    Json(StagesResponse {
        total: stages.len(),
        stages,
    })
    .into_response()
}

#[derive(Serialize)]
struct OverridesStateResponse {
    /// 'memory' when returning what the scanner is using; 'disk' when
    /// returning a fresh read of the overrides file.
    source: &'static str,
    path: String,
    summary: siphon_core::overrides::OverridesSummary,
    overrides: siphon_core::overrides::PatternOverrides,
}

async fn overrides_current(State(state): State<Arc<AppState>>) -> Json<OverridesStateResponse> {
    let loaded = state
        .live_overrides
        .read()
        .map(|g| (*g.loaded_overrides).clone())
        .unwrap_or_else(|_| siphon_core::overrides::PatternOverrides::empty());
    Json(OverridesStateResponse {
        source: "memory",
        path: state.overrides_path.display().to_string(),
        summary: loaded.summary(),
        overrides: loaded,
    })
}

async fn overrides_disk(
    State(state): State<Arc<AppState>>,
) -> Result<Json<OverridesStateResponse>, (StatusCode, Json<ErrorResponse>)> {
    use siphon_core::overrides::{LoadError, PatternOverrides};
    match PatternOverrides::from_file(state.overrides_path.as_path()) {
        Ok(o) => Ok(Json(OverridesStateResponse {
            source: "disk",
            path: state.overrides_path.display().to_string(),
            summary: o.summary(),
            overrides: o,
        })),
        // Missing file → empty document, not an error. Matches the
        // "overrides are additive" principle from the Phase 3 loader.
        Err(LoadError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            let empty = PatternOverrides::empty();
            Ok(Json(OverridesStateResponse {
                source: "disk",
                path: state.overrides_path.display().to_string(),
                summary: empty.summary(),
                overrides: empty,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("read failed: {e}"),
            }),
        )),
    }
}

#[derive(Serialize)]
struct ApplyResponse {
    status: &'static str,
    written_path: String,
    /// Path of the backup of the PREVIOUS overrides (so an analyst
    /// can roll back manually if something goes wrong before Phase 7
    /// ships). `None` when no prior file existed.
    backup_path: Option<String>,
    /// Backups removed by the auto-prune step during this apply.
    /// Empty when SIPHON_OVERRIDES_KEEP is unset or the file count
    /// was still under the cap. Included in the response so the
    /// audit trail sees which backups went away.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pruned_backups: Vec<String>,
    summary: siphon_core::overrides::OverridesSummary,
    /// `true` when the on-disk write succeeded AND the in-memory
    /// LiveOverrides swap landed, so the pod is scanning with the
    /// new config without needing a restart. `false` only in the
    /// unusual case where the lock was poisoned.
    hot_reloaded: bool,
    /// Kept for backwards compatibility with older consoles — always
    /// false now that hot-reload works. Remove once no one depends
    /// on it.
    restart_required: bool,
    note: &'static str,
}

/// POST /v1/overrides/apply — body is a PatternOverrides document.
/// Validates version + serialises + atomically writes to the
/// configured overrides path, keeping a timestamped backup of the
/// previous contents (if any). Does NOT hot-reload the scanner.
async fn overrides_apply(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(new_overrides): Json<siphon_core::overrides::PatternOverrides>,
) -> Result<Json<ApplyResponse>, (StatusCode, Json<ErrorResponse>)> {
    use siphon_core::overrides::CURRENT_VERSION;

    if new_overrides.version != CURRENT_VERSION {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "schema version {} not supported (expected {CURRENT_VERSION})",
                    new_overrides.version
                ),
            }),
        ));
    }

    let payload = serde_json::to_vec_pretty(&new_overrides).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("serialize failed: {e}"),
            }),
        )
    })?;

    let path = state.overrides_path.as_path();

    // Create the parent directory if it's missing. Fresh local-dev
    // setups (SIPHON_OVERRIDES_PATH=/etc/siphon/overrides.json on a
    // macOS host that doesn't have /etc/siphon) otherwise hit
    // "temp write failed: No such file or directory" at the first
    // Apply. Fails loudly rather than silently — directory creation
    // is expected to succeed on any writable path.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!(
                            "could not create overrides directory {}: {e}. Fix: run the pod \
                             with SIPHON_OVERRIDES_PATH pointing at a writable path, or \
                             `mkdir -p {}` first.",
                            parent.display(),
                            parent.display()
                        ),
                    }),
                ));
            }
            tracing::info!(parent = %parent.display(), "created SIPHON_OVERRIDES_PATH parent dir");
        }
    }

    // Backup the previous file if one exists. Name carries a nanosecond
    // timestamp so concurrent applies (unlikely, but possible) don't
    // clobber each other's backups. Phase 7 (history) will index these.
    let backup_path = if path.exists() {
        let ts_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let backup = path.with_extension(format!("v{ts_ns}.bak"));
        match std::fs::copy(path, &backup) {
            Ok(_) => Some(backup.display().to_string()),
            Err(e) => {
                // Continue with the apply even if backup fails — losing
                // a backup is worse than losing the apply. Logged.
                tracing::warn!(error = %e, path = %path.display(), "overrides apply: backup copy failed");
                None
            }
        }
    } else {
        None
    };

    // Atomic write: write temp + rename. If rename fails we leave the
    // previous file intact.
    let tmp = path.with_extension("tmp.apply");
    std::fs::write(&tmp, &payload).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("temp write failed: {e}"),
            }),
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("atomic rename failed: {e}"),
            }),
        )
    })?;

    // Auto-prune old backups so a chatty admin console doesn't grow
    // the overrides directory without bound. SIPHON_OVERRIDES_KEEP
    // caps the number of .v<nanos>.bak files we retain (newest kept);
    // default 20 is enough for a week of normal tuning, and unset /
    // malformed / 0 disables pruning entirely.
    let prune_keep: Option<usize> = std::env::var("SIPHON_OVERRIDES_KEEP")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0);
    let pruned_backups: Vec<String> = if let Some(keep) = prune_keep {
        prune_backups(path, keep)
    } else {
        Vec::new()
    };

    let summary = new_overrides.summary();
    tracing::info!(
        path = %path.display(),
        source_ip = %addr.ip(),
        disabled = summary.disabled_patterns,
        field_overrides = summary.pattern_overrides,
        custom_categories = summary.custom_categories,
        pruned = pruned_backups.len(),
        "overrides applied"
    );

    if let Ok(event) = AuditEvent::new("CONFIG") {
        emit_audit(
            event
                .with_action("overrides_apply")
                .with_outcome("applied")
                .with_source_ip(&addr.ip().to_string())
                .with_metadata(
                    "disabled_patterns",
                    serde_json::json!(summary.disabled_patterns),
                )
                .with_metadata(
                    "pattern_overrides",
                    serde_json::json!(summary.pattern_overrides),
                )
                .with_metadata(
                    "custom_categories",
                    serde_json::json!(summary.custom_categories),
                ),
        );
    }

    // Hot-reload: rebuild LiveOverrides from the doc we just wrote and
    // swap the whole block under the write lock. Any scan in-flight
    // already took a read snapshot so it finishes on the old view;
    // new scans see the new view.
    let hot_reloaded = match state.live_overrides.write() {
        Ok(mut guard) => {
            *guard = LiveOverrides::from_doc(new_overrides);
            tracing::info!(
                path = %path.display(),
                "overrides hot-reloaded into memory"
            );
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "live_overrides lock poisoned — hot-reload skipped, restart required");
            false
        }
    };

    Ok(Json(ApplyResponse {
        status: "applied",
        written_path: path.display().to_string(),
        backup_path,
        pruned_backups,
        summary,
        hot_reloaded,
        restart_required: !hot_reloaded,
        note:
            "overrides written to disk and hot-reloaded · scans on this pod now use the new ruleset",
    }))
}

/// POST /v1/overrides/reload — rebuilds the in-memory LiveOverrides
/// from whatever's currently at SIPHON_OVERRIDES_PATH. Used by the C2
/// fan-out flow when the overrides file was written by a sibling pod
/// (shared k8s ConfigMap mount, shared local-dev launcher path, etc)
/// and this pod just needs to pick up the change. No body.
#[derive(Serialize)]
struct ReloadResponse {
    status: &'static str,
    path: String,
    summary: siphon_core::overrides::OverridesSummary,
}

async fn overrides_reload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<ReloadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let path = state.overrides_path.as_path();
    let fresh = LiveOverrides::from_path(path);
    let summary = fresh.loaded_overrides.summary();
    match state.live_overrides.write() {
        Ok(mut guard) => {
            *guard = fresh;
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("live_overrides lock poisoned: {e}"),
                }),
            ));
        }
    };
    tracing::info!(
        path = %path.display(),
        source_ip = %addr.ip(),
        disabled = summary.disabled_patterns,
        field_overrides = summary.pattern_overrides,
        custom_categories = summary.custom_categories,
        "overrides reloaded"
    );
    if let Ok(event) = AuditEvent::new("CONFIG") {
        emit_audit(
            event
                .with_action("overrides_reload")
                .with_outcome("reloaded")
                .with_source_ip(&addr.ip().to_string()),
        );
    }
    Ok(Json(ReloadResponse {
        status: "reloaded",
        path: path.display().to_string(),
        summary,
    }))
}

/// Enumerate the `<basename>.v<nanos>.bak` backups next to the main
/// overrides file, sort newest-first, and remove everything past the
/// `keep` cap. Returns the paths of the pruned files so the Apply
/// response can surface them in the audit trail.
fn prune_backups(path: &std::path::Path, keep: usize) -> Vec<String> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Vec::new(),
    };
    let base = match path.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let read = match std::fs::read_dir(parent) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    // Collect entries matching `<base>.v<digits>.bak`. Nanosecond
    // tie-break is baked into the filename so sorting by name =
    // sorting by age.
    let mut candidates: Vec<std::path::PathBuf> = read
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| {
                    let prefix = format!("{base}.v");
                    n.starts_with(&prefix)
                        && n.ends_with(".bak")
                        && n[prefix.len()..n.len() - 4]
                            .chars()
                            .all(|c| c.is_ascii_digit())
                })
                .unwrap_or(false)
        })
        .collect();
    if candidates.len() <= keep {
        return Vec::new();
    }
    candidates.sort_by(|a, b| b.file_name().cmp(&a.file_name())); // newest first
    let mut pruned = Vec::new();
    for old in candidates.into_iter().skip(keep) {
        match std::fs::remove_file(&old) {
            Ok(_) => {
                tracing::info!(path = %old.display(), "pruned old overrides backup");
                pruned.push(old.display().to_string());
            }
            Err(e) => {
                // Backup prune failure is non-fatal — the apply
                // itself still succeeded. Log and carry on.
                tracing::warn!(path = %old.display(), error = %e, "backup prune failed");
            }
        }
    }
    pruned
}

// ─── /v1/overrides/roll (Phase 6) ───────────────────────────────
//
// Triggers a rolling restart of both siphon Deployments by patching
// each one's `spec.template.metadata.annotations.siphon.io/rolledAt`
// to the current ISO8601 timestamp — the standard
// `kubectl rollout restart` behaviour, expressed directly via the
// apps/v1 API. Compiled in behind the `k8s-roll` cargo feature so
// non-k8s builds stay lean.
//
// Without the feature: endpoint returns 501 with an operational
// hint. Auto-roll after /apply (chaining) isn't wired yet — apply
// still returns restart_required=true. A follow-up chains them.

#[cfg(feature = "k8s-roll")]
#[derive(Deserialize, Default)]
#[serde(default)]
struct RollRequest {
    /// Kubernetes namespace hosting the Deployments. Defaults to the
    /// pod's own namespace (read from the service-account mount) or
    /// SIPHON_K8S_NAMESPACE if the ServiceAccount isn't mounted
    /// (e.g. local `kubectl port-forward` into a cluster that the
    /// pod itself isn't in).
    namespace: Option<String>,
    /// Deployment names to roll. Defaults to ["siphon-api",
    /// "siphon-fs"] — the lab's two-Deployment layout.
    deployments: Option<Vec<String>>,
}

#[cfg(feature = "k8s-roll")]
#[derive(Serialize)]
struct RollOutcome {
    deployment: String,
    namespace: String,
    status: &'static str, // "rolled" | "skipped" | "error"
    error: Option<String>,
}

#[cfg(feature = "k8s-roll")]
#[derive(Serialize)]
struct RollResponse {
    status: &'static str,
    rolled_at: String,
    namespace: String,
    deployments: Vec<RollOutcome>,
    note: &'static str,
}

#[cfg(not(feature = "k8s-roll"))]
async fn overrides_roll(
    _state: State<Arc<AppState>>,
    _addr: ConnectInfo<SocketAddr>,
    // Accept + ignore a body so the same client code works against
    // builds with or without the feature.
    _body: Option<Json<serde_json::Value>>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "siphon-api was built without the `k8s-roll` feature — \
                 rebuild with `cargo build --features k8s-roll` or roll \
                 manually with `kubectl -n <ns> rollout restart \
                 deployment/siphon-api deployment/siphon-fs`"
                .to_string(),
        }),
    )
}

#[cfg(feature = "k8s-roll")]
async fn overrides_roll(
    State(_state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    maybe_req: Option<Json<RollRequest>>,
) -> Result<Json<RollResponse>, (StatusCode, Json<ErrorResponse>)> {
    use k8s_openapi::api::apps::v1::Deployment;
    use kube::{
        api::{Api, Patch, PatchParams},
        Client,
    };

    let req: RollRequest = maybe_req.map(|j| j.0).unwrap_or_default();

    // Namespace resolution:
    //   1. explicit request body field
    //   2. SIPHON_K8S_NAMESPACE env override
    //   3. in-cluster service-account mount
    //   4. "default"
    let namespace = req
        .namespace
        .or_else(|| std::env::var("SIPHON_K8S_NAMESPACE").ok())
        .or_else(|| {
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "default".to_string());

    let deployments = req
        .deployments
        .unwrap_or_else(|| vec!["siphon-api".to_string(), "siphon-fs".to_string()]);

    let client = Client::try_default().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!("kube client init failed — not in a cluster? no kubeconfig? · {e}"),
            }),
        )
    })?;
    let api: Api<Deployment> = Api::namespaced(client, &namespace);

    let rolled_at = siphon_core::audit::iso8601_now();
    // Strategic-merge patch: bumping the annotation triggers a
    // rollout because PodTemplate's hash changes. Mirrors kubectl's
    // `kubectl.kubernetes.io/restartedAt` convention but with our
    // own key so we can audit which roller poked each pod.
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "siphon.io/rolledAt": rolled_at,
                    }
                }
            }
        }
    });
    let pp = PatchParams::default();

    let mut outcomes = Vec::with_capacity(deployments.len());
    for name in &deployments {
        match api.patch(name, &pp, &Patch::Strategic(&patch)).await {
            Ok(_) => outcomes.push(RollOutcome {
                deployment: name.clone(),
                namespace: namespace.clone(),
                status: "rolled",
                error: None,
            }),
            Err(e) => outcomes.push(RollOutcome {
                deployment: name.clone(),
                namespace: namespace.clone(),
                status: "error",
                error: Some(e.to_string()),
            }),
        }
    }

    tracing::info!(
        source_ip = %addr.ip(),
        namespace = %namespace,
        deployments = ?deployments,
        rolled = outcomes.iter().filter(|o| o.status == "rolled").count(),
        "overrides roll triggered"
    );
    if let Ok(event) = AuditEvent::new("CONFIG") {
        emit_audit(
            event
                .with_action("overrides_roll")
                .with_outcome("applied")
                .with_source_ip(&addr.ip().to_string())
                .with_metadata("namespace", serde_json::json!(namespace))
                .with_metadata("deployments", serde_json::json!(deployments)),
        );
    }

    Ok(Json(RollResponse {
        status: "rolled",
        rolled_at,
        namespace,
        deployments: outcomes,
        note: "Deployment annotations patched · k8s will cycle the pods per the rolling-update strategy",
    }))
}

// ---------------------------------------------------------------------------
// /v1/k8s/pods — read-only pod discovery for the Ops UI
// ---------------------------------------------------------------------------
//
// The Helm chart's `api-k8s` Role grants list/get/watch on pods in
// the release namespace. This handler surfaces a compact view
// shaped for the Ops page: one row per pod with phase + restart
// count + age + first container's image. Listing the full V1Pod
// spec would ship ~50 KB of data per pod that the UI never renders.
//
// Like overrides_roll, this is feature-gated behind `k8s-roll`. A
// follow-up can split the features if someone wants read-only
// discovery without the patch-deployment capability, but in
// practice the two flow together.

#[cfg(feature = "k8s-roll")]
#[derive(Serialize)]
struct PodSummary {
    name: String,
    namespace: String,
    phase: String,
    ready: bool,
    restarts: u32,
    image: Option<String>,
    node: Option<String>,
    /// Deployment name derived from the pod's `app.kubernetes.io/component`
    /// label plus release name. Nullable when the labels aren't set,
    /// so clients know which pods are restartable via /rollout.
    deployment: Option<String>,
    created_at: Option<String>,
}

#[cfg(feature = "k8s-roll")]
#[derive(Serialize)]
struct PodListResponse {
    namespace: String,
    count: usize,
    pods: Vec<PodSummary>,
}

#[cfg(not(feature = "k8s-roll"))]
async fn k8s_pods(
    _state: State<Arc<AppState>>,
    _addr: ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "siphon-api was built without the `k8s-roll` feature — \
                 the Ops pod view needs kube-rs at runtime. Rebuild with \
                 `cargo build --features k8s-roll`."
                .to_string(),
        }),
    )
}

#[cfg(feature = "k8s-roll")]
async fn k8s_pods(
    State(_state): State<Arc<AppState>>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> Result<Json<PodListResponse>, (StatusCode, Json<ErrorResponse>)> {
    use k8s_openapi::api::core::v1::Pod;
    use kube::{
        api::{Api, ListParams},
        Client,
    };

    let namespace = resolve_namespace();

    let client = Client::try_default().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!("kube client init failed · {e}"),
            }),
        )
    })?;
    let api: Api<Pod> = Api::namespaced(client, &namespace);

    // Default list view is scoped to pods that carry the
    // `app.kubernetes.io/part-of=siphon` label — the chart labels
    // every Deployment with it. That keeps the Ops view from
    // filling up with unrelated workloads that happen to share
    // the namespace.
    let lp = ListParams::default().labels("app.kubernetes.io/part-of=siphon");

    let pods = api.list(&lp).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: format!("kube pods.list · {e}"),
            }),
        )
    })?;

    let summaries: Vec<PodSummary> = pods.items.iter().map(pod_summary).collect();

    Ok(Json(PodListResponse {
        namespace,
        count: summaries.len(),
        pods: summaries,
    }))
}

/// Resolve the effective namespace for all /v1/k8s/* handlers.
/// Mirrors the rule-set used by /v1/overrides/roll so the two
/// agree by construction.
#[cfg(feature = "k8s-roll")]
fn resolve_namespace() -> String {
    std::env::var("SIPHON_K8S_NAMESPACE")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "default".to_string())
}

/// Project a V1Pod down to the flat row the Ops UI renders.
/// Pulls just the fields the table needs — phase, ready flag
/// computed from the per-container readiness map, restart sum,
/// first container image, node name, and the creation timestamp
/// (used client-side to derive age).
#[cfg(feature = "k8s-roll")]
fn pod_summary(pod: &k8s_openapi::api::core::v1::Pod) -> PodSummary {
    let meta = &pod.metadata;
    let name = meta.name.clone().unwrap_or_default();
    let namespace = meta.namespace.clone().unwrap_or_default();

    let (phase, ready, restarts, image, node) = match (&pod.spec, &pod.status) {
        (Some(spec), Some(status)) => {
            let phase = status
                .phase
                .clone()
                .unwrap_or_else(|| "Unknown".to_string());
            let ready = status
                .container_statuses
                .as_ref()
                .map(|cs| !cs.is_empty() && cs.iter().all(|c| c.ready))
                .unwrap_or(false);
            let restarts = status
                .container_statuses
                .as_ref()
                .map(|cs| cs.iter().map(|c| c.restart_count.max(0) as u32).sum())
                .unwrap_or(0);
            let image = spec.containers.first().and_then(|c| c.image.clone());
            let node = spec.node_name.clone();
            (phase, ready, restarts, image, node)
        }
        _ => ("Unknown".to_string(), false, 0, None, None),
    };

    // Try the standard well-known label first (Helm chart sets it),
    // then fall back to the owner-reference Deployment controller
    // if the labels aren't set.
    let deployment = meta
        .labels
        .as_ref()
        .and_then(|m| m.get("app.kubernetes.io/component").cloned());

    // k8s-openapi 0.27 swapped chrono for jiff; Timestamp's
    // Display is already ISO-8601 so we just format it.
    let created_at = meta.creation_timestamp.as_ref().map(|t| t.0.to_string());

    PodSummary {
        name,
        namespace,
        phase,
        ready,
        restarts,
        image,
        node,
        deployment,
        created_at,
    }
}

// ---------------------------------------------------------------------------
// POST /v1/k8s/deployments/{name}/rollout — convenience wrapper
// ---------------------------------------------------------------------------
//
// The Ops UI wants to restart a single Deployment at a time (click
// a row → "Restart"). /v1/overrides/roll takes a list; this endpoint
// takes a path param and forwards as a one-element list so the UI
// doesn't have to synthesize the body.

#[cfg(not(feature = "k8s-roll"))]
async fn k8s_rollout(
    _state: State<Arc<AppState>>,
    _addr: ConnectInfo<SocketAddr>,
    _path: axum::extract::Path<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "siphon-api was built without the `k8s-roll` feature.".to_string(),
        }),
    )
}

#[cfg(feature = "k8s-roll")]
async fn k8s_rollout(
    state: State<Arc<AppState>>,
    addr: ConnectInfo<SocketAddr>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<RollResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Forward to the existing roll handler with a single-element
    // deployment list. Keeps the RBAC + audit-log wiring in one
    // place.
    let body = Json(RollRequest {
        namespace: None,
        deployments: Some(vec![name]),
    });
    overrides_roll(state, addr, Some(body)).await
}

// ─── /v1/overrides/history + /revert (Phase 7) ─────────────────
//
// `apply` has been creating timestamped `.v<nanos>.bak` backups
// alongside the overrides file since 4a. This pair of endpoints
// surfaces that history for the admin console:
//
//   · GET  /v1/overrides/history — list all backups + the current
//                                   file, newest-first, with size +
//                                   mtime + parsed-or-malformed
//                                   indicators.
//   · POST /v1/overrides/revert  — body: { version }. Copies the
//                                   chosen backup back over the
//                                   current file (itself backed up
//                                   first so revert is undoable).
//
// Revert deliberately DOESN'T hot-reload — same operational model as
// apply: write the file, require a pod restart to pick up the
// change. Phase 6 auto-roll handles the restart; until then the
// response includes restart_required=true.

#[derive(Serialize)]
struct HistoryEntry {
    /// Wire-stable version id ("current" for the live file;
    /// "v<unix_nanos>" for backups) so the revert endpoint can
    /// round-trip exactly what history returned.
    version: String,
    path: String,
    size_bytes: u64,
    /// ISO8601 mtime (or nanos-derived when the filename carries one).
    ts: String,
    /// `true` when the bytes parse cleanly as a PatternOverrides
    /// document. Lets the UI grey out a malformed version so the
    /// analyst doesn't try to revert to an unusable snapshot.
    parses: bool,
    summary: Option<siphon_core::overrides::OverridesSummary>,
}

#[derive(Serialize)]
struct HistoryResponse {
    current_path: String,
    total: usize,
    entries: Vec<HistoryEntry>,
}

fn parse_backup_entry(path: &std::path::Path, current_stem: &str) -> Option<HistoryEntry> {
    use siphon_core::overrides::PatternOverrides;
    let file_name = path.file_name()?.to_str()?;
    // Apply uses `path.with_extension("v<nanos>.bak")` which strips
    // the original extension, so a backup of /tmp/overrides.json
    // lands at /tmp/overrides.v<nanos>.bak. Parse format is therefore
    // "<stem>.v<nanos>.bak" — match on the stem, not the full file
    // name.
    let prefix = format!("{current_stem}.v");
    if !file_name.starts_with(&prefix) || !file_name.ends_with(".bak") {
        return None;
    }
    let mid = &file_name[prefix.len()..file_name.len() - ".bak".len()];
    let nanos: u128 = mid.parse().ok()?;
    let version = format!("v{nanos}");

    let meta = std::fs::metadata(path).ok()?;
    let size_bytes = meta.len();
    // Prefer the filename-encoded nanos timestamp over the filesystem
    // mtime — backups are rsync-safe that way.
    let secs = (nanos / 1_000_000_000) as i64;
    let sub_nanos = (nanos % 1_000_000_000) as u32;
    let ts = format_iso8601(secs, sub_nanos);

    let bytes = std::fs::read(path).ok()?;
    let parsed = PatternOverrides::from_bytes(&bytes).ok();
    Some(HistoryEntry {
        version,
        path: path.display().to_string(),
        size_bytes,
        ts,
        parses: parsed.is_some(),
        summary: parsed.as_ref().map(|o| o.summary()),
    })
}

/// Minimal UNIX-seconds → ISO8601 formatter. Avoids pulling chrono
/// into siphon-api for a single call site; the audit module has
/// iso8601_now() but not a seconds-based variant.
fn format_iso8601(secs: i64, nanos: u32) -> String {
    // Good enough for the admin console — humans read it, Rust
    // doesn't parse it back.
    let days_per_year = [365, 365, 365, 366];
    let mut y = 1970;
    let mut days = secs / 86_400;
    let mut secs_today = secs % 86_400;
    if secs_today < 0 {
        days -= 1;
        secs_today += 86_400;
    }
    // Walk forward by year blocks until the remaining days fit.
    while days >= 1461 {
        y += 4;
        days -= 1461;
    }
    while days >= days_per_year[(y - 1970) as usize % 4] as i64 {
        days -= days_per_year[(y - 1970) as usize % 4] as i64;
        y += 1;
    }
    let is_leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    while m < 12 && days >= month_days[m] as i64 {
        days -= month_days[m] as i64;
        m += 1;
    }
    let h = secs_today / 3600;
    let mn = (secs_today % 3600) / 60;
    let s = secs_today % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m + 1,
        days + 1,
        h,
        mn,
        s,
        nanos / 1_000_000
    )
}

async fn overrides_history(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let path = state.overrides_path.as_path();
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("overrides");

    let mut entries: Vec<HistoryEntry> = Vec::new();

    // Current file first (if present) with version id "current".
    if path.exists() {
        if let (Ok(meta), Ok(bytes)) = (std::fs::metadata(path), std::fs::read(path)) {
            let parsed = siphon_core::overrides::PatternOverrides::from_bytes(&bytes).ok();
            let ts = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| format_iso8601(d.as_secs() as i64, d.subsec_nanos()))
                .unwrap_or_else(|| "—".to_string());
            entries.push(HistoryEntry {
                version: "current".to_string(),
                path: path.display().to_string(),
                size_bytes: meta.len(),
                ts,
                parses: parsed.is_some(),
                summary: parsed.as_ref().map(|o| o.summary()),
            });
        }
    }

    // Backups alongside the current file. Ignore unrelated files.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for dirent in rd.flatten() {
            let p = dirent.path();
            if p == path {
                continue;
            }
            if let Some(entry) = parse_backup_entry(&p, stem) {
                entries.push(entry);
            }
        }
    }

    // Newest first. 'current' always wins the tie via its higher
    // mtime; backups sort by their parsed nanos timestamp.
    entries.sort_by(|a, b| b.ts.cmp(&a.ts));

    Ok(Json(HistoryResponse {
        current_path: path.display().to_string(),
        total: entries.len(),
        entries,
    }))
}

/// GET /v1/overrides/content?version=<ver> — returns the parsed
/// PatternOverrides document for a specific version ("current" or
/// "v<nanos>"). Used by the admin console's history diff viewer.
/// Kept separate from /history so that listing doesn't pay the
/// deserialise+serialise cost for every backup file.
#[derive(Deserialize)]
struct OverridesContentQuery {
    version: String,
}

#[derive(Serialize)]
struct OverridesContentResponse {
    version: String,
    path: String,
    /// Raw JSON of the file, parsed from the bytes on disk. Always a
    /// valid PatternOverrides when `parses` is true.
    overrides: siphon_core::overrides::PatternOverrides,
    parses: bool,
}

async fn overrides_content(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OverridesContentQuery>,
) -> Result<Json<OverridesContentResponse>, (StatusCode, Json<ErrorResponse>)> {
    use siphon_core::overrides::PatternOverrides;
    let path = state.overrides_path.as_path();
    let (target_path, label) = if q.version == "current" {
        (path.to_path_buf(), "current".to_string())
    } else {
        // Expect "v<nanos>"; look up the sibling backup file.
        let nanos = q
            .version
            .strip_prefix('v')
            .and_then(|n| n.parse::<u128>().ok())
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!(
                            "bad version {:?}; expected 'current' or 'v<nanos>'",
                            q.version
                        ),
                    }),
                )
            })?;
        let backup = path.with_extension(format!("v{nanos}.bak"));
        if !backup.exists() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("no backup at {}", backup.display()),
                }),
            ));
        }
        (backup, q.version.clone())
    };

    match std::fs::read(&target_path) {
        Ok(bytes) => {
            // Unparseable backups return parses=false + empty overrides
            // so the UI can still diff against whatever the scanner
            // WOULD have seen (which is: default overrides — the
            // parse would have failed at pod load).
            match PatternOverrides::from_bytes(&bytes) {
                Ok(o) => Ok(Json(OverridesContentResponse {
                    version: label,
                    path: target_path.display().to_string(),
                    overrides: o,
                    parses: true,
                })),
                Err(_) => Ok(Json(OverridesContentResponse {
                    version: label,
                    path: target_path.display().to_string(),
                    overrides: PatternOverrides::empty(),
                    parses: false,
                })),
            }
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("read failed: {e}"),
            }),
        )),
    }
}

#[derive(Deserialize)]
struct RevertRequest {
    version: String,
}

#[derive(Serialize)]
struct RevertResponse {
    status: &'static str,
    reverted_to: String,
    written_path: String,
    backup_path: Option<String>,
    summary: siphon_core::overrides::OverridesSummary,
    restart_required: bool,
    note: &'static str,
}

/// POST /v1/overrides/revert — body: { version }. Reverts the live
/// overrides file to the contents of the named backup. The current
/// file is backed up FIRST so a revert is itself undoable via
/// another revert.
async fn overrides_revert(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RevertRequest>,
) -> Result<Json<RevertResponse>, (StatusCode, Json<ErrorResponse>)> {
    use siphon_core::overrides::PatternOverrides;
    let path = state.overrides_path.as_path();
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("overrides");

    if req.version == "current" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "'current' is the live file; nothing to revert to".into(),
            }),
        ));
    }

    // req.version is attacker-controlled (JSON body). Reject anything
    // that isn't a v<nanos> token — without this, a version like
    // "../../etc/passwd" composes into the backup filename and
    // dir.join() happily walks out of the overrides directory.
    if !siphon_core::path_guard::is_safe_version_token(&req.version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid version {:?}; expected 'v<nanos>'", req.version),
            }),
        ));
    }

    // Expected backup filename shape: "<stem>.<version>.bak"
    // (apply's with_extension() strips the original ext — see
    // parse_backup_entry for the symmetric decode).
    let backup_name = format!("{stem}.{}.bak", req.version);
    let backup_path = dir.join(&backup_name);
    if !backup_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("no such backup: {}", backup_path.display()),
            }),
        ));
    }
    // Defense-in-depth: canonicalize and confirm the resolved file is
    // still inside the overrides dir before we read it. Runs after
    // the existence check so canonicalize has a real path to resolve
    // symlinks against.
    match (dir.canonicalize(), backup_path.canonicalize()) {
        (Ok(canon_dir), Ok(canon_backup)) if canon_backup.starts_with(&canon_dir) => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "backup path escapes overrides directory: {}",
                        backup_path.display()
                    ),
                }),
            ));
        }
    }
    let bytes = std::fs::read(&backup_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("read backup failed: {e}"),
            }),
        )
    })?;
    let parsed = PatternOverrides::from_bytes(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("backup does not parse as PatternOverrides: {e}"),
            }),
        )
    })?;

    // Back up the CURRENT file first so the revert itself is
    // undoable — same convention as /apply.
    let pre_revert_backup = if path.exists() {
        let ts_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let bkp = path.with_extension(format!("v{ts_ns}.bak"));
        match std::fs::copy(path, &bkp) {
            Ok(_) => Some(bkp.display().to_string()),
            Err(e) => {
                tracing::warn!(error = %e, "revert: pre-revert backup failed");
                None
            }
        }
    } else {
        None
    };

    // Atomic replace: write the backup contents as a fresh temp file
    // then rename over the current file. Keeps /current readable at
    // every instant (even under crash).
    let tmp = path.with_extension("tmp.revert");
    std::fs::write(&tmp, &bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("temp write failed: {e}"),
            }),
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("atomic rename failed: {e}"),
            }),
        )
    })?;

    tracing::info!(
        source_ip = %addr.ip(),
        version = %req.version,
        backup = %backup_path.display(),
        "overrides reverted"
    );
    if let Ok(event) = AuditEvent::new("CONFIG") {
        emit_audit(
            event
                .with_action("overrides_revert")
                .with_outcome("applied")
                .with_source_ip(&addr.ip().to_string())
                .with_metadata("reverted_to", serde_json::json!(req.version)),
        );
    }

    Ok(Json(RevertResponse {
        status: "reverted",
        reverted_to: req.version.clone(),
        written_path: path.display().to_string(),
        backup_path: pre_revert_backup,
        summary: parsed.summary(),
        restart_required: true,
        note: "overrides file restored to the requested version · restart detection pods to pick up the changes",
    }))
}

// ---------------------------------------------------------------------------
// Bundled documentation — every markdown file in docs/ (plus README) is
// baked into the binary at compile time. The admin console renders
// these via GET /v1/docs (index) and GET /v1/docs/content?path=... .
// ---------------------------------------------------------------------------

const DOCS_INDEX: &[(&str, &str)] = &[
    ("README.md", include_str!("../../../README.md")),
    (
        "docs/ARCHITECTURE.md",
        include_str!("../../../docs/ARCHITECTURE.md"),
    ),
    (
        "docs/BENCHMARKS.md",
        include_str!("../../../docs/BENCHMARKS.md"),
    ),
    (
        "docs/CHANGELOG.md",
        include_str!("../../../docs/CHANGELOG.md"),
    ),
    (
        "docs/KEYWORDS.md",
        include_str!("../../../docs/KEYWORDS.md"),
    ),
    (
        "docs/PATTERNS.md",
        include_str!("../../../docs/PATTERNS.md"),
    ),
    (
        "docs/advanced_techniques.md",
        include_str!("../../../docs/advanced_techniques.md"),
    ),
    (
        "docs/api-reference.md",
        include_str!("../../../docs/api-reference.md"),
    ),
    (
        "docs/architecture/context-matching.md",
        include_str!("../../../docs/architecture/context-matching.md"),
    ),
    (
        "docs/architecture/extending.md",
        include_str!("../../../docs/architecture/extending.md"),
    ),
    (
        "docs/architecture/microservices.md",
        include_str!("../../../docs/architecture/microservices.md"),
    ),
    (
        "docs/architecture/normalization.md",
        include_str!("../../../docs/architecture/normalization.md"),
    ),
    (
        "docs/architecture/pipeline.md",
        include_str!("../../../docs/architecture/pipeline.md"),
    ),
    (
        "docs/architecture/validation.md",
        include_str!("../../../docs/architecture/validation.md"),
    ),
    (
        "docs/architecture/zero-trust.md",
        include_str!("../../../docs/architecture/zero-trust.md"),
    ),
    (
        "docs/baselines/ABOUT-BASELINES.md",
        include_str!("../../../docs/baselines/ABOUT-BASELINES.md"),
    ),
    (
        "docs/baselines/BASELINE-CONFIGURATION-REFERENCE.md",
        include_str!("../../../docs/baselines/BASELINE-CONFIGURATION-REFERENCE.md"),
    ),
    (
        "docs/baselines/confidential-documents.md",
        include_str!("../../../docs/baselines/confidential-documents.md"),
    ),
    (
        "docs/baselines/index.md",
        include_str!("../../../docs/baselines/index.md"),
    ),
    (
        "docs/baselines/internal-financial.md",
        include_str!("../../../docs/baselines/internal-financial.md"),
    ),
    (
        "docs/baselines/pci.md",
        include_str!("../../../docs/baselines/pci.md"),
    ),
    (
        "docs/baselines/phi-keywords.md",
        include_str!("../../../docs/baselines/phi-keywords.md"),
    ),
    (
        "docs/baselines/phi-patterns.md",
        include_str!("../../../docs/baselines/phi-patterns.md"),
    ),
    (
        "docs/baselines/phi.md",
        include_str!("../../../docs/baselines/phi.md"),
    ),
    (
        "docs/baselines/pii-keywords.md",
        include_str!("../../../docs/baselines/pii-keywords.md"),
    ),
    (
        "docs/baselines/pii-patterns.md",
        include_str!("../../../docs/baselines/pii-patterns.md"),
    ),
    (
        "docs/baselines/pii.md",
        include_str!("../../../docs/baselines/pii.md"),
    ),
    (
        "docs/baselines/source-code-secrets.md",
        include_str!("../../../docs/baselines/source-code-secrets.md"),
    ),
    (
        "docs/deployment/cicd.md",
        include_str!("../../../docs/deployment/cicd.md"),
    ),
    (
        "docs/deployment/docker.md",
        include_str!("../../../docs/deployment/docker.md"),
    ),
    (
        "docs/deployment/pre-commit.md",
        include_str!("../../../docs/deployment/pre-commit.md"),
    ),
    (
        "docs/deployment/pypi.md",
        include_str!("../../../docs/deployment/pypi.md"),
    ),
    (
        "docs/enterprise/api.md",
        include_str!("../../../docs/enterprise/api.md"),
    ),
    (
        "docs/enterprise/audit.md",
        include_str!("../../../docs/enterprise/audit.md"),
    ),
    (
        "docs/enterprise/batch.md",
        include_str!("../../../docs/enterprise/batch.md"),
    ),
    (
        "docs/enterprise/classification.md",
        include_str!("../../../docs/enterprise/classification.md"),
    ),
    (
        "docs/enterprise/compliance.md",
        include_str!("../../../docs/enterprise/compliance.md"),
    ),
    (
        "docs/enterprise/env-config.md",
        include_str!("../../../docs/enterprise/env-config.md"),
    ),
    (
        "docs/enterprise/observability.md",
        include_str!("../../../docs/enterprise/observability.md"),
    ),
    (
        "docs/enterprise/rate-limiting.md",
        include_str!("../../../docs/enterprise/rate-limiting.md"),
    ),
    (
        "docs/enterprise/rbac.md",
        include_str!("../../../docs/enterprise/rbac.md"),
    ),
    (
        "docs/enterprise/security.md",
        include_str!("../../../docs/enterprise/security.md"),
    ),
    (
        "docs/enterprise/siem.md",
        include_str!("../../../docs/enterprise/siem.md"),
    ),
    (
        "docs/evasion_defenses.md",
        include_str!("../../../docs/evasion_defenses.md"),
    ),
    (
        "docs/evasion_techniques.md",
        include_str!("../../../docs/evasion_techniques.md"),
    ),
    (
        "docs/getting-started/concepts.md",
        include_str!("../../../docs/getting-started/concepts.md"),
    ),
    (
        "docs/getting-started/configuration.md",
        include_str!("../../../docs/getting-started/configuration.md"),
    ),
    (
        "docs/getting-started/installation.md",
        include_str!("../../../docs/getting-started/installation.md"),
    ),
    (
        "docs/getting-started/quickstart.md",
        include_str!("../../../docs/getting-started/quickstart.md"),
    ),
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
    if path == "README.md" {
        return "root";
    }
    let rest = path.strip_prefix("docs/").unwrap_or(path);
    if let Some(slash) = rest.find('/') {
        match &rest[..slash] {
            "architecture" => "architecture",
            "baselines" => "baselines",
            "deployment" => "deployment",
            "enterprise" => "enterprise",
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
    Json(DocResponse {
        path: "docs/CHANGELOG.md",
        format: "markdown",
        content: c,
        bytes: c.len(),
    })
}
async fn doc_architecture() -> Json<DocResponse> {
    let c = doc_by_path("docs/ARCHITECTURE.md").unwrap_or("");
    Json(DocResponse {
        path: "docs/ARCHITECTURE.md",
        format: "markdown",
        content: c,
        bytes: c.len(),
    })
}
async fn doc_readme() -> Json<DocResponse> {
    let c = doc_by_path("README.md").unwrap_or("");
    Json(DocResponse {
        path: "README.md",
        format: "markdown",
        content: c,
        bytes: c.len(),
    })
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
        let hit_rate = if total == 0 {
            0.0
        } else {
            s.hits as f64 / total as f64
        };
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
        ("splunk", || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("elasticsearch", || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("syslog", || std::env::var("DLPSCAN_SIEM_HOST").ok()),
        ("webhook", || std::env::var("DLPSCAN_SIEM_URL").ok()),
        ("datadog", || std::env::var("DLPSCAN_SIEM_SITE").ok()),
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
    let ring_handler: Box<dyn AuditHandler> = Box::new(RingBufferAuditHandler::new(
        audit_ring.clone(),
        audit_ring_cap,
    ));
    let logger = match build_audit_logger(
        std::env::var("SIPHON_AUDIT_LOG_PATH").ok().as_deref(),
        std::env::var("SIPHON_AUDIT_SIGNING_KEY_HEX")
            .ok()
            .as_deref(),
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
                    let texts = v
                        .get("texts")
                        .and_then(|x| x.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let patterns = v
                        .get("patterns")
                        .and_then(|x| x.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let paths = v
                        .get("paths")
                        .and_then(|x| x.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect()
                        })
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
        // No SIPHON_CORS_ORIGINS set → local-dev default. The admin
        // console is typically served from file:// (Origin: null) or a
        // sibling origin like the lab ingress, so without a permissive
        // default every browser fetch 'Load failed's on CORS. Matches
        // siphon-fs exactly for parity. Production deployments should
        // set SIPHON_CORS_ORIGINS to a specific origin list — the
        // explicit branch above takes precedence.
        _ => CorsLayer::permissive(),
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
    let live_overrides = LiveOverrides::from_doc(overrides);
    tracing::info!(
        path = %overrides_path,
        version = overrides_summary.version,
        disabled = overrides_summary.disabled_patterns,
        field_overrides = overrides_summary.pattern_overrides,
        custom_categories = overrides_summary.custom_categories,
        runtime_patterns_compiled = live_overrides.runtime_patterns.len(),
        regex_swaps_compiled = live_overrides.pattern_regex_overrides.len(),
        list_bindings_active = live_overrides.list_bindings.len(),
        unique_thresholds = live_overrides.unique_thresholds.len(),
        "PatternOverrides loaded"
    );

    let pod_id = Arc::new(uuid::Uuid::new_v4().to_string());
    let started_at = Instant::now();
    let started_at_iso = siphon_core::audit::iso8601_now();
    let overrides_path_arc = Arc::new(std::path::PathBuf::from(&overrides_path));

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
        live_overrides: Arc::new(RwLock::new(live_overrides)),
        pod_id: pod_id.clone(),
        started_at_iso,
        started_at,
        overrides_path: overrides_path_arc,
        disabled_stages: Arc::new(RwLock::new(HashSet::new())),
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
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/overrides/current", get(overrides_current))
        .route("/v1/overrides/disk", get(overrides_disk))
        .route("/v1/overrides/apply", post(overrides_apply))
        .route("/v1/overrides/reload", post(overrides_reload))
        .route("/v1/overrides/history", get(overrides_history))
        .route("/v1/overrides/content", get(overrides_content))
        .route(
            "/v1/pipeline/stages",
            get(pipeline_stages_get).patch(pipeline_stages_patch),
        )
        .route("/v1/overrides/revert", post(overrides_revert))
        .route("/v1/overrides/roll", post(overrides_roll))
        .route("/v1/k8s/pods", get(k8s_pods))
        .route("/v1/k8s/deployments/{name}/rollout", post(k8s_rollout))
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

        let parsed_addr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(addr = %addr, error = %e, "invalid bind address");
                std::process::exit(1);
            }
        };
        if let Err(e) = axum_server::bind_rustls(parsed_addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            tracing::error!(error = %e, "TLS server terminated with error");
            std::process::exit(1);
        }
    } else {
        if bind != "127.0.0.1" && bind != "::1" {
            tracing::warn!(
                "TLS disabled but binding to {bind} — set SIPHON_TLS_CERT and SIPHON_TLS_KEY for production"
            );
        }

        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(addr = %addr, error = %e, "bind failed — another process likely holds this port");
                std::process::exit(1);
            }
        };

        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        {
            tracing::error!(error = %e, "server terminated with error");
            std::process::exit(1);
        }
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
        let logger = build_audit_logger(
            Some(log_path.to_str().unwrap()),
            Some("not-valid-hex!"),
            None,
        )
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
