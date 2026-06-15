//! Polygon Siphon FS — file-scanner HTTP service.
//!
//! Separate pod from siphon-api so file parsing (PDF, DOCX, archives,
//! OCR, etc.) can scale independently from the text /scan API. Both
//! pods depend on siphon-core for the detection engine, so the regex
//! + keyword + validator stack stays single-source-of-truth.
//!
//! Endpoints:
//!   · GET  /health      — liveness probe (immediate 200)
//!   · GET  /ready       — readiness probe (Phase 3 gates on overrides)
//!   · POST /scan        — multipart file upload → extractor → scanner.
//!                         Each emitted finding is also pushed into
//!                         this pod's FindingsRing so it shows up in
//!                         /v1/findings independently of siphon-api.
//!   · GET  /v1/findings — recent findings from THIS pod's ring.
//!                         Shape matches siphon-api's /v1/findings so
//!                         the admin console can union the two.
//!
//! Graceful shutdown on SIGTERM lands in Phase 5.

use axum::{
    extract::{DefaultBodyLimit, Multipart, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siphon_core::audit::iso8601_now;
use siphon_core::findings_ring::{filter_findings, severity_for, FindingRecord, FindingsRing};
use siphon_core::overrides::{
    CompiledList, PatternOverride, PatternOverrides, Regex, RuntimePattern,
};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

mod db;

const POD_NAME: &str = "siphon-fs";
const FINDINGS_RING_CAP: usize = 500;

/// Upload body cap in bytes, read once at startup. Default 100 MB to
/// match siphon::extractors::extract_text's per-file limit. Override
/// via SIPHON_FS_BODY_LIMIT_MB (integer MB, e.g. "200" for 200 MB).
fn body_limit_bytes() -> usize {
    std::env::var("SIPHON_FS_BODY_LIMIT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(100 * 1024 * 1024)
}

/// Per-file streaming size cap. Checked chunk-by-chunk during multipart
/// intake; returns 413 before the full body is buffered. Separate from
/// the axum body limit (SIPHON_FS_BODY_LIMIT_MB) which gates the raw
/// HTTP body. Default 500 MB.
fn max_file_size_bytes() -> usize {
    std::env::var("SIPHON_FS_MAX_FILE_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(500 * 1024 * 1024)
}

/// Optional override for the temp directory used when streaming uploads
/// to disk. Defaults to the OS temp dir. Set SIPHON_FS_TEMP_DIR to a
/// path on a larger volume when the default is too small.
fn temp_dir_path() -> Option<std::path::PathBuf> {
    std::env::var("SIPHON_FS_TEMP_DIR")
        .ok()
        .map(std::path::PathBuf::from)
}

// ─── shared app state ────────────────────────────────────────────
// FindingsRing is owned by this pod — each siphon-fs replica keeps
// its own local ring. Multi-replica convergence (e.g. gossiping
// findings across replicas) is beyond the Phase 0 lab; the admin
// console queries the Service IP which load-balances across replicas.
//
// Overrides hot-reload: the pre-computed PatternOverrides views live
// behind an RwLock so `POST /v1/overrides/reload` can swap them at
// runtime. Scan handlers take a read snapshot once per request.
#[derive(Clone)]
struct LiveOverrides {
    disabled_patterns: Arc<HashSet<(String, String)>>,
    pattern_field_overrides: Arc<HashMap<(String, String), PatternOverride>>,
    runtime_patterns: Arc<Vec<RuntimePattern>>,
    pattern_regex_overrides: Arc<HashMap<(String, String), Regex>>,
    list_bindings: Arc<Vec<(String, CompiledList)>>,
    unique_thresholds: Arc<HashMap<(String, String), usize>>,
    loaded_overrides: Arc<PatternOverrides>,
}

impl LiveOverrides {
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

#[derive(Clone)]
struct AppState {
    findings: Arc<FindingsRing>,
    /// Hot-reloadable overrides. See LiveOverrides above.
    live_overrides: Arc<std::sync::RwLock<LiveOverrides>>,
    /// Path on disk to the overrides file — used by /v1/overrides/reload
    /// to re-read on operator command.
    overrides_path: Arc<std::path::PathBuf>,
    /// Stable identifier for this pod instance (uuidv4, generated at
    /// startup). Returned by /health so the C2 can deduplicate
    /// replicas of the same Service.
    pod_id: Arc<String>,
    /// Wall-clock startup timestamp (ISO8601).
    started_at_iso: String,
    /// Monotonic startup mark for uptime calculation.
    started_at: Instant,
    /// Optional Postgres pool. None when SIPHON_DATABASE_URL is unset
    /// or Postgres was unreachable at startup. Every consumer must
    /// handle the None case gracefully — persistence is always optional.
    db_pool: Option<deadpool_postgres::Pool>,
    /// Per-file size cap enforced during streaming multipart intake.
    /// Read once at startup from SIPHON_FS_MAX_FILE_SIZE_MB.
    max_file_bytes: usize,
    /// Optional temp directory for streamed uploads. None → OS default.
    /// Read once at startup from SIPHON_FS_TEMP_DIR.
    temp_dir: Option<std::path::PathBuf>,
}

// ─── health + readiness ──────────────────────────────────────────
// Identity + capability snapshot. Mirrors siphon-api's /health so the
// C2 can fan out across mixed pod fleets and treat both pod types
// uniformly. pod_id deduplicates replicas; pod_type labels them.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,  // legacy alias kept for older C2 builds
    pod_type: &'static str, // "siphon-fs"
    pod_id: String,         // uuidv4, generated at startup
    version: &'static str,
    core_version: &'static str,
    started_at: String,
    uptime_secs: u64,
}

fn build_health(state: &AppState, status: &'static str) -> JsonResponse<HealthResponse> {
    JsonResponse(HealthResponse {
        status,
        service: POD_NAME,
        pod_type: POD_NAME,
        pod_id: state.pod_id.to_string(),
        version: env!("CARGO_PKG_VERSION"),
        core_version: siphon_core::VERSION,
        started_at: state.started_at_iso.clone(),
        uptime_secs: state.started_at.elapsed().as_secs(),
    })
}

async fn health(State(state): State<AppState>) -> JsonResponse<HealthResponse> {
    build_health(&state, "ok")
}

async fn ready(State(state): State<AppState>) -> JsonResponse<HealthResponse> {
    // Same payload as /health until Phase 3+ introduces the overrides-
    // parsing gate. Keeping endpoints separate now so k8s manifests
    // can target /ready today without refactoring.
    build_health(&state, "ready")
}

// ─── /v1/capabilities (Phase 5b.1) ──────────────────────────────
// Mirrors siphon-api's capabilities response. Shared wire shape so
// the admin console can treat both pod types uniformly; disjoint
// fields (policies_loaded / supported_extensions) serde-skip when
// None.
#[derive(Serialize)]
struct CapabilitiesResponse {
    pod_type: &'static str,
    pod_id: String,
    version: &'static str,
    core_version: &'static str,
    scanner_pipeline: Vec<&'static str>,
    entropy_modes: Vec<&'static str>,
    overrides_features: Vec<&'static str>,
    patterns_loaded: usize,
    categories_loaded: usize,
    findings_ring_capacity: usize,
    overrides_summary: siphon_core::overrides::OverridesSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    policies_loaded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supported_extensions: Option<Vec<String>>,
}

async fn capabilities(State(state): State<AppState>) -> JsonResponse<CapabilitiesResponse> {
    // Pull the runtime extractor map so the response stays in sync
    // with what's actually in the binary (features can be compiled
    // out via cargo build flags).
    let mut exts = siphon::extractors::supported_extensions();
    exts.sort_unstable();
    exts.dedup();

    // Snapshot the current in-memory overrides so the summary
    // reflects whatever's loaded right now (including any hot-reload
    // that happened since startup).
    let summary = state
        .live_overrides
        .read()
        .map(|g| g.loaded_overrides.summary())
        .unwrap_or_else(|_| PatternOverrides::empty().summary());

    JsonResponse(CapabilitiesResponse {
        pod_type: POD_NAME,
        pod_id: state.pod_id.to_string(),
        version: env!("CARGO_PKG_VERSION"),
        core_version: siphon_core::VERSION,
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
        overrides_summary: summary,
        policies_loaded: None,
        supported_extensions: Some(exts),
    })
}

// ─── /scan response shape ────────────────────────────────────────
#[derive(Serialize)]
struct ScanFinding {
    category: String,
    sub_category: String,
    text: String,
    confidence: f64,
    has_context: bool,
    span: (usize, usize),
    /// Scanner-annotated metadata — includes list_action /
    /// list_matched (Phase 4.7c) and unique_count / action=block
    /// (Phase 9). Skipped when empty so the wire stays compact.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    metadata: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct ScanResponse {
    request_id: String,
    filename: Option<String>,
    content_type: Option<String>,
    bytes: usize,
    duration_ms: f64,
    parsed_as: String,
    warnings: Vec<String>,
    findings: Vec<ScanFinding>,
    /// Per-stage trace events — present only when the caller sent
    /// `options={"trace":true}` as a multipart field. Mirrors the shape
    /// siphon-api's /scan returns so the admin console's trace
    /// view renders both pods identically.
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<Vec<siphon_core::scanner::StageEvent>>,
    /// Set when extraction or scanning fails but the request was otherwise
    /// valid. Callers should check this field; an absent `error` means
    /// the scan completed normally.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Machine-readable error class. Currently emitted values:
    ///   PASSWORD_REQUIRED — archive or document is password-protected.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

/// Scan options accepted as a JSON-encoded `options` multipart field.
/// Shape mirrors siphon-api's ScanOptions so the admin console can
/// reuse the same form data for both /scan endpoints. All fields are
/// optional — omitted fields fall back to ScanConfig defaults.
#[derive(Deserialize, Default)]
struct ScanOptions {
    min_confidence: Option<f64>,
    categories: Option<Vec<String>>,
    require_context: Option<bool>,
    baseline_only: Option<bool>,
    deduplicate: Option<bool>,
    trace: Option<bool>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, JsonResponse(ErrorBody { error: msg.into() })).into_response()
}

// ─── /scan handler ───────────────────────────────────────────────
async fn scan(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // (tmp_file, byte_count, sha256_hash) — populated by streaming the
    // multipart "file" field chunk-by-chunk directly into a temp file.
    let mut file_info: Option<(tempfile::NamedTempFile, usize, Vec<u8>)> = None;
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut options: ScanOptions = ScanOptions::default();

    loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                let name = field.name().unwrap_or("").to_string();
                if name == "file" {
                    filename = field.file_name().map(|s| s.to_string());
                    content_type = field.content_type().map(|s| s.to_string());
                    let suffix = filename
                        .as_deref()
                        .and_then(|f| std::path::Path::new(f).extension())
                        .and_then(|s| s.to_str())
                        .map(|s| format!(".{s}"))
                        .unwrap_or_else(|| ".bin".to_string());
                    let mut builder = tempfile::Builder::new();
                    builder.prefix("siphon-fs-").suffix(&suffix);
                    let mut tmp = match match state.temp_dir.as_deref() {
                        Some(dir) => builder.tempfile_in(dir),
                        None => builder.tempfile(),
                    } {
                        Ok(t) => t,
                        Err(e) => {
                            return err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("tempfile create failed: {e}"),
                            );
                        }
                    };
                    let mut hasher = Sha256::new();
                    let mut total_bytes = 0usize;
                    loop {
                        match field.chunk().await {
                            Ok(Some(chunk)) => {
                                total_bytes += chunk.len();
                                if total_bytes > state.max_file_bytes {
                                    return err(
                                        StatusCode::PAYLOAD_TOO_LARGE,
                                        format!(
                                            "file exceeds limit of {} MB",
                                            state.max_file_bytes / (1024 * 1024)
                                        ),
                                    );
                                }
                                hasher.update(chunk.as_ref());
                                if let Err(e) = std::io::Write::write_all(&mut tmp, &chunk) {
                                    return err(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        format!("tempfile write failed: {e}"),
                                    );
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                return err(
                                    StatusCode::BAD_REQUEST,
                                    format!("failed to read file field: {e}"),
                                );
                            }
                        }
                    }
                    file_info = Some((tmp, total_bytes, hasher.finalize().to_vec()));
                } else if name == "options" {
                    // JSON-encoded ScanOptions (mirrors siphon-api's
                    // /scan body shape). Malformed → 400; missing is
                    // fine, options stays at Default.
                    match field.text().await {
                        Ok(s) if !s.is_empty() => match serde_json::from_str::<ScanOptions>(&s) {
                            Ok(o) => options = o,
                            Err(e) => {
                                return err(
                                    StatusCode::BAD_REQUEST,
                                    format!("options JSON parse failed: {e}"),
                                );
                            }
                        },
                        Ok(_) => {}
                        Err(e) => {
                            return err(
                                StatusCode::BAD_REQUEST,
                                format!("options field read failed: {e}"),
                            );
                        }
                    }
                } else {
                    // Unknown field — drain bytes so the next iteration
                    // of the multipart parser advances cleanly.
                    let _ = field.bytes().await;
                }
            }
            Ok(None) => break,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!("multipart parse failed: {e}"),
                );
            }
        }
    }

    let Some((tmp, file_len, file_hash)) = file_info else {
        return err(
            StatusCode::BAD_REQUEST,
            "missing 'file' multipart field".to_string(),
        );
    };

    let tmp_path = tmp.path().to_string_lossy().into_owned();

    // siphon's extractor registry covers text, RTF, EML, PDF, Office
    // (xlsx/docx/pptx), archives (zip/7z/rar/tar), data formats
    // (parquet/csv/sqlite), barcodes, and falls back to plain-text
    // for anything unrecognised. 100MB-per-file / 500MB-per-archive caps.
    let extract = match siphon::extractors::extract_text(&tmp_path) {
        Ok(r) => r,
        Err(e) => {
            let lower = e.to_lowercase();
            let is_password = lower.contains("password") || lower.contains("encrypt");
            warn!(
                request_id = %request_id,
                filename = %filename.clone().unwrap_or_else(|| "<none>".into()),
                error = %e,
                "extraction failed"
            );
            return JsonResponse(ScanResponse {
                request_id,
                filename,
                content_type,
                bytes: file_len,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                parsed_as: "unknown".to_string(),
                warnings: vec![],
                findings: vec![],
                trace: None,
                error: Some(format!("extraction failed: {e}")),
                error_code: if is_password {
                    Some("PASSWORD_REQUIRED".to_string())
                } else {
                    None
                },
            })
            .into_response();
        }
    };

    // Caller opted into tracing — allocate a sink the scanner drains
    // into; None disables tracing at the hot path (no per-candidate
    // allocs).
    let trace_sink: siphon_core::scanner::TraceSink = if options.trace.unwrap_or(false) {
        Some(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
    } else {
        None
    };

    // Snapshot the hot-reloadable overrides once per scan.
    let ov = {
        let g = state
            .live_overrides
            .read()
            .expect("live_overrides lock poisoned");
        g.clone()
    };
    let mut config = ScanConfig {
        disabled_patterns: Some(ov.disabled_patterns.clone()),
        pattern_field_overrides: Some(ov.pattern_field_overrides.clone()),
        runtime_patterns: Some(ov.runtime_patterns.clone()),
        pattern_regex_overrides: Some(ov.pattern_regex_overrides.clone()),
        list_bindings: Some(ov.list_bindings.clone()),
        max_unique_per_subcategory: Some(ov.unique_thresholds.clone()),
        trace: trace_sink.clone(),
        ..Default::default()
    };
    if let Some(v) = options.min_confidence {
        config.min_confidence = v;
    }
    if let Some(v) = options.require_context {
        config.require_context = v;
    }
    if let Some(v) = options.baseline_only {
        config.baseline_only = v;
    }
    if let Some(v) = options.deduplicate {
        config.deduplicate = v;
    }
    if let Some(cats) = options.categories.as_ref() {
        if !cats.is_empty() {
            config.categories = Some(cats.iter().cloned().collect());
        }
    }
    let matches = match scan_text_with_config(&extract.text, &config) {
        Ok(m) => m,
        Err(e) => {
            warn!(request_id = %request_id, error = %e, "scan failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan processing failed".to_string(),
            );
        }
    };

    // Push each finding into this pod's ring BEFORE building the
    // response — that way even if the caller drops the connection
    // the findings are queryable via /v1/findings.
    let ts_now = iso8601_now();
    let short_req = request_id.split('-').next().unwrap_or(&request_id);
    // Use the uploaded filename as the 'source_ip' field. It's not
    // actually an IP, but it's the most useful provenance signal for
    // a file scan (which client sent which file). The admin console
    // already renders source_ip as a provenance label.
    let source_label = filename
        .clone()
        .unwrap_or_else(|| "<anon-upload>".to_string());
    for (idx, m) in matches.iter().enumerate() {
        state.findings.push(FindingRecord {
            id: format!("f-{short_req}-{idx:02x}"),
            ts: ts_now.clone(),
            request_id: request_id.clone(),
            source_ip: source_label.clone(),
            source_pod: POD_NAME.to_string(),
            category: m.category.to_string(),
            sub_category: m.sub_category.to_string(),
            text: m.text.clone(),
            confidence: m.confidence,
            has_context: m.has_context,
            span: (m.span.0, m.span.1),
            metadata: HashMap::new(),
            severity: severity_for(&m.category, m.confidence),
        });
    }

    let findings: Vec<ScanFinding> = matches
        .into_iter()
        .map(|m| ScanFinding {
            category: m.category.to_string(),
            sub_category: m.sub_category.to_string(),
            text: m.text,
            confidence: m.confidence,
            has_context: m.has_context,
            span: (m.span.0, m.span.1),
            metadata: m.metadata,
        })
        .collect();

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Persist findings to Postgres in the background — never blocks the response.
    // SHA-256 was computed incrementally during streaming; raw bytes are not stored.
    {
        let scan_id = uuid::Uuid::new_v4();
        let input_len = file_len;
        let dur_ms = duration_ms as u64;
        let file_name_clone = filename.clone();
        let mime_type_clone = content_type.clone();
        let findings_json: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "category": f.category,
                    "sub_category": f.sub_category,
                    "confidence": f.confidence,
                    "text": f.text,
                    "has_context": f.has_context,
                    "span": [f.span.0, f.span.1],
                    "metadata": f.metadata,
                })
            })
            .collect();
        let pool_clone = state.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = db::persist_scan(
                &pool_clone,
                scan_id,
                &file_hash,
                input_len,
                &findings_json,
                dur_ms,
                POD_NAME,
                env!("CARGO_PKG_VERSION"),
                file_name_clone.as_deref(),
                Some(&file_hash),
                mime_type_clone.as_deref(),
            )
            .await
            {
                tracing::warn!("file scan persist failed: {e}");
            }
        });
    }

    info!(
        request_id = %request_id,
        filename = %filename.clone().unwrap_or_else(|| "<none>".into()),
        bytes = file_len,
        parsed_as = %extract.format,
        findings = findings.len(),
        duration_ms = %format!("{duration_ms:.2}"),
        "scan ok"
    );

    // Drain the trace sink after the scan completes. The scanner only
    // writes to it mid-pipeline, so unlocking here is race-free.
    let trace = trace_sink.and_then(|s| s.lock().ok().map(|g| g.clone()));

    JsonResponse(ScanResponse {
        request_id,
        filename,
        content_type,
        bytes: file_len,
        duration_ms,
        parsed_as: extract.format,
        warnings: extract.warnings,
        findings,
        trace,
        error: None,
        error_code: None,
    })
    .into_response()
}

// ─── /v1/findings handler ────────────────────────────────────────
// Mirrors siphon-api's /v1/findings so the admin console can fan-out
// to both pods and union the rings.
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
    State(state): State<AppState>,
    Query(q): Query<FindingsQuery>,
) -> JsonResponse<FindingsResponse> {
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
    JsonResponse(FindingsResponse {
        total,
        returned,
        capacity,
        findings,
    })
}

// ─── /v1/overrides/reload handler ───────────────────────────────
// Re-reads SIPHON_OVERRIDES_PATH and swaps the in-memory LiveOverrides.
// Called by the admin-console Apply fan-out so siphon-fs picks up
// siphon-api-authored edits without a restart. No body.

#[derive(Serialize)]
struct ReloadResponse {
    status: &'static str,
    path: String,
    summary: siphon_core::overrides::OverridesSummary,
}

async fn overrides_reload(State(state): State<AppState>) -> Response {
    let path = state.overrides_path.as_path();
    let fresh = LiveOverrides::from_path(path);
    let summary = fresh.loaded_overrides.summary();
    match state.live_overrides.write() {
        Ok(mut guard) => {
            *guard = fresh;
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("live_overrides lock poisoned: {e}"),
            );
        }
    };
    info!(
        path = %path.display(),
        disabled = summary.disabled_patterns,
        field_overrides = summary.pattern_overrides,
        custom_categories = summary.custom_categories,
        "overrides reloaded"
    );
    JsonResponse(ReloadResponse {
        status: "reloaded",
        path: path.display().to_string(),
        summary,
    })
    .into_response()
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/scan", post(scan))
        .route("/v1/findings", get(list_findings))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/overrides/reload", post(overrides_reload))
        .with_state(state)
        // 100 MB upload cap. Matches siphon::extractors::extract_text's
        // own per-file limit so a larger payload is rejected at the
        // HTTP edge rather than wasting the extract path. Override via
        // SIPHON_FS_BODY_LIMIT_MB for ad-hoc testing.
        .layer(DefaultBodyLimit::max(body_limit_bytes()))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("SIPHON_FS_BIND").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
    let addr: SocketAddr = bind.parse()?;

    // Load deployable overrides from the path k8s mounts the
    // siphon-overrides ConfigMap into (default /etc/siphon/overrides.json).
    // Missing file → empty (compile-time defaults). Parse error → empty +
    // logged. A failed override file does NOT prevent serving — Phase 3b
    // chooses operational continuity over hard-fail. Phase 6's auto-roll
    // gates on /ready and /ready will gate on a clean parse before then.
    let overrides_path = std::env::var("SIPHON_OVERRIDES_PATH")
        .unwrap_or_else(|_| "/etc/siphon/overrides.json".to_string());
    let overrides = PatternOverrides::from_file_or_empty(&overrides_path);
    let summary = overrides.summary();
    let live_overrides = LiveOverrides::from_doc(overrides);
    let runtime_pattern_count = live_overrides.runtime_patterns.len();
    let regex_override_count = live_overrides.pattern_regex_overrides.len();
    let list_binding_count = live_overrides.list_bindings.len();
    let unique_threshold_count = live_overrides.unique_thresholds.len();

    let pod_id = Arc::new(uuid::Uuid::new_v4().to_string());
    let started_at = Instant::now();
    let started_at_iso = siphon_core::audit::iso8601_now();

    // Optional Postgres pool — siphon-fs connects to the same DB as
    // siphon-api but does NOT run migrations (siphon-api owns the schema).
    let (_db_state, db_pool) = match db::init_optional().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "SIPHON_DATABASE_URL parse failed; refusing to start");
            std::process::exit(1);
        }
    };

    let max_file_bytes = max_file_size_bytes();
    let temp_dir = temp_dir_path();

    let state = AppState {
        findings: Arc::new(FindingsRing::new(FINDINGS_RING_CAP)),
        live_overrides: Arc::new(std::sync::RwLock::new(live_overrides)),
        overrides_path: Arc::new(std::path::PathBuf::from(&overrides_path)),
        pod_id: pod_id.clone(),
        started_at_iso,
        started_at,
        db_pool,
        max_file_bytes,
        temp_dir: temp_dir.clone(),
    };
    let app = build_router(state);

    info!(
        service = POD_NAME,
        version = env!("CARGO_PKG_VERSION"),
        core = siphon_core::VERSION,
        ring_cap = FINDINGS_RING_CAP,
        overrides_path = %overrides_path,
        overrides_disabled = summary.disabled_patterns,
        overrides_field = summary.pattern_overrides,
        overrides_custom_cats = summary.custom_categories,
        overrides_runtime_patterns_compiled = runtime_pattern_count,
        overrides_regex_swaps_compiled = regex_override_count,
        overrides_list_bindings_active = list_binding_count,
        overrides_unique_thresholds = unique_threshold_count,
        max_file_mb = max_file_bytes / (1024 * 1024),
        temp_dir = ?temp_dir,
        bind = %addr,
        "siphon-fs starting"
    );

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "bind failed — another process likely holds this port");
            std::process::exit(1);
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

// Shutdown trigger — completes when EITHER SIGINT (Ctrl-C, dev) or
// SIGTERM (k8s pod termination) arrives. with_graceful_shutdown holds
// new accepts off and waits for in-flight scans to finish before
// returning. The Deployment's terminationGracePeriodSeconds (60s for
// siphon-fs, larger than api because file uploads can be mid-flight
// when the roll starts) caps the wait before SIGKILL.
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
        _ = ctrl_c   => tracing::info!(signal = "SIGINT",  "shutdown signal received, draining"),
        _ = terminate => tracing::info!(signal = "SIGTERM", "shutdown signal received, draining"),
    }
}
