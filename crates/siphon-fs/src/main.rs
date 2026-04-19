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
use siphon_core::audit::iso8601_now;
use siphon_core::findings_ring::{
    filter_findings, severity_for, FindingRecord, FindingsRing,
};
use siphon_core::overrides::{PatternOverride, PatternOverrides};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

const POD_NAME: &str = "siphon-fs";
const FINDINGS_RING_CAP: usize = 500;

// ─── shared app state ────────────────────────────────────────────
// FindingsRing is owned by this pod — each siphon-fs replica keeps
// its own local ring. Multi-replica convergence (e.g. gossiping
// findings across replicas) is beyond the Phase 0 lab; the admin
// console queries the Service IP which load-balances across replicas.
//
// `disabled_patterns` is the pre-computed HashSet from the loaded
// PatternOverrides file. Built once at startup and shared via Arc
// across every scan request. A k8s rolling restart (Phase 6) is what
// picks up overrides edits — no live reload here.
#[derive(Clone)]
struct AppState {
    findings: Arc<FindingsRing>,
    disabled_patterns: Arc<HashSet<(String, String)>>,
    /// Pre-computed (category, sub_category) → PatternOverride map
    /// from PatternOverrides::override_lookup(). Scanner consults
    /// this at scoring + context-gating time. Phase 3c honours
    /// specificity + context_required; regex/keywords/proximity are
    /// loaded but not yet applied (Phase 3d).
    pattern_field_overrides: Arc<HashMap<(String, String), PatternOverride>>,
}

// ─── health + readiness ──────────────────────────────────────────
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health() -> JsonResponse<HealthResponse> {
    JsonResponse(HealthResponse {
        status: "ok",
        service: POD_NAME,
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready() -> JsonResponse<HealthResponse> {
    // Same response as /health until Phase 3 introduces the overrides-
    // loading gate. Keeping endpoints separate now so k8s manifests
    // can target /ready today without refactoring.
    JsonResponse(HealthResponse {
        status: "ready",
        service: POD_NAME,
        version: env!("CARGO_PKG_VERSION"),
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

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();
                if name == "file" {
                    filename = field.file_name().map(|s| s.to_string());
                    content_type = field.content_type().map(|s| s.to_string());
                    match field.bytes().await {
                        Ok(b) => file_bytes = Some(b.to_vec()),
                        Err(e) => {
                            return err(
                                StatusCode::BAD_REQUEST,
                                format!("failed to read file field: {e}"),
                            );
                        }
                    }
                } else {
                    // 'options' JSON (min_confidence, categories, etc.) wiring
                    // is a post-Phase-0 follow-up; for now drain the field.
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

    let Some(bytes) = file_bytes else {
        return err(
            StatusCode::BAD_REQUEST,
            "missing 'file' multipart field".to_string(),
        );
    };
    let file_len = bytes.len();

    // Write the multipart bytes to a temp file so siphon's extractor
    // registry can dispatch on extension. Unknown extensions fall
    // through to plain-text extraction.
    let suffix = filename
        .as_deref()
        .and_then(|f| std::path::Path::new(f).extension())
        .and_then(|s| s.to_str())
        .map(|s| format!(".{s}"))
        .unwrap_or_else(|| ".bin".to_string());

    let mut tmp = match tempfile::Builder::new()
        .prefix("siphon-fs-")
        .suffix(&suffix)
        .tempfile()
    {
        Ok(t) => t,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("tempfile create failed: {e}"),
            );
        }
    };
    if let Err(e) = std::io::Write::write_all(&mut tmp, &bytes) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("tempfile write failed: {e}"),
        );
    }
    let tmp_path = tmp.path().to_string_lossy().into_owned();

    // siphon's extractor registry covers text, RTF, EML, PDF, Office
    // (xlsx/docx/pptx), archives (zip/7z/rar/tar), data formats
    // (parquet/csv/sqlite), barcodes, and falls back to plain-text
    // for anything unrecognised. 100MB-per-file / 500MB-per-archive caps.
    let extract = match siphon::extractors::extract_text(&tmp_path) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("extraction failed: {e}"),
            );
        }
    };

    let config = ScanConfig {
        disabled_patterns: Some(state.disabled_patterns.clone()),
        pattern_field_overrides: Some(state.pattern_field_overrides.clone()),
        ..Default::default()
    };
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
        })
        .collect();

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    info!(
        request_id = %request_id,
        filename = %filename.clone().unwrap_or_else(|| "<none>".into()),
        bytes = file_len,
        parsed_as = %extract.format,
        findings = findings.len(),
        duration_ms = %format!("{duration_ms:.2}"),
        "scan ok"
    );

    JsonResponse(ScanResponse {
        request_id,
        filename,
        content_type,
        bytes: file_len,
        duration_ms,
        parsed_as: extract.format,
        warnings: extract.warnings,
        findings,
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

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/scan", post(scan))
        .route("/v1/findings", get(list_findings))
        .with_state(state)
        // 64MB upload cap — overridable once we decide on real limits.
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
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
    let disabled_patterns = Arc::new(overrides.disabled_set());
    let pattern_field_overrides = Arc::new(overrides.override_lookup());

    let state = AppState {
        findings: Arc::new(FindingsRing::new(FINDINGS_RING_CAP)),
        disabled_patterns,
        pattern_field_overrides,
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
        bind = %addr,
        "siphon-fs starting"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
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
