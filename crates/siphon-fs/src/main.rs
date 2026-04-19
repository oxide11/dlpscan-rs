//! Polygon Siphon FS — file-scanner HTTP service.
//!
//! Separate pod from siphon-api so file parsing (PDF, DOCX, archives,
//! OCR, etc.) can scale independently from the text /scan API. Both
//! pods depend on siphon-core for the detection engine, so the regex
//! + keyword + validator stack stays single-source-of-truth.
//!
//! Phase 0b scope (this file):
//!   · GET  /health    — liveness probe
//!   · GET  /ready     — readiness probe (Phase 3 gates on overrides)
//!   · POST /scan      — multipart upload of a single file; bytes
//!                       are decoded as UTF-8 and run through
//!                       siphon-core::scanner::scan_text_with_config.
//!                       PDF/DOCX/archive parsing via siphon-core's
//!                       ingest layer lands in Phase 0c.
//!
//! Graceful shutdown on SIGTERM lands in Phase 5.

use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::net::SocketAddr;
use std::time::Instant;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

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
        service: "siphon-fs",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready() -> JsonResponse<HealthResponse> {
    // Same response as /health until Phase 3 introduces the overrides-
    // loading gate. Keeping endpoints separate now so k8s manifests
    // can target /ready today without refactoring.
    JsonResponse(HealthResponse {
        status: "ready",
        service: "siphon-fs",
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ─── /scan response shape ────────────────────────────────────────
// Shape matches siphon_core::Match fields that serialise cleanly.
// String (not &'static str) because Match owns its fields. Severity
// derivation lives in siphon-api today — siphon-fs stays minimal and
// lets the Phase 2c forward-to-/v1/findings/ingest path decide how
// severities are reconciled.
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
    parsed_as: &'static str,
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
async fn scan(mut multipart: Multipart) -> Response {
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
                    // Phase 0b ignores non-'file' fields. An 'options'
                    // JSON blob (min_confidence, categories, etc.) gets
                    // wired in Phase 0c alongside the ingest layer.
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

    // Phase 0b: UTF-8 text only. Phase 0c swaps to siphon-core's
    // ingest layer which dispatches on mime type (PDF, DOCX, archives,
    // OCR, barcodes).
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return err(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "file bytes are not valid UTF-8 · PDF/DOCX/binary parsing ships in Phase 0c"
                    .to_string(),
            );
        }
    };

    let config = ScanConfig::default();
    let matches = match scan_text_with_config(&text, &config) {
        Ok(m) => m,
        Err(e) => {
            warn!(request_id = %request_id, error = %e, "scan failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan processing failed".to_string(),
            );
        }
    };

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
        parsed_as: "utf8_text",
        findings,
    })
    .into_response()
}

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/scan", post(scan))
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
    let app = build_router();

    info!(
        service = "siphon-fs",
        version = env!("CARGO_PKG_VERSION"),
        core = siphon_core::VERSION,
        bind = %addr,
        "siphon-fs starting"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
