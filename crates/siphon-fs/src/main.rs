//! Polygon Siphon FS — file-scanner HTTP service.
//!
//! Separate pod from siphon-api so file parsing (PDF, DOCX, archives,
//! OCR, etc.) can scale independently from the text /scan API. Both
//! pods depend on siphon-core for the detection engine, so the regex
//! + keyword + validator stack stays single-source-of-truth.
//!
//! Phase 0a scope (this binary):
//!   · axum HTTP server on 0.0.0.0:8081 (configurable via SIPHON_FS_BIND)
//!   · GET  /health    — liveness probe (returns immediately)
//!   · GET  /ready     — readiness probe (same as health for now;
//!                       Phase 3 gates this on overrides parsing clean)
//!   · POST /scan      — stub that echoes the request shape. Wired to
//!                       siphon-core's scanner in Phase 0b.
//!
//! Graceful shutdown on SIGTERM lands in Phase 5 — required before
//! rolling-restart can be safe.

use axum::{
    extract::DefaultBodyLimit,
    response::Json as JsonResponse,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

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
    // Same response as /health until Phase 3 introduces overrides-
    // loading gate. Keeping them separate now so readiness probes in
    // k8s manifests can already target /ready without refactoring.
    JsonResponse(HealthResponse {
        status: "ready",
        service: "siphon-fs",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct ScanStub {
    status: &'static str,
    note: &'static str,
    core_version: &'static str,
}

async fn scan_stub() -> JsonResponse<ScanStub> {
    JsonResponse(ScanStub {
        status: "not_implemented",
        note: "multipart file ingest + detection wiring ships in Phase 0b",
        core_version: siphon_core::VERSION,
    })
}

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/scan", post(scan_stub))
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
