//! Polygon Siphon launcher — local-dev process manager.
//!
//! Runs as a long-lived daemon on the analyst's workstation. Exposes
//! a small HTTP surface the admin console (siphon-c2) calls to start
//! and stop siphon-api / siphon-fs subprocesses without the analyst
//! dropping to a terminal. Think `tmuxinator` but driven from a
//! browser.
//!
//! Not production-grade and not meant for k8s — the k8s lab already
//! handles lifecycle via Deployments + Phase 6 auto-roll. This is
//! for the before-kind phase (laptop dev, docker-less machine, CI
//! fixture, demo prep).
//!
//! Security model: bound to 127.0.0.1 only; same-machine trust is
//! assumed. Any user with a shell on the machine can already spawn
//! these binaries, so the launcher isn't adding new attack surface.
//! Don't expose it on a routable interface.
//!
//! Phase 8.5a (this file): axum skeleton + /health + stub
//! /v1/manage/list returning an empty array. Process spawn/stop
//! lands in 8.5b; admin-console UI in 8.5c.

use axum::{
    response::Json as JsonResponse,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

const LAUNCHER_NAME: &str = "siphon-launcher";
const DEFAULT_BIND: &str = "127.0.0.1:8090";

// ─── Health ──────────────────────────────────────────────────────
// Mirrors the pod /health shape loosely so the admin console can
// probe the launcher the same way it probes siphon-api / siphon-fs.
// Not all /health fields apply (no pod_type / pod_id here since a
// launcher isn't a detection pod) — kept minimal.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health() -> JsonResponse<HealthResponse> {
    JsonResponse(HealthResponse {
        status: "ok",
        service: LAUNCHER_NAME,
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ─── /v1/manage/list ────────────────────────────────────────────
// Returns the set of processes this launcher currently tracks. For
// 8.5a the list is always empty (no spawn handler yet). 8.5b adds
// an in-memory state map and populates this from it.
#[derive(Serialize)]
struct ManagedProcess {
    // Shape placeholder — real fields arrive in 8.5b. Declared now so
    // the wire is stable from the first ping.
    id: String,
    kind: String,  // "siphon-api" | "siphon-fs"
    pid: u32,
    bind: String,
    started_at: String,
    status: &'static str,
}

#[derive(Serialize)]
struct ListResponse {
    total: usize,
    processes: Vec<ManagedProcess>,
    note: &'static str,
}

async fn list_processes() -> JsonResponse<ListResponse> {
    JsonResponse(ListResponse {
        total: 0,
        processes: Vec::new(),
        note: "process spawn/stop handlers land in Phase 8.5b · list is empty for now",
    })
}

// ─── Placeholder start/stop ─────────────────────────────────────
// 501 until 8.5b. Shape the endpoints now so the admin console can
// be written against a stable surface.
#[derive(Serialize)]
struct NotImplemented {
    error: &'static str,
    phase: &'static str,
}

async fn start_stub() -> (axum::http::StatusCode, JsonResponse<NotImplemented>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        JsonResponse(NotImplemented {
            error: "spawn not wired yet — Phase 8.5b adds tokio::process::Command + PID tracking",
            phase: "8.5b",
        }),
    )
}

async fn stop_stub() -> (axum::http::StatusCode, JsonResponse<NotImplemented>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        JsonResponse(NotImplemented {
            error: "stop not wired yet — Phase 8.5b adds SIGTERM + drain to the tracked child",
            phase: "8.5b",
        }),
    )
}

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/manage/list", get(list_processes))
        .route("/v1/manage/start", post(start_stub))
        .route("/v1/manage/stop", post(stop_stub))
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

    let bind = std::env::var("SIPHON_LAUNCHER_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind.parse()?;

    // Enforce localhost-only for the security model. Binding to
    // 0.0.0.0 from an env var is a footgun — refuse.
    if !addr.ip().is_loopback() {
        eprintln!(
            "siphon-launcher refuses non-loopback bind {addr}: \
             the launcher assumes same-machine trust and has no auth. \
             Set SIPHON_LAUNCHER_BIND to a 127.0.0.1 or ::1 address."
        );
        std::process::exit(2);
    }

    let app = build_router();
    info!(
        service = LAUNCHER_NAME,
        version = env!("CARGO_PKG_VERSION"),
        bind = %addr,
        "siphon-launcher starting (Phase 8.5a — stub only; spawn lands in 8.5b)"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
