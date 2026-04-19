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
//! Security model:
//!   · bound to 127.0.0.1 only; same-machine trust assumed
//!   · SIPHON_LAUNCHER_BIND with a non-loopback address exits hard
//!   · binary kind must be on a small whitelist (siphon-api /
//!     siphon-fs) — no arbitrary command execution
//!   · no authentication (anyone with a local shell already has
//!     equivalent power)

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

const LAUNCHER_NAME: &str = "siphon-launcher";
const DEFAULT_BIND: &str = "127.0.0.1:8090";
/// Hard-coded whitelist of spawnable kinds. Keep in sync with the
/// admin-console Settings UI (Phase 8.5c) — any new kind must land
/// here first so the launcher doesn't serve as a general-purpose
/// exec server.
const ALLOWED_KINDS: &[&str] = &["siphon-api", "siphon-fs"];
/// How long to wait for a SIGTERM'd child to drain before sending
/// SIGKILL. Matches the Deployment terminationGracePeriodSeconds in
/// the lab (45s for api, 60s for fs); use the larger one.
const STOP_GRACE_SECS: u64 = 60;

// ─── App state ──────────────────────────────────────────────────
// Arc<Mutex<HashMap<id, TrackedProcess>>> for the in-flight set.
// Intentionally in-memory only: restarting the launcher means
// orphaning any children it was tracking (they keep running; the
// analyst can re-attach to them by killing them directly if needed).
// Persistent state is a future commitment when/if this tool grows
// teeth.

#[derive(Clone)]
struct AppState {
    registry: Arc<Mutex<HashMap<String, TrackedProcess>>>,
    bin_dir: Arc<PathBuf>,
}

struct TrackedProcess {
    id: String,
    kind: String,
    bind: String,
    pid: u32,
    started_at: String,
    // Option so stop() can take() the Child to wait on it without
    // keeping the lock held for the full grace window.
    child: Option<Child>,
}

// ─── Health ──────────────────────────────────────────────────────
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    bin_dir: String,
}

async fn health(State(state): State<AppState>) -> JsonResponse<HealthResponse> {
    JsonResponse(HealthResponse {
        status: "ok",
        service: LAUNCHER_NAME,
        version: env!("CARGO_PKG_VERSION"),
        bin_dir: state.bin_dir.display().to_string(),
    })
}

// ─── List ────────────────────────────────────────────────────────
#[derive(Serialize)]
struct ManagedProcess {
    id: String,
    kind: String,
    pid: u32,
    bind: String,
    started_at: String,
    /// "running" | "exited" — re-checked on every /list by calling
    /// try_wait() on the tracked Child. `exited` entries get pruned
    /// out of the registry so the list stays tidy.
    status: &'static str,
}

#[derive(Serialize)]
struct ListResponse {
    total: usize,
    processes: Vec<ManagedProcess>,
}

async fn list_processes(State(state): State<AppState>) -> JsonResponse<ListResponse> {
    let mut guard = state.registry.lock().await;
    let mut processes = Vec::new();
    let mut to_prune: Vec<String> = Vec::new();

    for (id, tp) in guard.iter_mut() {
        let status = match tp.child.as_mut() {
            Some(c) => match c.try_wait() {
                Ok(Some(_)) => "exited",
                Ok(None) => "running",
                Err(_) => "exited", // kernel says the pid is gone
            },
            None => "exited",
        };
        processes.push(ManagedProcess {
            id: tp.id.clone(),
            kind: tp.kind.clone(),
            pid: tp.pid,
            bind: tp.bind.clone(),
            started_at: tp.started_at.clone(),
            status,
        });
        if status == "exited" {
            to_prune.push(id.clone());
        }
    }
    for id in to_prune {
        guard.remove(&id);
    }
    JsonResponse(ListResponse {
        total: processes.len(),
        processes,
    })
}

// ─── Start ───────────────────────────────────────────────────────
#[derive(Deserialize)]
struct StartRequest {
    /// Which binary kind to spawn. Must be on ALLOWED_KINDS.
    kind: String,
    /// Bind address for the spawned pod. Defaults to a sensible
    /// sibling port per kind if omitted.
    bind: Option<String>,
    /// Extra environment variables forwarded to the child. The
    /// launcher already sets the kind-appropriate *_BIND / *_PORT
    /// env vars; this field is for overrides-path, log level, etc.
    env: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct StartResponse {
    id: String,
    kind: String,
    pid: u32,
    bind: String,
    started_at: String,
    binary: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (
        code,
        JsonResponse(ErrorBody {
            error: msg.into(),
        }),
    )
        .into_response()
}

async fn start_process(State(state): State<AppState>, Json(req): Json<StartRequest>) -> Response {
    if !ALLOWED_KINDS.contains(&req.kind.as_str()) {
        return err(
            StatusCode::BAD_REQUEST,
            format!(
                "kind must be one of {:?}; got {:?}",
                ALLOWED_KINDS, req.kind
            ),
        );
    }

    let bin_path = state.bin_dir.join(&req.kind);
    if !bin_path.exists() {
        return err(
            StatusCode::NOT_FOUND,
            format!(
                "binary not found: {} — set SIPHON_BIN_DIR to the directory holding siphon-api / siphon-fs",
                bin_path.display()
            ),
        );
    }

    // Default bind per kind — analyst can override in the request.
    let default_bind = match req.kind.as_str() {
        "siphon-api" => "127.0.0.1:8080",
        "siphon-fs" => "127.0.0.1:8081",
        _ => "127.0.0.1:8080",
    };
    let bind = req.bind.unwrap_or_else(|| default_bind.to_string());

    let mut cmd = Command::new(&bin_path);
    // Wire bind into the kind's env convention. siphon-api uses
    // SIPHON_BIND / SIPHON_PORT; siphon-fs uses the single
    // SIPHON_FS_BIND.
    match req.kind.as_str() {
        "siphon-api" => {
            if let Some((host, port)) = bind.rsplit_once(':') {
                cmd.env("SIPHON_BIND", host).env("SIPHON_PORT", port);
            }
        }
        "siphon-fs" => {
            cmd.env("SIPHON_FS_BIND", &bind);
        }
        _ => {}
    }
    if let Some(extra) = req.env {
        for (k, v) in extra {
            cmd.env(k, v);
        }
    }
    // Keep stdio inherited so the analyst sees child output in the
    // terminal running the launcher. `kill_on_drop(true)` so if the
    // launcher itself exits unexpectedly, the children don't
    // survive — otherwise a crash would orphan them.
    cmd.kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn failed: {e}"),
            );
        }
    };
    let Some(pid) = child.id() else {
        // Unlikely — Child::id() returns None only after wait has
        // been called, which we haven't done yet.
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "spawn succeeded but PID unavailable".to_string(),
        );
    };

    let short = uuid::Uuid::new_v4().to_string();
    let id = format!("{}-{}", req.kind, &short[..8]);
    let started_at = siphon_core::audit::iso8601_now();

    let tp = TrackedProcess {
        id: id.clone(),
        kind: req.kind.clone(),
        bind: bind.clone(),
        pid,
        started_at: started_at.clone(),
        child: Some(child),
    };
    state.registry.lock().await.insert(id.clone(), tp);

    info!(
        id = %id,
        kind = %req.kind,
        pid,
        bind = %bind,
        binary = %bin_path.display(),
        "spawned"
    );

    JsonResponse(StartResponse {
        id,
        kind: req.kind,
        pid,
        bind,
        started_at,
        binary: bin_path.display().to_string(),
    })
    .into_response()
}

// ─── Stop ────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct StopRequest {
    /// Process id returned by /start.
    id: String,
    /// If true, skip the SIGTERM grace window and go straight to
    /// SIGKILL. Default false — respects the Phase-5 drain.
    #[serde(default)]
    force: bool,
}

#[derive(Serialize)]
struct StopResponse {
    id: String,
    pid: u32,
    signal: &'static str,   // "SIGTERM" | "SIGKILL"
    graceful: bool,
    waited_ms: u128,
}

async fn stop_process(State(state): State<AppState>, Json(req): Json<StopRequest>) -> Response {
    // Take the Child out of the registry so we can wait on it
    // without holding the registry lock for the full grace window.
    let (child, pid) = {
        let mut guard = state.registry.lock().await;
        let Some(tp) = guard.get_mut(&req.id) else {
            return err(
                StatusCode::NOT_FOUND,
                format!("no process with id {:?}", req.id),
            );
        };
        (tp.child.take(), tp.pid)
    };

    let Some(mut child) = child else {
        // Already taken — previous stop call in flight or child
        // died on its own. Prune the entry.
        state.registry.lock().await.remove(&req.id);
        return err(
            StatusCode::CONFLICT,
            format!(
                "process {:?} has no live child — already stopping or exited",
                req.id
            ),
        );
    };

    let t0 = std::time::Instant::now();
    let (signal, graceful) = if req.force {
        // Caller explicitly asked for SIGKILL. tokio's kill()
        // sends SIGKILL on Unix / TerminateProcess on Windows.
        let _ = child.kill().await;
        let _ = child.wait().await;
        ("SIGKILL", false)
    } else {
        // SIGTERM first, then SIGKILL fallback after STOP_GRACE_SECS.
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            // No SIGTERM on Windows — fall straight to kill().
            let _ = child.kill().await;
        }

        let drained = tokio::time::timeout(
            std::time::Duration::from_secs(STOP_GRACE_SECS),
            child.wait(),
        )
        .await
        .is_ok();
        if drained {
            ("SIGTERM", true)
        } else {
            warn!(
                id = %req.id, pid,
                grace_secs = STOP_GRACE_SECS,
                "grace window expired — escalating to SIGKILL"
            );
            let _ = child.kill().await;
            let _ = child.wait().await;
            ("SIGKILL", false)
        }
    };
    let waited_ms = t0.elapsed().as_millis();

    // Prune the registry entry regardless of exit status.
    state.registry.lock().await.remove(&req.id);

    info!(id = %req.id, pid, signal, graceful, waited_ms, "stopped");

    JsonResponse(StopResponse {
        id: req.id,
        pid,
        signal,
        graceful,
        waited_ms,
    })
    .into_response()
}

// ─── Router ──────────────────────────────────────────────────────
fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/manage/list", get(list_processes))
        .route("/v1/manage/start", post(start_process))
        .route("/v1/manage/stop", post(stop_process))
        .with_state(state)
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

    if !addr.ip().is_loopback() {
        eprintln!(
            "siphon-launcher refuses non-loopback bind {addr}: \
             the launcher assumes same-machine trust and has no auth. \
             Set SIPHON_LAUNCHER_BIND to a 127.0.0.1 or ::1 address."
        );
        std::process::exit(2);
    }

    // Resolve the directory holding spawnable binaries. Precedence:
    //   1. SIPHON_BIN_DIR env var
    //   2. directory of the launcher binary itself (common when
    //      `cargo build` puts everything in target/{debug,release})
    //   3. "." — last resort, will probably fail at first /start
    let bin_dir = std::env::var("SIPHON_BIN_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        })
        .unwrap_or_else(|| PathBuf::from("."));

    let state = AppState {
        registry: Arc::new(Mutex::new(HashMap::new())),
        bin_dir: Arc::new(bin_dir.clone()),
    };
    let app = build_router(state);

    info!(
        service = LAUNCHER_NAME,
        version = env!("CARGO_PKG_VERSION"),
        bind = %addr,
        bin_dir = %bin_dir.display(),
        grace_secs = STOP_GRACE_SECS,
        allowed_kinds = ?ALLOWED_KINDS,
        "siphon-launcher starting"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// Pull axum Json for the handlers. Declared at the bottom so it
// doesn't clash with axum::response::Json (used for owned
// responses) earlier.
use axum::Json;
