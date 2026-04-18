//! Polygon Siphon API — sync HTTP scan service.
//!
//! Exposes `POST /scan` and `POST /guard` endpoints that accept JSON,
//! run the siphon-core scanner, and return findings synchronously.
//!
//! Usage:
//!   siphon-api                     Start on 0.0.0.0:8080
//!   siphon-api --port 9090         Custom port
//!   siphon-api --bind 127.0.0.1    Bind to localhost only

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    version: &'static str,
}

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
    version: &'static str,
    pod: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: state.version,
        pod: "siphon-api",
    })
}

async fn scan(
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorResponse>)> {
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
                error: "text exceeds 10 MB limit".into(),
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("scan failed: {e}"),
            }),
        )
    })?;

    let elapsed = start.elapsed();

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

    Ok(Json(ScanResponse {
        source_pod: "siphon-api",
        request_id,
        findings,
        finding_count: count,
        scan_duration_ms: elapsed.as_millis() as u64,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port = std::env::var("SIPHON_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let bind = std::env::var("SIPHON_BIND").unwrap_or_else(|_| "0.0.0.0".into());

    let state = Arc::new(AppState {
        version: env!("CARGO_PKG_VERSION"),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{bind}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    tracing::info!(
        "Polygon Siphon API v{} listening on {addr}",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!(
        "Loaded {} patterns across {} categories",
        siphon_core::patterns::PATTERNS.len(),
        siphon_core::patterns::categories().len()
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install signal handler");
    tracing::info!("shutdown signal received, draining connections...");
}
