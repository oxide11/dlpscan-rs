//! Database layer — Postgres connection pool + migrations.
//!
//! Optional. siphon-api keeps working without a database; every
//! handler that wants persistence routes through `state.db_pool`
//! which is `Option<Pool>` and degrades gracefully when None.
//!
//! Backed by `tokio-postgres` + `deadpool-postgres`. We don't use
//! sqlx because its umbrella crate carries a hard-coded
//! `links = "sqlite3"` (via sqlx-sqlite) that conflicts with
//! rusqlite's libsqlite3-sys link further down the workspace
//! dep graph.
//!
//! Migrations are bundled at compile time via `include_str!` and
//! applied in name order at startup. A `_schema_migrations` table
//! records what's been run so re-runs are idempotent. Migration
//! failures crash the process so the operator sees the crashloop
//! instead of a half-applied schema.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::time::Duration;
use tokio_postgres::NoTls;

const MAX_POOL_SIZE: usize = 8;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection-state classification surfaced via /v1/db/health.
/// Kept separate from the pool's `Option<Pool>` representation so
/// the smoke endpoint can tell "URL absent" apart from "URL set but
/// pool failed to come up at startup" — both are None at the
/// AppState layer, which had me chasing a phantom config issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolState {
    /// SIPHON_DATABASE_URL was not set in the environment.
    Unconfigured,
    /// URL was set and pool came up successfully.
    Connected,
    /// URL was set but the startup connection failed or timed out.
    StartupFailed,
}

/// Migration files. Each entry is (sequence_id, name, sql_text).
/// Add new files in chronological order; the runner applies them
/// in this order and remembers which ones have run via the
/// `_schema_migrations` bookkeeping table.
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "0001_init", include_str!("../migrations/0001_init.sql")),
    (
        2,
        "0002_findings",
        include_str!("../migrations/0002_findings.sql"),
    ),
];

/// Initialise an optional database pool from the environment.
///
/// Returns `(state, pool)`:
///   * `(Unconfigured, None)` — SIPHON_DATABASE_URL not set.
///   * `(Connected, Some)` — URL set, pool ready, caller should
///     run migrations next.
///   * `(StartupFailed, None)` — URL set but the startup connect
///     attempt failed or timed out. /v1/db/health surfaces this
///     distinct from Unconfigured.
///   * Returns `Err(_)` only on malformed URL — main() exits.
pub async fn init_optional(
) -> Result<(PoolState, Option<Pool>), Box<dyn std::error::Error + Send + Sync>> {
    let Ok(url) = std::env::var("SIPHON_DATABASE_URL") else {
        tracing::info!(
            "SIPHON_DATABASE_URL not set — persistence disabled; findings \
             history and C2 shared state will return empty/in-memory"
        );
        return Ok((PoolState::Unconfigured, None));
    };

    let mut cfg = Config::new();
    cfg.url = Some(url.clone());
    // SIPHON_DATABASE_PASSWORD comes in via a separate env var so
    // the URL stays non-secret in pod env. deadpool's Config has
    // no direct password setter, so we splice it onto the parsed
    // tokio-postgres Config below.
    if let Ok(password) = std::env::var("SIPHON_DATABASE_PASSWORD") {
        cfg.password = Some(password);
    }
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    cfg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: MAX_POOL_SIZE,
        timeouts: deadpool_postgres::Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(5)),
            recycle: Some(Duration::from_secs(2)),
        },
        ..Default::default()
    });

    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;

    // Round-trip a single connection at startup so unreachable
    // Postgres surfaces immediately instead of on first scan.
    match tokio::time::timeout(STARTUP_TIMEOUT, pool.get()).await {
        Ok(Ok(client)) => {
            // Trivial query to confirm the wire is live.
            let _ = client.simple_query("SELECT 1").await;
            tracing::info!(max_pool_size = MAX_POOL_SIZE, "connected to Postgres");
            Ok((PoolState::Connected, Some(pool)))
        }
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                "Postgres connection failed at startup — running without \
                 persistence. Restart the pod once Postgres is reachable."
            );
            Ok((PoolState::StartupFailed, None))
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = STARTUP_TIMEOUT.as_secs(),
                "Postgres connection timed out at startup — running \
                 without persistence."
            );
            Ok((PoolState::StartupFailed, None))
        }
    }
}

/// Apply any pending migrations from the embedded MIGRATIONS list.
/// Tracked in `_schema_migrations(version, name, applied_at)` so
/// re-runs are idempotent.
pub async fn run_migrations(pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;

    // Bookkeeping table — created on first run; idempotent.
    client
        .simple_query(
            "CREATE TABLE IF NOT EXISTS _schema_migrations (\
             version BIGINT PRIMARY KEY, \
             name TEXT NOT NULL, \
             applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        )
        .await?;

    for &(version, name, sql) in MIGRATIONS {
        let already: Option<tokio_postgres::Row> = client
            .query_opt(
                "SELECT version FROM _schema_migrations WHERE version = $1",
                &[&version],
            )
            .await?;
        if already.is_some() {
            tracing::debug!(version, name, "migration already applied — skipping");
            continue;
        }
        tracing::info!(version, name, "applying migration");
        // simple_query runs the whole .sql file (handles multiple
        // statements separated by semicolons). Wrap in a
        // transaction so a mid-file failure doesn't leave the
        // schema half-applied.
        client.simple_query("BEGIN").await?;
        if let Err(e) = client.simple_query(sql).await {
            let _ = client.simple_query("ROLLBACK").await;
            return Err(format!("migration {version} '{name}' failed: {e}").into());
        }
        client
            .execute(
                "INSERT INTO _schema_migrations (version, name) VALUES ($1, $2)",
                &[&version, &name],
            )
            .await?;
        client.simple_query("COMMIT").await?;
    }
    Ok(())
}

/// Persist one completed scan to the `scans` + `findings` tables.
///
/// Called in a background `tokio::spawn` after every POST /scan so
/// DB latency never slows the scan response. If the pool is None
/// (Postgres unconfigured or unreachable at startup) the call is a
/// silent no-op. Individual DB errors are returned to the caller,
/// which logs a warning and discards them — a failed write must
/// never affect the scan response.
///
/// Raw input text is never stored. The caller pre-hashes both the
/// api_key and the input with SHA-256 so db.rs stays self-contained
/// (no crypto dep here).
///
/// `findings` is a slice of `serde_json::Value` objects with the
/// following shape (produced by the scan handler from `Finding`
/// structs):
/// ```json
/// {
///   "category":         "Credit Card Numbers",
///   "sub_category":     "Visa",
///   "confidence":       0.95,
///   "text":             "4111...",
///   "has_context":      true,
///   "span":             [0, 16],
///   "metadata":         {}
/// }
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn persist_scan(
    pool: &Option<Pool>,
    scan_id: uuid::Uuid,
    api_key_hash: &[u8],
    input_hash: &[u8],
    input_length: usize,
    findings: &[serde_json::Value],
    duration_ms: u64,
    action: &str,
    source_pod: Option<&str>,
    scanner_version: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(());
    };

    let client = pool.get().await?;

    let api_key_hash_bytes: Option<&[u8]> = if api_key_hash.is_empty() {
        None
    } else {
        Some(api_key_hash)
    };
    let input_hash_bytes: Option<&[u8]> = if input_hash.is_empty() {
        None
    } else {
        Some(input_hash)
    };
    let input_len_i32 = input_length as i32;
    let finding_count_i32 = findings.len() as i32;
    let duration_ms_i32 = duration_ms as i32;

    client
        .execute(
            "INSERT INTO scans \
             (id, source_pod, scanner_version, api_key_hash, input_hash, \
              input_length, finding_count, duration_ms, action) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &scan_id,
                &source_pod,
                &scanner_version,
                &api_key_hash_bytes,
                &input_hash_bytes,
                &input_len_i32,
                &finding_count_i32,
                &duration_ms_i32,
                &action,
            ],
        )
        .await?;

    for f in findings {
        let category = f.get("category").and_then(|v| v.as_str()).unwrap_or("");
        let sub_category = f.get("sub_category").and_then(|v| v.as_str());
        let confidence = f.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let span_start: Option<i32> = f
            .get("span")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_i64())
            .map(|n| n as i32);
        let span_end: Option<i32> = f
            .get("span")
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_i64())
            .map(|n| n as i32);
        let matched_text = f.get("text").and_then(|v| v.as_str());
        let has_context = f.get("has_context").and_then(|v| v.as_bool());
        let context_required: Option<bool> = None;
        let metadata: Option<serde_json::Value> = f.get("metadata").cloned();

        client
            .execute(
                "INSERT INTO findings \
                 (scan_id, source_pod, scanner_version, api_key_hash, input_hash, \
                  input_length, category, sub_category, confidence, \
                  span_start, span_end, matched_text, has_context, context_required, metadata) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                &[
                    &scan_id,
                    &source_pod,
                    &scanner_version,
                    &api_key_hash_bytes,
                    &input_hash_bytes,
                    &input_len_i32,
                    &category,
                    &sub_category,
                    &confidence,
                    &span_start,
                    &span_end,
                    &matched_text,
                    &has_context,
                    &context_required,
                    &metadata,
                ],
            )
            .await?;
    }

    Ok(())
}
