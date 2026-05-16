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
const MIGRATIONS: &[(i64, &str, &str)] =
    &[(1, "0001_init", include_str!("../migrations/0001_init.sql"))];

/// Initialise an optional database pool from the environment.
///
/// Returns `(state, pool)`:
///   * `(Unconfigured, None)` — SIPHON_DATABASE_URL not set.
///   * `(Connected, Some)`    — URL set, pool ready, caller should
///                              run migrations next.
///   * `(StartupFailed, None)` — URL set but the startup connect
///                              attempt failed or timed out. /v1/db/health
///                              surfaces this distinct from Unconfigured.
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
