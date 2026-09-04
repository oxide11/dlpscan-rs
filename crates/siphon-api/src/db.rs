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

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime, SslMode};
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
    (
        3,
        "0003_file_scans",
        include_str!("../migrations/0003_file_scans.sql"),
    ),
    (
        4,
        "0004_retention",
        include_str!("../migrations/0004_retention.sql"),
    ),
    (5, "0005_edm", include_str!("../migrations/0005_edm.sql")),
    (6, "0006_lsh", include_str!("../migrations/0006_lsh.sql")),
    (
        7,
        "0007_evadex",
        include_str!("../migrations/0007_evadex.sql"),
    ),
    (
        8,
        "0008_tenant_id",
        include_str!("../migrations/0008_tenant_id.sql"),
    ),
    (
        9,
        "0009_scan_rollup",
        include_str!("../migrations/0009_scan_rollup.sql"),
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

    let pool = match build_tls()? {
        MaybeTls::Plain => cfg.create_pool(Some(Runtime::Tokio1), NoTls)?,
        MaybeTls::Tls(c) => {
            // Supplying a TLS connector is not by itself enough to get an
            // encrypted link. tokio-postgres defaults to `SslMode::Prefer`,
            // which negotiates TLS and then *silently continues in clear
            // text* if the server declines — so a stripped or misconfigured
            // server downgrades us without a word, which is precisely the
            // exposure `require` is supposed to close. deadpool applies this
            // field after parsing the URL, so it also overrides an
            // `sslmode=` the connection string may carry.
            cfg.ssl_mode = Some(SslMode::Require);
            cfg.create_pool(Some(Runtime::Tokio1), *c)?
        }
    };

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

/// Delete findings and scans older than `retention_days`.
///
/// Calls the `prune_findings` PL/pgSQL function installed by migration
/// 0004. Returns `(scans_deleted, findings_deleted)`. No-ops silently
/// when the pool is `None` (Postgres unconfigured or unreachable at
/// startup).
pub async fn prune_old_findings(
    pool: &Option<Pool>,
    retention_days: u32,
) -> Result<(i64, i64), Box<dyn std::error::Error + Send + Sync>> {
    let pool = match pool {
        Some(p) => p,
        None => return Ok((0, 0)),
    };

    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT * FROM prune_findings($1)",
            &[&(retention_days as i32)],
        )
        .await?;

    if rows.is_empty() {
        return Ok((0, 0));
    }
    let scans_deleted: i64 = rows[0].get(0);
    let findings_deleted: i64 = rows[0].get(1);
    Ok((scans_deleted, findings_deleted))
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
    file_name: Option<&str>,
    file_hash: Option<&[u8]>,
    mime_type: Option<&str>,
    tenant_id: Option<&str>,
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

    // Deduplication: skip if we already stored a scan with the same input_hash
    // within the last 60 seconds (prevents double-writes from client retries).
    if !input_hash.is_empty() {
        let existing = client
            .query_opt(
                "SELECT id FROM scans \
                 WHERE input_hash = $1 \
                 AND created_at > NOW() - INTERVAL '60 seconds' \
                 LIMIT 1",
                &[&input_hash],
            )
            .await?;
        if existing.is_some() {
            tracing::debug!("skipping duplicate scan (same input_hash within 60s)");
            return Ok(());
        }
    }

    client
        .execute(
            "INSERT INTO scans \
             (id, source_pod, scanner_version, api_key_hash, input_hash, \
              input_length, finding_count, duration_ms, action, \
              file_name, file_hash, mime_type, tenant_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
                &file_name,
                &file_hash,
                &mime_type,
                &tenant_id,
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
                  span_start, span_end, matched_text, has_context, context_required, \
                  metadata, tenant_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
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
                    &tenant_id,
                ],
            )
            .await?;
    }

    Ok(())
}

/// Persist one EDM (Exact Data Match) query event to the `edm_queries` table.
///
/// Called non-blockingly via `tokio::spawn` after each scan that ran an EDM
/// lookup, regardless of whether it matched. Silently no-ops when the pool
/// is None.
pub async fn persist_edm_query(
    pool: &Option<Pool>,
    matched: bool,
    category: Option<&str>,
    confidence: Option<f32>,
    api_key_hash: &[u8],
    source_pod: Option<&str>,
    duration_ms: u64,
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
    let duration_ms_i32 = duration_ms as i32;

    client
        .execute(
            "INSERT INTO edm_queries \
             (matched, category, confidence, api_key_hash, source_pod, duration_ms) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &matched,
                &category,
                &confidence,
                &api_key_hash_bytes,
                &source_pod,
                &duration_ms_i32,
            ],
        )
        .await?;

    Ok(())
}

/// Persist one LSH (document similarity) query event to the `lsh_queries` table.
///
/// Called non-blockingly via `tokio::spawn` after each scan that ran an LSH
/// lookup, regardless of whether it matched. Silently no-ops when the pool
/// is None.
pub async fn persist_lsh_query(
    pool: &Option<Pool>,
    query_hash: &[u8],
    query_length: usize,
    matched: bool,
    matched_doc_id: Option<&str>,
    similarity: Option<f32>,
    api_key_hash: &[u8],
    source_pod: Option<&str>,
    duration_ms: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(());
    };

    let client = pool.get().await?;
    let query_hash_bytes: Option<&[u8]> = if query_hash.is_empty() {
        None
    } else {
        Some(query_hash)
    };
    let api_key_hash_bytes: Option<&[u8]> = if api_key_hash.is_empty() {
        None
    } else {
        Some(api_key_hash)
    };
    let query_length_i32 = query_length as i32;
    let duration_ms_i32 = duration_ms as i32;

    client
        .execute(
            "INSERT INTO lsh_queries \
             (query_hash, query_length, matched, matched_doc_id, similarity, \
              api_key_hash, source_pod, duration_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &query_hash_bytes,
                &query_length_i32,
                &matched,
                &matched_doc_id,
                &similarity,
                &api_key_hash_bytes,
                &source_pod,
                &duration_ms_i32,
            ],
        )
        .await?;

    Ok(())
}

/// Persist one LSH vault document registration to the `lsh_registrations` table.
///
/// Called when a document is registered into a vault. Silently no-ops when
/// the pool is None.
pub async fn persist_lsh_registration(
    pool: &Option<Pool>,
    document_id: &str,
    document_hash: &[u8],
    document_length: usize,
    api_key_hash: &[u8],
    source_pod: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(());
    };

    let client = pool.get().await?;
    let document_hash_bytes: Option<&[u8]> = if document_hash.is_empty() {
        None
    } else {
        Some(document_hash)
    };
    let api_key_hash_bytes: Option<&[u8]> = if api_key_hash.is_empty() {
        None
    } else {
        Some(api_key_hash)
    };
    let document_length_i32 = document_length as i32;

    client
        .execute(
            "INSERT INTO lsh_registrations \
             (document_id, document_hash, document_length, api_key_hash, source_pod, \
              scanner_version) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &document_id,
                &document_hash_bytes,
                &document_length_i32,
                &api_key_hash_bytes,
                &source_pod,
                &env!("CARGO_PKG_VERSION"),
            ],
        )
        .await?;

    Ok(())
}

/// Persist a completed evadex adversarial run and up to 2 000 individual test
/// findings to the `evadex_runs` + `evadex_findings` tables.
///
/// The run row is inserted with ON CONFLICT DO NOTHING so re-pushing the same
/// run_id is idempotent (the bridge may retry on transient failures). Findings
/// are only inserted for new runs — they are silently skipped when the run_id
/// already exists. Silently no-ops when the pool is None.
///
/// `findings` is a slice of raw evadex result items:
/// ```json
/// {
///   "payload":  { "category": "credit_card", "value": "...", "label": "..." },
///   "variant":  { "technique": "morse_code", "value": "...", ... },
///   "detected": true,
///   "confidence": 0.95
/// }
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn persist_evadex_run(
    pool: &Option<Pool>,
    run_id: &str,
    scanner_label: Option<&str>,
    tier: Option<&str>,
    evasion_mode: Option<&str>,
    strategy: Option<&str>,
    total_variants: Option<i32>,
    detected: Option<i32>,
    bypassed: Option<i32>,
    detection_rate: Option<f32>,
    duration_s: Option<f32>,
    evadex_version: Option<&str>,
    siphon_version: Option<&str>,
    findings: &[serde_json::Value],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(());
    };

    let client = pool.get().await?;

    // Insert the run summary. ON CONFLICT makes the push idempotent.
    let inserted = client
        .execute(
            "INSERT INTO evadex_runs \
             (run_id, scanner_label, tier, evasion_mode, strategy, \
              total_variants, detected, bypassed, detection_rate, \
              duration_s, evadex_version, siphon_version) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             ON CONFLICT (run_id) DO NOTHING",
            &[
                &run_id,
                &scanner_label,
                &tier,
                &evasion_mode,
                &strategy,
                &total_variants,
                &detected,
                &bypassed,
                &detection_rate,
                &duration_s,
                &evadex_version,
                &siphon_version,
            ],
        )
        .await?;

    // Skip findings if the run already existed (inserted == 0).
    if inserted == 0 {
        return Ok(());
    }

    // Insert up to 2 000 individual test findings.
    for f in findings.iter().take(2000) {
        let category = f
            .get("payload")
            .and_then(|p| p.get("category"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let technique = f
            .get("variant")
            .and_then(|v| v.get("technique"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        // Redact before persisting: store only a structural prefix so
        // real PANs/SSNs don't land in the evadex_findings table in
        // clear text. First 4 chars + **** preserves enough structure
        // for deduplication without retaining the sensitive payload.
        let redacted_variant: Option<String> = f
            .get("variant")
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .map(|v| {
                let prefix: String = v.chars().take(4).collect();
                if prefix.len() < v.chars().count() {
                    format!("{}****", prefix)
                } else {
                    "****".to_string()
                }
            });
        let variant_value: Option<&str> = redacted_variant.as_deref();
        let det: bool = f.get("detected").and_then(|v| v.as_bool()).unwrap_or(false);
        let confidence: Option<f32> = f
            .get("confidence")
            .and_then(|v| v.as_f64())
            .map(|n| n as f32);

        client
            .execute(
                "INSERT INTO evadex_findings \
                 (run_id, category, technique, variant_value, detected, confidence) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
                &[
                    &run_id,
                    &category,
                    &technique,
                    &variant_value,
                    &det,
                    &confidence,
                ],
            )
            .await?;
    }

    Ok(())
}

/// Persist one EDM vault registration to the `edm_registrations` table.
///
/// Called when an EDM vault is registered via the scan endpoint (as part of
/// the ScanConfig). Silently no-ops when the pool is None.
pub async fn persist_edm_registration(
    pool: &Option<Pool>,
    category: &str,
    record_count: i32,
    api_key_hash: &[u8],
    source_pod: Option<&str>,
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

    client
        .execute(
            "INSERT INTO edm_registrations \
             (category, record_count, api_key_hash, source_pod) \
             VALUES ($1, $2, $3, $4)",
            &[&category, &record_count, &api_key_hash_bytes, &source_pod],
        )
        .await?;

    Ok(())
}

/// Build the TLS connector for Postgres.
///
/// Findings rows carry the sensitive data this product exists to detect —
/// matched card numbers, national IDs, credentials — so the link to Postgres
/// carried them in clear text on `NoTls`. In-cluster with a NetworkPolicy that
/// is a narrower exposure than an open port, but "narrower" is not "none": a
/// compromised node, a sniffing sidecar, or a mesh misconfiguration all read
/// it.
///
/// Controlled by `SIPHON_DATABASE_TLS`:
///
/// * `disable` — plaintext. The historical behaviour, and still right when a
///   service mesh already provides mTLS on this hop (the chart can inject
///   linkerd via `global.linkerd.enabled`, off by default), or for a loopback
///   Postgres in local development. The bundled chart Postgres serves no
///   certificate, so the chart sets this explicitly rather than inheriting
///   the `require` default.
/// * `require` *(default)* — TLS with the platform root store, plus any extra
///   CA in `SIPHON_DATABASE_CA_FILE` for the self-signed certificate an
///   in-cluster Postgres usually presents.
///
/// The default changed to `require` deliberately. A deployment that silently
/// sends other people's identifiers unencrypted is the wrong thing to get by
/// accident; one that fails to connect is noticed and fixed.
fn build_tls() -> Result<MaybeTls, String> {
    let mode = std::env::var("SIPHON_DATABASE_TLS").unwrap_or_else(|_| "require".into());
    match mode.trim().to_ascii_lowercase().as_str() {
        "disable" | "off" | "false" => {
            tracing::warn!(
                "SIPHON_DATABASE_TLS=disable — the Postgres link is unencrypted. \
                 Findings rows contain the sensitive data this scanner detects; \
                 only do this when a service mesh secures the hop or Postgres is \
                 on loopback."
            );
            Ok(MaybeTls::Plain)
        }
        "require" | "on" | "true" => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            if let Ok(path) = std::env::var("SIPHON_DATABASE_CA_FILE") {
                let pem = std::fs::read(&path)
                    .map_err(|e| format!("reading SIPHON_DATABASE_CA_FILE {path}: {e}"))?;
                let mut added = 0usize;
                for cert in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
                    roots
                        .add(cert)
                        .map_err(|e| format!("adding CA from {path}: {e}"))?;
                    added += 1;
                }
                if added == 0 {
                    return Err(format!("no certificates found in {path}"));
                }
                tracing::info!(path, added, "loaded extra Postgres CA certificates");
            }

            // rustls 0.23 requires the provider to be named when it cannot
            // infer one from features alone. Building the config with an
            // explicit provider is better than installing a process-wide
            // default: siphon-api also drives rustls for its own TLS listener,
            // and a global install couples two unrelated call sites through
            // hidden state. Without this the connector panics at first use —
            // "Could not automatically determine the process-level
            // CryptoProvider".
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("configuring Postgres TLS: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            tracing::info!("Postgres TLS enabled");
            Ok(MaybeTls::Tls(Box::new(
                tokio_postgres_rustls::MakeRustlsConnect::new(config),
            )))
        }
        other => Err(format!(
            "SIPHON_DATABASE_TLS={other:?} is not recognised (expected 'require' or 'disable')"
        )),
    }
}

/// Either connector, resolved at startup. Boxed because the rustls variant is
/// substantially larger than the unit-sized `NoTls`.
enum MaybeTls {
    Plain,
    Tls(Box<tokio_postgres_rustls::MakeRustlsConnect>),
}

// ---------------------------------------------------------------------------
// Scan rollup — aggregate counters for all scanned traffic
// ---------------------------------------------------------------------------

/// One accumulator bucket, keyed by (hour, tenant, channel).
///
/// Counts are kept in memory and flushed periodically rather than written per
/// scan. At mail-gateway volume a row per scan is the difference between a
/// table that grows with time and one that grows with traffic; see
/// `migrations/0009_scan_rollup.sql`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupCounts {
    pub scans_total: u64,
    pub scans_with_findings: u64,
    pub findings_total: u64,
    pub bytes_scanned: u64,
    pub duration_ms_sum: u64,
    pub oversize_skipped: u64,
    pub scan_errors: u64,
}

impl RollupCounts {
    fn merge(&mut self, other: &RollupCounts) {
        self.scans_total += other.scans_total;
        self.scans_with_findings += other.scans_with_findings;
        self.findings_total += other.findings_total;
        self.bytes_scanned += other.bytes_scanned;
        self.duration_ms_sum += other.duration_ms_sum;
        self.oversize_skipped += other.oversize_skipped;
        self.scan_errors += other.scan_errors;
    }

    fn is_empty(&self) -> bool {
        *self == RollupCounts::default()
    }
}

/// Bucket key. `tenant_id` is an empty string rather than None so it matches
/// the table's NOT NULL primary-key column — see the migration for why NULL
/// would break aggregation.
pub type RollupKey = (chrono::DateTime<chrono::Utc>, String, String);

/// In-process accumulator, flushed to `scan_rollup` on an interval.
///
/// A `Mutex<HashMap>` rather than per-field atomics: the unit of work is a
/// whole bucket, and holding the lock for a handful of integer adds is far
/// cheaper than the scan that produced them. Contention here is not close to
/// being the bottleneck at any volume the scanner itself can sustain.
#[derive(Default)]
pub struct RollupAccumulator {
    buckets: std::sync::Mutex<std::collections::HashMap<RollupKey, RollupCounts>>,
}

impl RollupAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one scan's worth of counts. Cheap and infallible: this sits on
    /// the request path, so it must never block on I/O or fail a scan.
    pub fn record(&self, tenant_id: Option<&str>, channel: &str, counts: RollupCounts) {
        let bucket_hour = truncate_to_hour(chrono::Utc::now());
        let key = (
            bucket_hour,
            tenant_id.unwrap_or("").to_string(),
            channel.to_string(),
        );
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.entry(key).or_default().merge(&counts);
    }

    /// Remove and return everything accumulated so far.
    ///
    /// Taking the buckets out under the lock means a concurrent `record` lands
    /// in a fresh bucket rather than being lost to the flush, and the lock is
    /// not held across the database round trip.
    fn drain(&self) -> Vec<(RollupKey, RollupCounts)> {
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *guard).into_iter().collect()
    }

    /// Put drained counts back after a failed flush, merging with anything
    /// recorded in the meantime, so a database blip costs latency rather than
    /// data. Buckets are additive, so re-merging is exact, not approximate.
    fn restore(&self, drained: Vec<(RollupKey, RollupCounts)>) {
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (key, counts) in drained {
            guard.entry(key).or_default().merge(&counts);
        }
    }
}

fn truncate_to_hour(ts: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::{Timelike, Utc};
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or_else(|| {
            // with_* only fails on values out of range, which 0 never is;
            // fall back rather than panic on the request path.
            tracing::warn!("failed to truncate timestamp to hour; using raw value");
            Utc::now()
        })
}

/// Flush accumulated counters to `scan_rollup`.
///
/// Writes are additive UPSERTs (`SET col = scan_rollup.col + EXCLUDED.col`),
/// so every pod flushes independently and the totals sum without coordination
/// — no leader, no partitioning of the counter space, and a pod that misses a
/// flush simply contributes late rather than double-counting.
pub async fn flush_rollup(
    pool: &Option<Pool>,
    acc: &RollupAccumulator,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        // No database configured: drop the counts rather than growing the map
        // without bound.
        let _ = acc.drain();
        return Ok(0);
    };

    let drained = acc.drain();
    if drained.is_empty() {
        return Ok(0);
    }

    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            acc.restore(drained);
            return Err(Box::new(e));
        }
    };

    let mut written = 0usize;
    for (key, counts) in &drained {
        if counts.is_empty() {
            continue;
        }
        let (bucket_hour, tenant_id, channel) = key;
        let res = client
            .execute(
                "INSERT INTO scan_rollup \
                 (bucket_hour, tenant_id, channel, scans_total, scans_with_findings, \
                  findings_total, bytes_scanned, duration_ms_sum, oversize_skipped, scan_errors) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (bucket_hour, tenant_id, channel) DO UPDATE SET \
                   scans_total         = scan_rollup.scans_total         + EXCLUDED.scans_total, \
                   scans_with_findings = scan_rollup.scans_with_findings + EXCLUDED.scans_with_findings, \
                   findings_total      = scan_rollup.findings_total      + EXCLUDED.findings_total, \
                   bytes_scanned       = scan_rollup.bytes_scanned       + EXCLUDED.bytes_scanned, \
                   duration_ms_sum     = scan_rollup.duration_ms_sum     + EXCLUDED.duration_ms_sum, \
                   oversize_skipped    = scan_rollup.oversize_skipped    + EXCLUDED.oversize_skipped, \
                   scan_errors         = scan_rollup.scan_errors         + EXCLUDED.scan_errors",
                &[
                    bucket_hour,
                    tenant_id,
                    channel,
                    &(counts.scans_total as i64),
                    &(counts.scans_with_findings as i64),
                    &(counts.findings_total as i64),
                    &(counts.bytes_scanned as i64),
                    &(counts.duration_ms_sum as i64),
                    &(counts.oversize_skipped as i64),
                    &(counts.scan_errors as i64),
                ],
            )
            .await;

        match res {
            Ok(_) => written += 1,
            Err(e) => {
                // Restore only what has not been written, so a mid-flush
                // failure neither loses nor double-counts.
                let remaining: Vec<_> = drained.iter().skip(written).cloned().collect();
                acc.restore(remaining);
                return Err(Box::new(e));
            }
        }
    }

    Ok(written)
}

#[cfg(test)]
mod rollup_tests {
    use super::*;

    #[test]
    fn record_merges_into_one_bucket_per_key() {
        let acc = RollupAccumulator::new();
        acc.record(
            Some("acme"),
            "api",
            RollupCounts {
                scans_total: 1,
                findings_total: 3,
                ..Default::default()
            },
        );
        acc.record(
            Some("acme"),
            "api",
            RollupCounts {
                scans_total: 1,
                scans_with_findings: 1,
                findings_total: 2,
                ..Default::default()
            },
        );

        let drained = acc.drain();
        assert_eq!(drained.len(), 1, "same key must collapse into one bucket");
        let (_, counts) = &drained[0];
        assert_eq!(counts.scans_total, 2);
        assert_eq!(counts.findings_total, 5);
        assert_eq!(counts.scans_with_findings, 1);
    }

    #[test]
    fn distinct_tenants_and_channels_do_not_merge() {
        let acc = RollupAccumulator::new();
        let one = RollupCounts {
            scans_total: 1,
            ..Default::default()
        };
        acc.record(Some("acme"), "api", one);
        acc.record(Some("globex"), "api", one);
        acc.record(Some("acme"), "icap", one);
        assert_eq!(acc.drain().len(), 3);
    }

    #[test]
    fn untenanted_scans_share_the_empty_string_key() {
        let acc = RollupAccumulator::new();
        let one = RollupCounts {
            scans_total: 1,
            ..Default::default()
        };
        acc.record(None, "api", one);
        acc.record(Some(""), "api", one);
        let drained = acc.drain();
        assert_eq!(
            drained.len(),
            1,
            "None and empty tenant must aggregate together, not split"
        );
        assert_eq!(drained[0].1.scans_total, 2);
    }

    #[test]
    fn drain_empties_so_counts_are_not_flushed_twice() {
        let acc = RollupAccumulator::new();
        acc.record(
            None,
            "api",
            RollupCounts {
                scans_total: 5,
                ..Default::default()
            },
        );
        assert_eq!(acc.drain().len(), 1);
        assert!(acc.drain().is_empty(), "second drain must yield nothing");
    }

    #[test]
    fn restore_merges_rather_than_overwrites() {
        // A failed flush must not clobber counts recorded while it was in
        // flight.
        let acc = RollupAccumulator::new();
        acc.record(
            None,
            "api",
            RollupCounts {
                scans_total: 2,
                ..Default::default()
            },
        );
        let drained = acc.drain();

        acc.record(
            None,
            "api",
            RollupCounts {
                scans_total: 3,
                ..Default::default()
            },
        );
        acc.restore(drained);

        let after = acc.drain();
        assert_eq!(after.len(), 1);
        assert_eq!(
            after[0].1.scans_total, 5,
            "restored and concurrent counts must sum"
        );
    }

    #[test]
    fn oversize_and_errors_stay_out_of_scans_total() {
        // A scan that did not happen must not inflate the denominator — that
        // would quietly improve the apparent detection rate.
        let acc = RollupAccumulator::new();
        acc.record(
            None,
            "icap",
            RollupCounts {
                oversize_skipped: 4,
                scan_errors: 2,
                ..Default::default()
            },
        );
        let drained = acc.drain();
        let counts = &drained[0].1;
        assert_eq!(counts.scans_total, 0);
        assert_eq!(counts.oversize_skipped, 4);
        assert_eq!(counts.scan_errors, 2);
    }

    #[test]
    fn timestamps_truncate_to_the_hour() {
        use chrono::TimeZone;
        let ts = chrono::Utc
            .with_ymd_and_hms(2026, 9, 4, 13, 47, 31)
            .unwrap();
        let truncated = truncate_to_hour(ts);
        assert_eq!(
            truncated,
            chrono::Utc.with_ymd_and_hms(2026, 9, 4, 13, 0, 0).unwrap()
        );
    }
}
