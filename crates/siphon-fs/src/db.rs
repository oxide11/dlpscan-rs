//! Database layer for siphon-fs — connection pool + findings persistence.
//!
//! Mirrors siphon-api's db.rs but omits the migration runner: schema
//! migrations are applied exclusively by siphon-api at startup. siphon-fs
//! only inserts rows into the tables that siphon-api created.
//!
//! Optional at runtime. Every call guards on `Option<Pool>` and degrades
//! gracefully to a no-op when SIPHON_DATABASE_URL is unset or Postgres
//! is unreachable at startup.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime, SslMode};
use std::time::Duration;
use tokio_postgres::NoTls;

const MAX_POOL_SIZE: usize = 4;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection-state classification, mirrored from siphon-api for symmetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolState {
    Unconfigured,
    Connected,
    StartupFailed,
}

/// Initialise an optional database pool from the environment.
/// Mirrors siphon-api's `db::init_optional` exactly. Returns
/// `(Unconfigured, None)` when SIPHON_DATABASE_URL is absent.
pub async fn init_optional(
) -> Result<(PoolState, Option<Pool>), Box<dyn std::error::Error + Send + Sync>> {
    let Ok(url) = std::env::var("SIPHON_DATABASE_URL") else {
        tracing::info!("SIPHON_DATABASE_URL not set — file-scan persistence disabled");
        return Ok((PoolState::Unconfigured, None));
    };

    let mut cfg = Config::new();
    cfg.url = Some(url);
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

    match tokio::time::timeout(STARTUP_TIMEOUT, pool.get()).await {
        Ok(Ok(client)) => {
            let _ = client.simple_query("SELECT 1").await;
            tracing::info!(
                max_pool_size = MAX_POOL_SIZE,
                "siphon-fs: connected to Postgres"
            );
            Ok((PoolState::Connected, Some(pool)))
        }
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                "siphon-fs: Postgres connection failed at startup — running without persistence"
            );
            Ok((PoolState::StartupFailed, None))
        }
        Err(_) => {
            tracing::warn!(
                "siphon-fs: Postgres connection timed out at startup — running without persistence"
            );
            Ok((PoolState::StartupFailed, None))
        }
    }
}

/// Persist one completed file scan to the `scans` + `findings` tables.
///
/// Identical contract to siphon-api's `db::persist_scan` — called in a
/// background `tokio::spawn` so DB latency never delays the scan response.
/// The pool being None is a silent no-op; individual DB errors are logged
/// and discarded.
///
/// `file_name`, `file_hash` (SHA-256 of the raw bytes), and `mime_type`
/// populate the columns added by migration 0003.
#[allow(clippy::too_many_arguments)]
pub async fn persist_scan(
    pool: &Option<Pool>,
    scan_id: uuid::Uuid,
    input_hash: &[u8],
    input_length: usize,
    findings: &[serde_json::Value],
    duration_ms: u64,
    source_pod: &str,
    scanner_version: &str,
    file_name: Option<&str>,
    file_hash: Option<&[u8]>,
    mime_type: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(());
    };

    let client = pool.get().await?;

    let input_hash_bytes: Option<&[u8]> = if input_hash.is_empty() {
        None
    } else {
        Some(input_hash)
    };
    let input_len_i32 = input_length as i32;
    let finding_count_i32 = findings.len() as i32;
    let duration_ms_i32 = duration_ms as i32;
    let source_pod_opt: Option<&str> = Some(source_pod);

    client
        .execute(
            "INSERT INTO scans \
             (id, source_pod, scanner_version, input_hash, \
              input_length, finding_count, duration_ms, action, \
              file_name, file_hash, mime_type) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &scan_id,
                &source_pod_opt,
                &scanner_version,
                &input_hash_bytes,
                &input_len_i32,
                &finding_count_i32,
                &duration_ms_i32,
                &"report",
                &file_name,
                &file_hash,
                &mime_type,
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
                 (scan_id, source_pod, scanner_version, input_hash, \
                  input_length, category, sub_category, confidence, \
                  span_start, span_end, matched_text, has_context, context_required, metadata) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                &[
                    &scan_id,
                    &source_pod_opt,
                    &scanner_version,
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
