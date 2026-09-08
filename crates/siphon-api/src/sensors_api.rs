//! Sensors: the receiving side of telemetry, and the report built from it.
//!
//! `POST /v1/sensors/heartbeat` takes one [`Heartbeat`] from a detector
//! holding the `Sensor` role and stores it as a row. `GET /v1/sensors`
//! answers the operator's three questions per detector — is it up, is it
//! talking securely, is it catching things — from the rows alone, so the
//! answer is a measurement, not a self-description. siphon-api reports
//! itself the same way, written in-process by `self_report_loop`.
//!
//! Every judgement here is a pure function of timestamps and counters and is
//! tested as such; the SQL only aggregates.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use siphon_auth::telemetry::Heartbeat;

use crate::{AppState, AuthContextExt, ErrorResponse, RequireReportTelemetry, RequireViewStatus};

/// Missed this many intervals → stale. Three, not one: a single missed beat
/// is a GC pause or a busy scan, and a console that flaps on that trains
/// people to ignore it.
const STALE_AFTER_INTERVALS: i64 = 3;
/// Stale this long → gone. Still listed for the rest of the 7-day window so
/// a pod that died is visible as having died, not silently absent.
const GONE_AFTER_SECS: i64 = 24 * 3600;
/// A certificate with fewer days left than this is a warning.
const CERT_WARN_DAYS: i64 = 14;
const H24: i64 = 24 * 3600;
const D7: i64 = 7 * 24 * 3600;
/// Heartbeats older than this are pruned by the retention task.
pub const HEARTBEAT_RETENTION_DAYS: u32 = 30;

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: msg.into() }))
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

fn validate(hb: &Heartbeat, now: DateTime<Utc>) -> Result<(), String> {
    let name_ok = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    if !name_ok(&hb.sensor, 32) {
        return Err("sensor must be 1–32 characters of [A-Za-z0-9._-]".into());
    }
    if !name_ok(&hb.instance, 128) {
        return Err("instance must be 1–128 characters of [A-Za-z0-9._-]".into());
    }
    if hb.version.is_empty() || hb.version.len() > 64 || hb.version.chars().any(char::is_control) {
        return Err("version must be 1–64 printable characters".into());
    }
    if !(5..=3600).contains(&hb.interval_secs) {
        return Err("interval_secs must be between 5 and 3600".into());
    }
    // A sensor whose clock is ahead of ours would report an uptime of
    // negative duration; clamp the complaint to a tolerance clocks actually
    // drift by.
    if hb.started_at > now + Duration::minutes(5) {
        return Err("started_at is in the future".into());
    }
    if let Some(t) = hb.last_scan_at {
        if t > now + Duration::minutes(5) {
            return Err("last_scan_at is in the future".into());
        }
    }
    Ok(())
}

/// Store one heartbeat. Shared by the handler and the in-process
/// self-report, so siphon-api's own row has exactly the shape of any other.
pub async fn insert_heartbeat(
    pool: &Pool,
    hb: &Heartbeat,
    api_key_id: Option<&str>,
) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let (l_tls, l_mtls, l_exp) = match &hb.transport.listener {
        Some(l) => (Some(l.tls), Some(l.mtls), l.cert_not_after),
        None => (None, None, None),
    };
    let (db_mode, db_auth) = match &hb.transport.database {
        Some(d) => (Some(d.mode.as_str()), Some(d.client_authenticated)),
        None => (None, None),
    };
    let c = &hb.counters;
    let as_i64 = |v: Option<u64>| v.map(|n| i64::try_from(n).unwrap_or(i64::MAX));
    let row = client
        .query_one(
            "INSERT INTO sensor_heartbeats \
             (sensor, instance, api_key_id, version, started_at, interval_secs, \
              listener_tls, listener_mtls, listener_cert_not_after, db_mode, db_client_authenticated, \
              scans_total, scans_with_findings, findings_total, errors_total, bytes_scanned, \
              duration_ms_sum, last_scan_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
             RETURNING received_at",
            &[
                &hb.sensor,
                &hb.instance,
                &api_key_id,
                &hb.version,
                &hb.started_at,
                &(hb.interval_secs as i32),
                &l_tls,
                &l_mtls,
                &l_exp,
                &db_mode,
                &db_auth,
                &as_i64(c.scans_total),
                &as_i64(c.scans_with_findings),
                &as_i64(c.findings_total),
                &as_i64(c.errors_total),
                &as_i64(c.bytes_scanned),
                &as_i64(c.duration_ms_sum),
                &hb.last_scan_at,
            ],
        )
        .await?;
    Ok(row.get("received_at"))
}

#[derive(Serialize)]
pub struct Ack {
    pub received_at: DateTime<Utc>,
    /// When the receiver will start calling this instance stale.
    pub stale_after: DateTime<Utc>,
}

pub async fn heartbeat(
    _: RequireReportTelemetry,
    AuthContextExt(ctx): AuthContextExt,
    State(state): State<Arc<AppState>>,
    Json(hb): Json<Heartbeat>,
) -> Result<(StatusCode, Json<Ack>), (StatusCode, Json<ErrorResponse>)> {
    let Some(pool) = &state.db_pool else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "telemetry cannot be stored: SIPHON_DATABASE_URL is not set",
        ));
    };
    let now = Utc::now();
    validate(&hb, now).map_err(|why| err(StatusCode::BAD_REQUEST, why))?;
    let received_at = insert_heartbeat(pool, &hb, ctx.key_id.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, sensor = %hb.sensor, "heartbeat insert failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "heartbeat could not be stored",
            )
        })?;
    tracing::debug!(sensor = %hb.sensor, instance = %hb.instance, actor = %ctx.actor, "heartbeat");
    Ok((
        StatusCode::ACCEPTED,
        Json(Ack {
            received_at,
            stale_after: received_at
                + Duration::seconds(hb.interval_secs as i64 * STALE_AFTER_INTERVALS),
        }),
    ))
}

/// siphon-api's own heartbeat, written straight to the table every
/// `interval` — it is a sensor too, and it does not get to skip the queue.
pub async fn self_report_loop(state: Arc<AppState>, interval: std::time::Duration) {
    let Some(pool) = state.db_pool.clone() else {
        return;
    };
    let started_at = Utc::now() - Duration::seconds(state.started_at.elapsed().as_secs() as i64);
    let mut failing = false;
    loop {
        let hb = Heartbeat {
            sensor: "siphon-api".into(),
            instance: state.pod_id.to_string(),
            version: env!("CARGO_PKG_VERSION").into(),
            started_at,
            interval_secs: interval.as_secs(),
            transport: state.transport.clone(),
            counters: state.sensor.snapshot(),
            last_scan_at: state.sensor.last_scan_at(),
        };
        match insert_heartbeat(&pool, &hb, None).await {
            Ok(_) => failing = false,
            Err(e) => {
                if !failing {
                    tracing::warn!(error = %e, "own heartbeat could not be stored; will keep trying");
                    failing = true;
                }
            }
        }
        tokio::time::sleep(interval).await;
    }
}

// ---------------------------------------------------------------------------
// Judgement — pure, tested
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Liveness {
    Healthy,
    Stale,
    Gone,
}

pub fn liveness(now: DateTime<Utc>, last_seen: DateTime<Utc>, interval_secs: i64) -> Liveness {
    let age = (now - last_seen).num_seconds();
    if age <= interval_secs * STALE_AFTER_INTERVALS {
        Liveness::Healthy
    } else if age <= GONE_AFTER_SECS {
        Liveness::Stale
    } else {
        Liveness::Gone
    }
}

/// One hop's state. `NotApplicable` is a hop the sensor does not have and is
/// never counted against it; `Off` is a hop it has and does not secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HopState {
    NotApplicable,
    Ok,
    Warn,
    Off,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HopReport {
    pub state: HopState,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_days_left: Option<i64>,
}

pub fn judge_listener(
    tls: Option<bool>,
    mtls: Option<bool>,
    not_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> HopReport {
    let Some(tls) = tls else {
        return HopReport {
            state: HopState::NotApplicable,
            detail: "no listener".into(),
            cert_days_left: None,
        };
    };
    if !tls {
        return HopReport {
            state: HopState::Off,
            detail: "plaintext listener".into(),
            cert_days_left: None,
        };
    }
    let days = not_after.map(|t| (t - now).num_days());
    let (state, detail) = match (mtls.unwrap_or(false), days) {
        (_, Some(d)) if d < 0 => (HopState::Off, "certificate expired".to_string()),
        (false, _) => (
            HopState::Warn,
            "TLS without client authentication — encrypted, not mutual".into(),
        ),
        (true, Some(d)) if d < CERT_WARN_DAYS => (
            HopState::Warn,
            format!("mutual TLS; certificate expires in {d} days"),
        ),
        (true, _) => (HopState::Ok, "mutual TLS".into()),
    };
    HopReport {
        state,
        detail,
        cert_days_left: days,
    }
}

pub fn judge_database(mode: Option<&str>, client_authenticated: Option<bool>) -> HopReport {
    let Some(mode) = mode else {
        return HopReport {
            state: HopState::NotApplicable,
            detail: "no database".into(),
            cert_days_left: None,
        };
    };
    let (state, detail) = match (mode, client_authenticated.unwrap_or(false)) {
        ("disable", _) => (HopState::Off, "plaintext database connection".to_string()),
        (_, true) => (
            HopState::Ok,
            format!("{mode}: client certificate presented"),
        ),
        (m, false) => (
            HopState::Warn,
            format!("{m}: encrypted, service anonymous to the database"),
        ),
    };
    HopReport {
        state,
        detail,
        cert_days_left: None,
    }
}

/// Worst applicable hop. All not-applicable → not applicable.
pub fn overall(hops: &[HopState]) -> HopState {
    hops.iter()
        .copied()
        .max()
        .unwrap_or(HopState::NotApplicable)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Ratio {
    pub received: i64,
    pub expected: i64,
    /// `None` when nothing was expected — a sensor first seen seconds ago
    /// has no availability figure yet, and 0% would be a lie.
    pub ratio: Option<f64>,
}

/// Heartbeat slots received ÷ slots expected while the sensor existed
/// inside the window. Capped at 1: clock skew can put two beats in a slot.
pub fn availability(slots: i64, interval_secs: i64, present_secs: i64) -> Ratio {
    let interval = interval_secs.max(1);
    let present = present_secs.max(0);
    let expected = (present + interval - 1) / interval;
    Ratio {
        received: slots.min(expected),
        expected,
        ratio: (expected > 0).then(|| (slots as f64 / expected as f64).min(1.0)),
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
pub struct Activity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans_with_findings: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_duration_ms: Option<f64>,
    /// scans with findings ÷ scans. `None` with no scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_rate: Option<f64>,
}

impl Activity {
    fn add(&mut self, other: &Activity) {
        fn sum(a: &mut Option<i64>, b: Option<i64>) {
            if let Some(b) = b {
                *a = Some(a.unwrap_or(0) + b);
            }
        }
        sum(&mut self.scans, other.scans);
        sum(&mut self.scans_with_findings, other.scans_with_findings);
        sum(&mut self.findings, other.findings);
        sum(&mut self.errors, other.errors);
        sum(&mut self.bytes, other.bytes);
        // avg_duration recomputed by `finish` from duration_sum, kept private.
    }

    fn finish(&mut self, duration_ms_sum: Option<i64>) {
        self.detection_rate = match (self.scans, self.scans_with_findings) {
            (Some(s), Some(w)) if s > 0 => Some(w as f64 / s as f64),
            _ => None,
        };
        self.avg_duration_ms = match (self.scans, duration_ms_sum) {
            (Some(s), Some(d)) if s > 0 => Some(d as f64 / s as f64),
            _ => None,
        };
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdicts {
    pub reviewed: i64,
    pub true_positives: i64,
    pub false_positives: i64,
    /// tp ÷ (tp + fp). `None` until something has been reviewed.
    pub precision: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportReport {
    pub listener: HopReport,
    pub database: HopReport,
    pub overall: HopState,
}

#[derive(Debug, Clone, Serialize)]
pub struct Windowed<T> {
    pub h24: T,
    pub d7: T,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstanceReport {
    pub instance: String,
    pub api_key_id: Option<String>,
    pub version: String,
    pub started_at: DateTime<Utc>,
    pub uptime_secs: i64,
    pub restarts_7d: i64,
    pub last_seen: DateTime<Utc>,
    pub interval_secs: i64,
    pub liveness: Liveness,
    pub stale_for_secs: i64,
    pub availability: Windowed<Ratio>,
    pub transport: TransportReport,
    pub activity: Windowed<Activity>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorReport {
    pub sensor: String,
    /// Best instance: one healthy replica is a sensor that is up.
    pub liveness: Liveness,
    pub instances: Vec<InstanceReport>,
    /// Slots in which *any* instance beat.
    pub availability: Windowed<Ratio>,
    /// Worst instance.
    pub transport_overall: HopState,
    pub activity: Windowed<Activity>,
    /// From analyst verdicts on this sensor's findings, last 7 days.
    pub verdicts: Option<Verdicts>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorsReport {
    pub generated_at: DateTime<Utc>,
    pub sensors: Vec<SensorReport>,
    /// Sensors the deployment expects and has never heard from. Absence is
    /// a state: an unconfigured siphon-fs and a dead one look the same from
    /// here, and the console must say "never seen", not omit the row.
    pub never_seen: Vec<String>,
}

/// What every deployment has. A sensor outside this list still reports and
/// is still listed; this only decides what "never seen" can name.
const EXPECTED_SENSORS: [&str; 4] = ["siphon-api", "siphon-fs", "siphon-icap", "siphon-smtp"];

#[derive(Deserialize)]
pub struct SensorsQuery {}

struct Segment {
    sensor: String,
    instance: String,
    started_at: DateTime<Utc>,
    first_seen: DateTime<Utc>,
    slots_24h: i64,
    slots_7d: i64,
    activity_24h: Activity,
    duration_24h: Option<i64>,
    activity_7d: Activity,
    duration_7d: Option<i64>,
}

pub async fn list_sensors(
    _: RequireViewStatus,
    State(state): State<Arc<AppState>>,
    Query(_q): Query<SensorsQuery>,
) -> Result<Json<SensorsReport>, (StatusCode, Json<ErrorResponse>)> {
    let Some(pool) = &state.db_pool else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sensor telemetry is not stored: SIPHON_DATABASE_URL is not set",
        ));
    };
    let client = pool.get().await.map_err(|e| {
        tracing::error!(error = %e, "sensors: pool");
        err(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable")
    })?;
    let now = Utc::now();

    // Q1: the latest row per instance in the 7-day window.
    let latest = client
        .query(
            "SELECT DISTINCT ON (sensor, instance) sensor, instance, api_key_id, version, started_at, \
             received_at, interval_secs, listener_tls, listener_mtls, listener_cert_not_after, \
             db_mode, db_client_authenticated, last_scan_at \
             FROM sensor_heartbeats WHERE received_at > now() - interval '7 days' \
             ORDER BY sensor, instance, received_at DESC",
            &[],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "sensors: latest");
            err(StatusCode::INTERNAL_SERVER_ERROR, "query failed")
        })?;

    // Q2: per (instance, started_at) segment — heartbeat slots and counter
    // deltas for both windows. Deltas are max-min within the window, so a
    // window's activity is what happened inside it, not since boot.
    let segments = client
        .query(
            "SELECT sensor, instance, started_at, min(received_at) AS first_seen, \
             count(DISTINCT floor(extract(epoch FROM received_at) / interval_secs)) \
               FILTER (WHERE received_at > now() - interval '24 hours') AS slots_24h, \
             count(DISTINCT floor(extract(epoch FROM received_at) / interval_secs)) AS slots_7d, \
             max(scans_total) FILTER (WHERE received_at > now() - interval '24 hours') - min(scans_total) FILTER (WHERE received_at > now() - interval '24 hours') AS scans_24h, \
             max(scans_with_findings) FILTER (WHERE received_at > now() - interval '24 hours') - min(scans_with_findings) FILTER (WHERE received_at > now() - interval '24 hours') AS swf_24h, \
             max(findings_total) FILTER (WHERE received_at > now() - interval '24 hours') - min(findings_total) FILTER (WHERE received_at > now() - interval '24 hours') AS findings_24h, \
             max(errors_total) FILTER (WHERE received_at > now() - interval '24 hours') - min(errors_total) FILTER (WHERE received_at > now() - interval '24 hours') AS errors_24h, \
             max(bytes_scanned) FILTER (WHERE received_at > now() - interval '24 hours') - min(bytes_scanned) FILTER (WHERE received_at > now() - interval '24 hours') AS bytes_24h, \
             max(duration_ms_sum) FILTER (WHERE received_at > now() - interval '24 hours') - min(duration_ms_sum) FILTER (WHERE received_at > now() - interval '24 hours') AS dur_24h, \
             max(scans_total) - min(scans_total) AS scans_7d, \
             max(scans_with_findings) - min(scans_with_findings) AS swf_7d, \
             max(findings_total) - min(findings_total) AS findings_7d, \
             max(errors_total) - min(errors_total) AS errors_7d, \
             max(bytes_scanned) - min(bytes_scanned) AS bytes_7d, \
             max(duration_ms_sum) - min(duration_ms_sum) AS dur_7d \
             FROM sensor_heartbeats WHERE received_at > now() - interval '7 days' \
             GROUP BY sensor, instance, started_at",
            &[],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "sensors: segments");
            err(StatusCode::INTERNAL_SERVER_ERROR, "query failed")
        })?
        .into_iter()
        .map(|r| {
            let mut a24 = Activity {
                scans: r.get("scans_24h"),
                scans_with_findings: r.get("swf_24h"),
                findings: r.get("findings_24h"),
                errors: r.get("errors_24h"),
                bytes: r.get("bytes_24h"),
                ..Default::default()
            };
            let d24: Option<i64> = r.get("dur_24h");
            a24.finish(d24);
            let mut a7 = Activity {
                scans: r.get("scans_7d"),
                scans_with_findings: r.get("swf_7d"),
                findings: r.get("findings_7d"),
                errors: r.get("errors_7d"),
                bytes: r.get("bytes_7d"),
                ..Default::default()
            };
            let d7: Option<i64> = r.get("dur_7d");
            a7.finish(d7);
            Segment {
                sensor: r.get("sensor"),
                instance: r.get("instance"),
                started_at: r.get("started_at"),
                first_seen: r.get("first_seen"),
                slots_24h: r.get("slots_24h"),
                slots_7d: r.get("slots_7d"),
                activity_24h: a24,
                duration_24h: d24,
                activity_7d: a7,
                duration_7d: d7,
            }
        })
        .collect::<Vec<_>>();

    // Q3: slots in which any instance of a sensor beat, and when the sensor
    // was first seen — the sensor-level availability.
    let sensor_slots = client
        .query(
            "SELECT sensor, min(received_at) AS first_seen, min(interval_secs) AS interval_secs, \
             count(DISTINCT floor(extract(epoch FROM received_at) / interval_secs)) \
               FILTER (WHERE received_at > now() - interval '24 hours') AS slots_24h, \
             count(DISTINCT floor(extract(epoch FROM received_at) / interval_secs)) AS slots_7d \
             FROM sensor_heartbeats WHERE received_at > now() - interval '7 days' GROUP BY sensor",
            &[],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "sensors: slots");
            err(StatusCode::INTERNAL_SERVER_ERROR, "query failed")
        })?;

    // Q4: analyst verdicts by the pod that produced the finding.
    let verdict_rows = client
        .query(
            "SELECT source_pod, count(*) FILTER (WHERE analyst_verdict IS NOT NULL) AS reviewed, \
             count(*) FILTER (WHERE analyst_verdict = 'tp') AS tp, \
             count(*) FILTER (WHERE analyst_verdict = 'fp') AS fp \
             FROM findings WHERE reviewed_at > now() - interval '7 days' AND source_pod IS NOT NULL \
             GROUP BY source_pod",
            &[],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "sensors: verdicts");
            err(StatusCode::INTERNAL_SERVER_ERROR, "query failed")
        })?;

    // Assemble.
    let mut by_sensor: std::collections::BTreeMap<String, Vec<InstanceReport>> =
        std::collections::BTreeMap::new();
    for row in &latest {
        let sensor: String = row.get("sensor");
        let instance: String = row.get("instance");
        let started_at: DateTime<Utc> = row.get("started_at");
        let last_seen: DateTime<Utc> = row.get("received_at");
        let interval_secs = i64::from(row.get::<_, i32>("interval_secs"));

        let segs: Vec<&Segment> = segments
            .iter()
            .filter(|s| s.sensor == sensor && s.instance == instance)
            .collect();
        let first_seen = segs.iter().map(|s| s.first_seen).min().unwrap_or(last_seen);
        let present_7d = (now - first_seen).num_seconds().min(D7);
        let present_24h = (now - first_seen.max(now - Duration::seconds(H24))).num_seconds();
        let slots_24h: i64 = segs.iter().map(|s| s.slots_24h).sum();
        let slots_7d: i64 = segs.iter().map(|s| s.slots_7d).sum();

        let mut a24 = Activity::default();
        let mut a7 = Activity::default();
        let mut d24 = None;
        let mut d7 = None;
        for s in &segs {
            a24.add(&s.activity_24h);
            a7.add(&s.activity_7d);
            if let Some(d) = s.duration_24h {
                d24 = Some(d24.unwrap_or(0) + d);
            }
            if let Some(d) = s.duration_7d {
                d7 = Some(d7.unwrap_or(0) + d);
            }
        }
        a24.finish(d24);
        a7.finish(d7);

        let listener = judge_listener(
            row.get("listener_tls"),
            row.get("listener_mtls"),
            row.get("listener_cert_not_after"),
            now,
        );
        let database = judge_database(row.get("db_mode"), row.get("db_client_authenticated"));
        let transport = TransportReport {
            overall: overall(&[listener.state, database.state]),
            listener,
            database,
        };
        let liveness = liveness(now, last_seen, interval_secs);

        by_sensor.entry(sensor).or_default().push(InstanceReport {
            instance,
            api_key_id: row.get("api_key_id"),
            version: row.get("version"),
            started_at,
            uptime_secs: (now - started_at).num_seconds().max(0),
            restarts_7d: (segs.len() as i64 - 1).max(0),
            last_seen,
            interval_secs,
            liveness,
            stale_for_secs: match liveness {
                Liveness::Healthy => 0,
                _ => (now - last_seen).num_seconds(),
            },
            availability: Windowed {
                h24: availability(slots_24h, interval_secs, present_24h),
                d7: availability(slots_7d, interval_secs, present_7d),
            },
            transport,
            activity: Windowed { h24: a24, d7: a7 },
            last_scan_at: row.get("last_scan_at"),
        });
    }

    let mut sensors = Vec::new();
    for (sensor, mut instances) in by_sensor {
        instances.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        let slot_row = sensor_slots
            .iter()
            .find(|r| r.get::<_, String>("sensor") == sensor);
        let (s24, s7, interval, first_seen) = match slot_row {
            Some(r) => (
                r.get::<_, i64>("slots_24h"),
                r.get::<_, i64>("slots_7d"),
                i64::from(r.get::<_, i32>("interval_secs")),
                r.get::<_, DateTime<Utc>>("first_seen"),
            ),
            None => (0, 0, 30, now),
        };
        let present_7d = (now - first_seen).num_seconds().min(D7);
        let present_24h = (now - first_seen.max(now - Duration::seconds(H24))).num_seconds();

        let mut a24 = Activity::default();
        let mut a7 = Activity::default();
        for i in &instances {
            a24.add(&i.activity.h24);
            a7.add(&i.activity.d7);
        }
        // Sensor-level averages need the duration sums, which are per
        // instance only; report the count-based figures at this level.
        a24.finish(None);
        a7.finish(None);

        let verdicts = verdict_rows
            .iter()
            .find(|r| r.get::<_, String>("source_pod") == sensor)
            .map(|r| {
                let tp: i64 = r.get("tp");
                let fp: i64 = r.get("fp");
                Verdicts {
                    reviewed: r.get("reviewed"),
                    true_positives: tp,
                    false_positives: fp,
                    precision: (tp + fp > 0).then(|| tp as f64 / (tp + fp) as f64),
                }
            });

        sensors.push(SensorReport {
            liveness: instances
                .iter()
                .map(|i| i.liveness)
                .min_by_key(|l| match l {
                    Liveness::Healthy => 0,
                    Liveness::Stale => 1,
                    Liveness::Gone => 2,
                })
                .unwrap_or(Liveness::Gone),
            availability: Windowed {
                h24: availability(s24, interval, present_24h),
                d7: availability(s7, interval, present_7d),
            },
            transport_overall: overall(
                &instances
                    .iter()
                    .map(|i| i.transport.overall)
                    .collect::<Vec<_>>(),
            ),
            activity: Windowed { h24: a24, d7: a7 },
            verdicts,
            last_scan_at: instances.iter().filter_map(|i| i.last_scan_at).max(),
            instances,
            sensor,
        });
    }

    let never_seen = EXPECTED_SENSORS
        .iter()
        .filter(|e| !sensors.iter().any(|s| s.sensor == **e))
        .map(|s| s.to_string())
        .collect();

    Ok(Json(SensorsReport {
        generated_at: now,
        sensors,
        never_seen,
    }))
}

/// Delete heartbeats older than the retention window. Returns rows removed.
pub async fn prune_heartbeats(
    pool: &Option<Pool>,
    days: u32,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else {
        return Ok(0);
    };
    let client = pool.get().await?;
    let n = client
        .execute(
            "DELETE FROM sensor_heartbeats WHERE received_at < now() - make_interval(days => $1)",
            &[&(days as i32)],
        )
        .await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_auth::telemetry::{Counters, ListenerState, Transport};

    #[test]
    fn liveness_tolerates_two_missed_beats_not_three() {
        // One `now` for both sides: two clock reads would differ by
        // microseconds and `num_seconds` truncates, so 91 s could read as 90.
        let now = Utc::now();
        let ago = |s: i64| now - Duration::seconds(s);
        assert_eq!(liveness(now, ago(0), 30), Liveness::Healthy);
        assert_eq!(liveness(now, ago(90), 30), Liveness::Healthy);
        assert_eq!(liveness(now, ago(91), 30), Liveness::Stale);
        assert_eq!(liveness(now, ago(GONE_AFTER_SECS), 30), Liveness::Stale);
        assert_eq!(liveness(now, ago(GONE_AFTER_SECS + 1), 30), Liveness::Gone);
    }

    #[test]
    fn a_hop_the_sensor_lacks_is_not_a_failure() {
        let now = Utc::now();
        assert_eq!(
            judge_listener(None, None, None, now).state,
            HopState::NotApplicable
        );
        assert_eq!(judge_database(None, None).state, HopState::NotApplicable);
        // And it does not drag the overall down.
        assert_eq!(
            overall(&[HopState::NotApplicable, HopState::Ok]),
            HopState::Ok
        );
        assert_eq!(overall(&[HopState::NotApplicable]), HopState::NotApplicable);
    }

    #[test]
    fn encrypted_is_not_mutual() {
        let now = Utc::now();
        let far = Some(now + Duration::days(300));
        assert_eq!(
            judge_listener(Some(true), Some(false), far, now).state,
            HopState::Warn
        );
        assert_eq!(
            judge_listener(Some(true), Some(true), far, now).state,
            HopState::Ok
        );
        assert_eq!(
            judge_listener(Some(false), None, None, now).state,
            HopState::Off
        );
        assert_eq!(
            judge_database(Some("require"), Some(false)).state,
            HopState::Warn
        );
        assert_eq!(judge_database(Some("mtls"), Some(true)).state, HopState::Ok);
        assert_eq!(
            judge_database(Some("disable"), Some(false)).state,
            HopState::Off
        );
    }

    #[test]
    fn an_expiring_certificate_warns_and_an_expired_one_is_off() {
        let now = Utc::now();
        let soon = judge_listener(Some(true), Some(true), Some(now + Duration::days(3)), now);
        assert_eq!(soon.state, HopState::Warn);
        assert_eq!(soon.cert_days_left, Some(3));
        let gone = judge_listener(Some(true), Some(true), Some(now - Duration::days(1)), now);
        assert_eq!(gone.state, HopState::Off);
    }

    #[test]
    fn overall_is_the_worst_hop() {
        assert_eq!(overall(&[HopState::Ok, HopState::Warn]), HopState::Warn);
        assert_eq!(overall(&[HopState::Warn, HopState::Off]), HopState::Off);
    }

    #[test]
    fn availability_is_a_ratio_of_expected_slots_and_never_fakes_zero() {
        // 24 h at 30 s = 2880 slots.
        let r = availability(2880, 30, 86_400);
        assert_eq!(r.expected, 2880);
        assert_eq!(r.ratio, Some(1.0));
        let r = availability(1440, 30, 86_400);
        assert!((r.ratio.unwrap() - 0.5).abs() < 1e-9);
        // Present for 0 s → nothing expected → no figure, not 0 %.
        assert_eq!(availability(0, 30, 0).ratio, None);
        // Skew put two beats in one slot: capped, not 103 %.
        assert_eq!(availability(3000, 30, 86_400).ratio, Some(1.0));
    }

    #[test]
    fn activity_sums_and_absent_stays_absent() {
        let mut a = Activity {
            scans: Some(10),
            scans_with_findings: Some(2),
            ..Default::default()
        };
        a.add(&Activity {
            scans: Some(5),
            scans_with_findings: Some(3),
            bytes: None,
            ..Default::default()
        });
        a.finish(Some(300));
        assert_eq!(a.scans, Some(15));
        assert_eq!(a.bytes, None, "nobody counted bytes, so there is no figure");
        assert!((a.detection_rate.unwrap() - 5.0 / 15.0).abs() < 1e-9);
        assert!((a.avg_duration_ms.unwrap() - 20.0).abs() < 1e-9);
        let mut none = Activity::default();
        none.finish(None);
        assert_eq!(none.detection_rate, None, "no scans → no rate, not 0");
    }

    #[test]
    fn heartbeat_validation() {
        let now = Utc::now();
        let mut hb = Heartbeat {
            sensor: "siphon-fs".into(),
            instance: "pod-abc".into(),
            version: "1.4.0".into(),
            started_at: now - Duration::hours(1),
            interval_secs: 30,
            transport: Transport {
                listener: Some(ListenerState {
                    tls: true,
                    mtls: true,
                    cert_not_after: None,
                }),
                database: None,
            },
            counters: Counters::default(),
            last_scan_at: None,
        };
        assert!(validate(&hb, now).is_ok());
        hb.sensor = "siphon fs".into();
        assert!(validate(&hb, now).is_err());
        hb.sensor = "siphon-fs".into();
        hb.interval_secs = 1;
        assert!(validate(&hb, now).is_err());
        hb.interval_secs = 30;
        hb.started_at = now + Duration::hours(1);
        assert!(validate(&hb, now).is_err());
    }
}
