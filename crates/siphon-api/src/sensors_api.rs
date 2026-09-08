//! Sensors: the receiving side of telemetry, and the report built from it.
//!
//! `POST /v1/sensors/heartbeat` takes one [`Heartbeat`] from a detector
//! holding the `Sensor` role and stores it as a row. `GET /v1/sensors`
//! reads the rows back as ACEE — Availability, Coverage, Efficacy,
//! Efficiency — per sensor, each axis against a stated target, plus the
//! transport state per hop. siphon-api reports itself the same way, written
//! in-process by `self_report_loop`. The vocabulary and the rules are from
//! *Inside the Adversary's Loop* (Noun, 2026); `docs/architecture/acee.md`
//! says what each axis means here and what it cannot yet read.
//!
//! Three rules the shape enforces. A figure that was not measured is
//! absent, never zero. The four axes are a vector, never averaged. Every
//! reading carries its numerator, denominator and target, so the console
//! renders a judgement it can show the working for.
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
use siphon_auth::telemetry::{
    judge_canary, Canary, Enforcement, FailMode, Heartbeat, Posture, CANARY_TEXT,
};

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
/// Bumped whenever a field's meaning changes. 1 was the three-question
/// report; 2 is the ACEE shape.
pub const SCHEMA_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Objectives — what a reading is judged against
// ---------------------------------------------------------------------------

/// Targets and the expected-sensor inventory.
///
/// ACEE reads a value against what the objective specified, never against
/// last week. Siphon has no objectives layer, so these are declared
/// defaults, overridable per deployment through `SIPHON_SENSORS_*`, and the
/// response says which it is using. When an objectives layer exists these
/// should come from it; until then a default that says it is a default is
/// the honest position.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Objectives {
    /// What the deployment expects to hear from. Coverage against the
    /// matrix is measured over this list, and `never_seen` names its gaps.
    pub expected: Vec<String>,
    /// Heartbeat slots received ÷ expected, 24 h.
    pub availability: f64,
    /// Items scanned ÷ items seen, per sensor, and sensors operational ÷
    /// sensors expected, program-wide.
    pub coverage: f64,
    /// Analyst verdicts true ÷ verdicts, 7 d.
    pub precision: f64,
    /// Heartbeats whose canary passed ÷ heartbeats that ran one, 24 h.
    pub canary: f64,
    /// `defaults`, or the variables that overrode them.
    pub source: String,
}

impl Objectives {
    pub const DEFAULT_EXPECTED: [&'static str; 4] =
        ["siphon-api", "siphon-fs", "siphon-icap", "siphon-smtp"];

    pub fn defaults() -> Self {
        Self {
            expected: Self::DEFAULT_EXPECTED
                .iter()
                .map(|s| s.to_string())
                .collect(),
            availability: 0.99,
            coverage: 0.95,
            precision: 0.80,
            canary: 1.0,
            source: "defaults".into(),
        }
    }

    /// `SIPHON_SENSORS_EXPECTED` (comma-separated) and
    /// `SIPHON_SENSORS_TARGET_{AVAILABILITY,COVERAGE,PRECISION,CANARY}`, each
    /// a fraction in `0..=1`. An unparseable value is an error, never a
    /// silently substituted default — the whole point of a target is that
    /// the operator meant it.
    pub fn from_env() -> Result<Self, String> {
        Self::from_vars(|name| {
            std::env::var(format!("SIPHON_SENSORS_{name}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut o = Self::defaults();
        let mut set = Vec::new();
        if let Some(list) = var("EXPECTED") {
            let expected: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if expected.is_empty() {
                return Err("SIPHON_SENSORS_EXPECTED is set but names no sensor".into());
            }
            o.expected = expected;
            set.push("SIPHON_SENSORS_EXPECTED");
        }
        let mut target = |name: &'static str, slot: &mut f64| -> Result<(), String> {
            if let Some(raw) = var(&format!("TARGET_{name}")) {
                let v: f64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("SIPHON_SENSORS_TARGET_{name}={raw:?} is not a number"))?;
                if !(0.0..=1.0).contains(&v) {
                    return Err(format!(
                        "SIPHON_SENSORS_TARGET_{name}={raw:?} must be a fraction between 0 and 1"
                    ));
                }
                *slot = v;
                set.push(match name {
                    "AVAILABILITY" => "SIPHON_SENSORS_TARGET_AVAILABILITY",
                    "COVERAGE" => "SIPHON_SENSORS_TARGET_COVERAGE",
                    "PRECISION" => "SIPHON_SENSORS_TARGET_PRECISION",
                    _ => "SIPHON_SENSORS_TARGET_CANARY",
                });
            }
            Ok(())
        };
        target("AVAILABILITY", &mut o.availability)?;
        target("COVERAGE", &mut o.coverage)?;
        target("PRECISION", &mut o.precision)?;
        target("CANARY", &mut o.canary)?;
        if !set.is_empty() {
            o.source = set.join(", ");
        }
        Ok(o)
    }
}

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
    if let Some(p) = &hb.posture {
        if p.degraded
            .as_ref()
            .is_some_and(|d| d.is_empty() || d.len() > 256)
        {
            return Err("posture.degraded must be 1–256 characters when present".into());
        }
    }
    if let Some(c) = &hb.canary {
        if c.missing.len() > 16 || c.missing.iter().any(|m| m.len() > 128) {
            return Err("canary.missing is implausibly large".into());
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
    let (p_finding, p_indet, p_degraded) = match &hb.posture {
        Some(p) => (
            Some(p.on_finding.as_str()),
            Some(p.on_indeterminate.as_str()),
            p.degraded.as_deref(),
        ),
        None => (None, None, None),
    };
    let (canary_passed, canary_detail) = match &hb.canary {
        Some(c) => (Some(c.passed), Some(c.detail())),
        None => (None, None),
    };
    let row = client
        .query_one(
            "INSERT INTO sensor_heartbeats \
             (sensor, instance, api_key_id, version, started_at, interval_secs, \
              listener_tls, listener_mtls, listener_cert_not_after, db_mode, db_client_authenticated, \
              scans_total, scans_with_findings, findings_total, errors_total, bytes_scanned, \
              duration_ms_sum, last_scan_at, \
              posture_on_finding, posture_on_indeterminate, posture_degraded, \
              unscanned_total, canary_passed, canary_detail) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,\
                     $19,$20,$21,$22,$23,$24) \
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
                &p_finding,
                &p_indet,
                &p_degraded,
                &as_i64(c.unscanned_total),
                &canary_passed,
                &canary_detail,
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
            posture: Some(own_posture(&state)),
            canary: Some(own_canary(&state)),
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

/// siphon-api is advisory — it answers a scan and the caller decides — so its
/// posture is about degradation only: a pipeline stage an operator toggled
/// off through `PATCH /v1/pipeline/stages` is the one way this sensor does
/// less than its whole job while still answering.
fn own_posture(state: &AppState) -> Posture {
    let mut disabled: Vec<String> = state
        .disabled_stages
        .read()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default();
    disabled.sort();
    Posture {
        on_finding: Enforcement::Advisory,
        on_indeterminate: FailMode::NotApplicable,
        degraded: (!disabled.is_empty())
            .then(|| format!("pipeline stages disabled: {}", disabled.join(", "))),
    }
}

/// The canary through this pod's own scan path, with the same overrides and
/// disabled stages a caller's scan would get — that is the point: it tests
/// the configuration in force, not the scanner in the abstract.
fn own_canary(state: &AppState) -> Canary {
    let ov = state
        .live_overrides
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let disabled = state
        .disabled_stages
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let mut config = siphon_core::scanner::ScanConfig {
        disabled_patterns: Some(ov.disabled_patterns.clone()),
        pattern_field_overrides: Some(ov.pattern_field_overrides.clone()),
        runtime_patterns: Some(ov.runtime_patterns.clone()),
        pattern_regex_overrides: Some(ov.pattern_regex_overrides.clone()),
        list_bindings: Some(ov.list_bindings.clone()),
        max_unique_per_subcategory: Some(ov.unique_thresholds.clone()),
        ..Default::default()
    };
    if disabled.contains("min_confidence") {
        config.min_confidence = 0.0;
    }
    if disabled.contains("require_context") {
        config.require_context = false;
    }
    match siphon_core::scanner::scan_text_with_config(CANARY_TEXT, &config) {
        Ok(matches) => {
            let found: Vec<&str> = matches.iter().map(|m| m.category.as_str()).collect();
            judge_canary(&found)
        }
        // A scan that errors found nothing: that is a failed canary, and
        // the detail says why rather than leaving "missing everything".
        Err(e) => {
            tracing::warn!(error = %e, "own canary scan failed");
            judge_canary::<&str>(&[])
        }
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
// A reading: a value, its working, and the target it is judged against
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AxisState {
    /// Measured, and at or above target.
    Met,
    /// Measured, below target — or a condition that fails the axis
    /// outright, such as a sensor that is not running.
    Gap,
    /// Measured, and there is no target to judge against.
    NoTarget,
    /// Not measured. Absence, never a fake pass and never a fake fail.
    Unmeasured,
}

impl AxisState {
    /// Gap outranks Unmeasured outranks the rest: an overall built from
    /// these is the worst of its parts, never an average.
    fn rank(self) -> u8 {
        match self {
            AxisState::Gap => 3,
            AxisState::Unmeasured => 2,
            AxisState::NoTarget => 1,
            AxisState::Met => 0,
        }
    }
}

/// Worst of the parts. Empty → unmeasured.
pub fn worst(states: &[AxisState]) -> AxisState {
    states
        .iter()
        .copied()
        .max_by_key(|s| s.rank())
        .unwrap_or(AxisState::Unmeasured)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reading {
    /// numerator ÷ denominator. `None` when either is absent or the
    /// denominator is zero.
    pub value: Option<f64>,
    pub numerator: Option<i64>,
    pub denominator: Option<i64>,
    pub target: Option<f64>,
    /// value − target; negative is short.
    pub gap: Option<f64>,
    pub state: AxisState,
    /// What the fraction is, in words. A percentage without this is a score.
    pub basis: String,
}

pub fn reading(
    numerator: Option<i64>,
    denominator: Option<i64>,
    target: Option<f64>,
    basis: &str,
) -> Reading {
    let value = match (numerator, denominator) {
        (Some(n), Some(d)) if d > 0 => Some((n as f64 / d as f64).min(1.0)),
        _ => None,
    };
    let gap = match (value, target) {
        (Some(v), Some(t)) => Some(v - t),
        _ => None,
    };
    let state = match (value, target) {
        (None, _) => AxisState::Unmeasured,
        (Some(_), None) => AxisState::NoTarget,
        (Some(v), Some(t)) if v + 1e-9 >= t => AxisState::Met,
        _ => AxisState::Gap,
    };
    Reading {
        value,
        numerator,
        denominator,
        target,
        gap,
        state,
        basis: basis.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Operational: the third term of availability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalState {
    Ok,
    /// Running and doing less than its whole job: audit-only, fail-open,
    /// a stage disabled.
    Warn,
    /// The sensor predates posture reporting. Not "enforcing".
    NotReported,
}

impl OperationalState {
    fn rank(self) -> u8 {
        match self {
            OperationalState::Warn => 2,
            OperationalState::NotReported => 1,
            OperationalState::Ok => 0,
        }
    }
    fn axis(self) -> AxisState {
        match self {
            OperationalState::Ok => AxisState::Met,
            OperationalState::Warn => AxisState::Gap,
            OperationalState::NotReported => AxisState::Unmeasured,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OperationalReport {
    pub state: OperationalState,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<Posture>,
}

/// Is the sensor doing its whole job? Blocking is ok. Advisory is ok — the
/// caller acts, by design. Annotating is a warning, because enforcement is
/// then delegated to something this side cannot see: Postfix's rules on the
/// stamped header, the proxy's handling of a flagged body. Failing open is
/// a warning whatever else is true. Degraded is a warning that names why.
pub fn judge_posture(posture: Option<&Posture>) -> OperationalReport {
    let Some(p) = posture else {
        return OperationalReport {
            state: OperationalState::NotReported,
            detail: "posture not reported — this sensor predates it".into(),
            posture: None,
        };
    };
    let mut warns: Vec<String> = Vec::new();
    if let Some(d) = &p.degraded {
        warns.push(format!("degraded: {d}"));
    }
    if p.on_indeterminate == FailMode::Open {
        warns.push("fails open: traffic it could not inspect passes".into());
    }
    if p.on_finding == Enforcement::Annotate {
        warns.push(
            "annotates only: enforcement is delegated downstream and not verified here".into(),
        );
    }
    let mode = match (p.on_finding, p.on_indeterminate) {
        (Enforcement::Block, FailMode::Closed) => "blocks on a finding; fails closed",
        (Enforcement::Block, _) => "blocks on a finding",
        (Enforcement::Annotate, FailMode::Closed) => "annotates; fails closed",
        (Enforcement::Annotate, _) => "annotates",
        (Enforcement::Advisory, _) => "advisory by design: the caller acts on the findings",
    };
    OperationalReport {
        state: if warns.is_empty() {
            OperationalState::Ok
        } else {
            OperationalState::Warn
        },
        detail: if warns.is_empty() {
            mode.to_string()
        } else {
            format!("{mode}; {}", warns.join("; "))
        },
        posture: Some(p.clone()),
    }
}

/// Worst instance: one replica in audit-only is a sensor in audit-only.
pub fn worst_operational(reports: &[&OperationalReport]) -> OperationalReport {
    reports
        .iter()
        .max_by_key(|r| r.state.rank())
        .map(|r| (*r).clone())
        .unwrap_or_else(|| judge_posture(None))
}

// ---------------------------------------------------------------------------
// The four axes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Windowed<T> {
    pub h24: T,
    pub d7: T,
}

/// Deployed ∧ running ∧ operational. Deployed is the expected list
/// (`never_seen` names the gap); running is liveness plus the slot ratio;
/// operational is posture. A sensor that is stale or gone is a gap whatever
/// its ratio says, and a sensor whose posture is unknown is unmeasured
/// whatever its ratio says — the ratio alone is what the first cut of this
/// page reported, and the book's worked example is about why that lies.
#[derive(Debug, Clone, Serialize)]
pub struct AvailabilityAxis {
    pub running: Liveness,
    pub beats: Windowed<Reading>,
    pub operational: OperationalReport,
    pub state: AxisState,
}

pub fn availability_axis(
    running: Liveness,
    beats: Windowed<Reading>,
    operational: OperationalReport,
) -> AvailabilityAxis {
    let state = if running != Liveness::Healthy {
        AxisState::Gap
    } else {
        worst(&[beats.h24.state, operational.state.axis()])
    };
    AvailabilityAxis {
        running,
        beats,
        operational,
        state,
    }
}

/// Coverage at depth: of what reached this sensor, how much did it read?
/// Coverage against the environment — flows with no sensor at all — is not
/// knowable from inside a sensor, and the note says so rather than a number.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageAxis {
    pub at_depth: Windowed<Reading>,
    pub state: AxisState,
    pub note: &'static str,
}

pub const COVERAGE_NOTE: &str =
    "Coverage against the environment — mail flows, proxies and file paths \
     that have no sensor at all — cannot be measured from inside a sensor. \
     This is coverage at depth: of what reached the sensor, how much it read.";

pub fn coverage_axis(at_depth: Windowed<Reading>) -> CoverageAxis {
    CoverageAxis {
        state: at_depth.h24.state,
        at_depth,
        note: COVERAGE_NOTE,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CanaryLast {
    pub passed: bool,
    pub detail: String,
    pub at: DateTime<Utc>,
}

/// Recall and precision, separately, never F1. Recall is the canary — one
/// fixture through the deployed path, which proves the path and not the
/// recall, and the note says so. Precision is analyst verdicts.
#[derive(Debug, Clone, Serialize)]
pub struct EfficacyAxis {
    pub canary: Windowed<Reading>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_canary: Option<CanaryLast>,
    pub precision: Reading,
    pub verdicts: Option<Verdicts>,
    /// Worst of canary (24 h) and precision. They are reported separately;
    /// this is for the badge, not a composite.
    pub state: AxisState,
    pub note: &'static str,
}

pub const EFFICACY_NOTE: &str =
    "Canary recall is one fixture with two planted values, scanned through \
     the deployed path each heartbeat. It proves the path finds what it is \
     for; it does not prove recall is high. Adversarial recall is in the \
     program header.";

pub fn efficacy_axis(
    canary: Windowed<Reading>,
    last_canary: Option<CanaryLast>,
    precision: Reading,
    verdicts: Option<Verdicts>,
) -> EfficacyAxis {
    EfficacyAxis {
        state: worst(&[canary.h24.state, precision.state]),
        canary,
        last_canary,
        precision,
        verdicts,
        note: EFFICACY_NOTE,
    }
}

/// Six cost dimensions in the book; three are derivable from telemetry and
/// the axis names the ones that are not rather than reporting a third of
/// the cost as the cost.
#[derive(Debug, Clone, Serialize)]
pub struct EfficiencyAxis {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms_per_scan_24h: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms_per_mb_24h: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors_per_scan_24h: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_7d: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub false_positives_7d: Option<i64>,
    pub measured: Vec<&'static str>,
    pub unmeasured: Vec<&'static str>,
}

pub fn efficiency_axis(
    activity: &Activity,
    duration_ms_sum: Option<i64>,
    verdicts: Option<&Verdicts>,
) -> EfficiencyAxis {
    let scans = activity.scans.filter(|&s| s > 0);
    let ms_per_scan = match (scans, duration_ms_sum) {
        (Some(s), Some(d)) => Some(d as f64 / s as f64),
        _ => None,
    };
    let ms_per_mb = match (activity.bytes.filter(|&b| b > 0), duration_ms_sum) {
        (Some(b), Some(d)) => Some(d as f64 / (b as f64 / 1_048_576.0)),
        _ => None,
    };
    let errors_per_scan = match (scans, activity.errors) {
        (Some(s), Some(e)) => Some(e as f64 / s as f64),
        _ => None,
    };
    let mut measured = Vec::new();
    let mut unmeasured = vec!["license cost", "maintenance cost", "opportunity cost"];
    if ms_per_scan.is_some() {
        measured.push("compute");
    } else {
        unmeasured.insert(0, "compute");
    }
    if verdicts.is_some() {
        measured.push("operator attention");
        measured.push("false positives (count, not blast radius)");
    } else {
        unmeasured.insert(0, "operator attention");
        unmeasured.insert(1, "false-positive blast radius");
    }
    EfficiencyAxis {
        ms_per_scan_24h: ms_per_scan,
        ms_per_mb_24h: ms_per_mb,
        errors_per_scan_24h: errors_per_scan,
        reviewed_7d: verdicts.map(|v| v.reviewed),
        false_positives_7d: verdicts.map(|v| v.false_positives),
        measured,
        unmeasured,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Acee {
    pub availability: AvailabilityAxis,
    pub coverage: CoverageAxis,
    pub efficacy: EfficacyAxis,
    pub efficiency: EfficiencyAxis,
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
    /// Seen and passed without reading. Absent from a sensor that predates
    /// the count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unscanned: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_duration_ms: Option<f64>,
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
        sum(&mut self.unscanned, other.unscanned);
        sum(&mut self.bytes, other.bytes);
        // avg_duration recomputed by `finish` from duration_sum, kept private.
    }

    fn finish(&mut self, duration_ms_sum: Option<i64>) {
        self.avg_duration_ms = match (self.scans, duration_ms_sum) {
            (Some(s), Some(d)) if s > 0 => Some(d as f64 / s as f64),
            _ => None,
        };
    }

    /// scans ÷ (scans + unscanned): of what the sensor saw, what it read.
    fn coverage(&self, target: f64) -> Reading {
        let seen = match (self.scans, self.unscanned) {
            (Some(s), Some(u)) => Some(s + u),
            _ => None,
        };
        reading(
            self.scans,
            seen,
            Some(target),
            "items scanned ÷ items seen (scanned + passed unscanned)",
        )
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
    pub operational: OperationalReport,
    pub transport: TransportReport,
    pub activity: Windowed<Activity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_canary: Option<CanaryLast>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorReport {
    pub sensor: String,
    /// Best instance: one healthy replica is a sensor that is up.
    pub liveness: Liveness,
    pub acee: Acee,
    pub instances: Vec<InstanceReport>,
    /// Slots in which *any* instance beat.
    pub availability: Windowed<Ratio>,
    /// Worst instance.
    pub transport_overall: HopState,
    pub activity: Windowed<Activity>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// The latest evadex adversarial run: recall against a corpus built to
/// evade, program-wide because evadex drives the scanner, not a sensor.
#[derive(Debug, Clone, Serialize)]
pub struct Adversarial {
    pub recall: Reading,
    pub runs: i64,
    pub last_run_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProgramReport {
    /// Expected sensors that are healthy and operational ÷ expected. The
    /// matrix here is the expected list; a sensor never heard from counts
    /// against it.
    pub matrix_coverage: Reading,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adversarial: Option<Adversarial>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorsReport {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub objectives: Objectives,
    pub program: ProgramReport,
    pub sensors: Vec<SensorReport>,
    /// Sensors the deployment expects and has never heard from. Absence is
    /// a state: an unconfigured siphon-fs and a dead one look the same from
    /// here, and the console must say "never seen", not omit the row.
    pub never_seen: Vec<String>,
}

#[derive(Deserialize)]
pub struct SensorsQuery {}

struct Segment {
    sensor: String,
    instance: String,
    first_seen: DateTime<Utc>,
    slots_24h: i64,
    slots_7d: i64,
    activity_24h: Activity,
    duration_24h: Option<i64>,
    activity_7d: Activity,
    duration_7d: Option<i64>,
    canary_24h: (i64, i64),
    canary_7d: (i64, i64),
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
             db_mode, db_client_authenticated, last_scan_at, \
             posture_on_finding, posture_on_indeterminate, posture_degraded, \
             canary_passed, canary_detail \
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
             max(unscanned_total) FILTER (WHERE received_at > now() - interval '24 hours') - min(unscanned_total) FILTER (WHERE received_at > now() - interval '24 hours') AS unscanned_24h, \
             max(scans_total) - min(scans_total) AS scans_7d, \
             max(scans_with_findings) - min(scans_with_findings) AS swf_7d, \
             max(findings_total) - min(findings_total) AS findings_7d, \
             max(errors_total) - min(errors_total) AS errors_7d, \
             max(bytes_scanned) - min(bytes_scanned) AS bytes_7d, \
             max(duration_ms_sum) - min(duration_ms_sum) AS dur_7d, \
             max(unscanned_total) - min(unscanned_total) AS unscanned_7d, \
             count(*) FILTER (WHERE canary_passed AND received_at > now() - interval '24 hours') AS canary_pass_24h, \
             count(*) FILTER (WHERE canary_passed IS NOT NULL AND received_at > now() - interval '24 hours') AS canary_runs_24h, \
             count(*) FILTER (WHERE canary_passed) AS canary_pass_7d, \
             count(*) FILTER (WHERE canary_passed IS NOT NULL) AS canary_runs_7d \
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
                unscanned: r.get("unscanned_24h"),
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
                unscanned: r.get("unscanned_7d"),
                bytes: r.get("bytes_7d"),
                ..Default::default()
            };
            let d7: Option<i64> = r.get("dur_7d");
            a7.finish(d7);
            Segment {
                sensor: r.get("sensor"),
                instance: r.get("instance"),
                first_seen: r.get("first_seen"),
                slots_24h: r.get("slots_24h"),
                slots_7d: r.get("slots_7d"),
                activity_24h: a24,
                duration_24h: d24,
                activity_7d: a7,
                duration_7d: d7,
                canary_24h: (r.get("canary_pass_24h"), r.get("canary_runs_24h")),
                canary_7d: (r.get("canary_pass_7d"), r.get("canary_runs_7d")),
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

    // Q5: the latest evadex run. Optional data — a deployment that never
    // ran the bridge has none, and that is an absence, not a failure.
    let adversarial = match client
        .query_opt(
            "SELECT created_at, scanner_label, total_variants, detected, \
             (SELECT count(*) FROM evadex_runs) AS runs \
             FROM evadex_runs ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await
    {
        Ok(Some(r)) => {
            let variants: Option<i32> = r.get("total_variants");
            let detected: Option<i32> = r.get("detected");
            Some(Adversarial {
                recall: reading(
                    detected.map(i64::from),
                    variants.map(i64::from),
                    None,
                    "variants detected ÷ variants, latest evadex run",
                ),
                runs: r.get("runs"),
                last_run_at: r.get("created_at"),
                scanner_label: r.get("scanner_label"),
            })
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "sensors: evadex runs unreadable; reporting none");
            None
        }
    };

    let objectives = state.sensor_objectives.clone();

    // Assemble.
    let mut by_sensor: std::collections::BTreeMap<String, Vec<InstanceReport>> =
        std::collections::BTreeMap::new();
    let mut canary_by_instance: std::collections::HashMap<
        (String, String),
        ((i64, i64), (i64, i64)),
    > = std::collections::HashMap::new();
    let mut duration_by_instance: std::collections::HashMap<
        (String, String),
        (Option<i64>, Option<i64>),
    > = std::collections::HashMap::new();
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
        let mut c24 = (0, 0);
        let mut c7 = (0, 0);
        for s in &segs {
            a24.add(&s.activity_24h);
            a7.add(&s.activity_7d);
            if let Some(d) = s.duration_24h {
                d24 = Some(d24.unwrap_or(0) + d);
            }
            if let Some(d) = s.duration_7d {
                d7 = Some(d7.unwrap_or(0) + d);
            }
            c24 = (c24.0 + s.canary_24h.0, c24.1 + s.canary_24h.1);
            c7 = (c7.0 + s.canary_7d.0, c7.1 + s.canary_7d.1);
        }
        a24.finish(d24);
        a7.finish(d7);
        canary_by_instance.insert((sensor.clone(), instance.clone()), (c24, c7));
        duration_by_instance.insert((sensor.clone(), instance.clone()), (d24, d7));

        let posture = match (
            row.get::<_, Option<String>>("posture_on_finding"),
            row.get::<_, Option<String>>("posture_on_indeterminate"),
        ) {
            (Some(f), Some(i)) => match (Enforcement::parse(&f), FailMode::parse(&i)) {
                (Some(on_finding), Some(on_indeterminate)) => Some(Posture {
                    on_finding,
                    on_indeterminate,
                    degraded: row.get("posture_degraded"),
                }),
                _ => {
                    tracing::warn!(sensor = %sensor, on_finding = %f, on_indeterminate = %i,
                        "posture label this receiver does not know; treating as not reported");
                    None
                }
            },
            _ => None,
        };
        let operational = judge_posture(posture.as_ref());
        let last_canary = row
            .get::<_, Option<bool>>("canary_passed")
            .map(|passed| CanaryLast {
                passed,
                detail: row
                    .get::<_, Option<String>>("canary_detail")
                    .unwrap_or_default(),
                at: last_seen,
            });

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
            operational,
            transport,
            activity: Windowed { h24: a24, d7: a7 },
            last_canary,
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
        let mut d24 = None;
        let mut d7 = None;
        let mut c24 = (0, 0);
        let mut c7 = (0, 0);
        for i in &instances {
            a24.add(&i.activity.h24);
            a7.add(&i.activity.d7);
            let key = (sensor.clone(), i.instance.clone());
            if let Some((i24, i7)) = duration_by_instance.get(&key) {
                if let Some(d) = i24 {
                    d24 = Some(d24.unwrap_or(0) + d);
                }
                if let Some(d) = i7 {
                    d7 = Some(d7.unwrap_or(0) + d);
                }
            }
            if let Some((ic24, ic7)) = canary_by_instance.get(&key) {
                c24 = (c24.0 + ic24.0, c24.1 + ic24.1);
                c7 = (c7.0 + ic7.0, c7.1 + ic7.1);
            }
        }
        a24.finish(d24);
        a7.finish(d7);

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

        let liveness_best = instances
            .iter()
            .map(|i| i.liveness)
            .min_by_key(|l| match l {
                Liveness::Healthy => 0,
                Liveness::Stale => 1,
                Liveness::Gone => 2,
            })
            .unwrap_or(Liveness::Gone);
        let beats = Windowed {
            h24: availability(s24, interval, present_24h),
            d7: availability(s7, interval, present_7d),
        };
        let beat_reading = |r: &Ratio| {
            reading(
                r.ratio.map(|_| r.received),
                r.ratio.map(|_| r.expected),
                Some(objectives.availability),
                "heartbeat slots received ÷ slots expected",
            )
        };
        let operational =
            worst_operational(&instances.iter().map(|i| &i.operational).collect::<Vec<_>>());
        let canary_reading = |(pass, runs): (i64, i64)| {
            reading(
                (runs > 0).then_some(pass),
                (runs > 0).then_some(runs),
                Some(objectives.canary),
                "heartbeats whose canary found every planted category ÷ heartbeats that ran one",
            )
        };
        let precision = reading(
            verdicts.as_ref().map(|v| v.true_positives),
            verdicts
                .as_ref()
                .map(|v| v.true_positives + v.false_positives),
            Some(objectives.precision),
            "findings an analyst ruled true ÷ findings an analyst ruled, 7 d",
        );
        let acee = Acee {
            availability: availability_axis(
                liveness_best,
                Windowed {
                    h24: beat_reading(&beats.h24),
                    d7: beat_reading(&beats.d7),
                },
                operational,
            ),
            coverage: coverage_axis(Windowed {
                h24: a24.coverage(objectives.coverage),
                d7: a7.coverage(objectives.coverage),
            }),
            efficacy: efficacy_axis(
                Windowed {
                    h24: canary_reading(c24),
                    d7: canary_reading(c7),
                },
                instances
                    .iter()
                    .filter_map(|i| i.last_canary.clone())
                    .max_by_key(|c| c.at),
                precision,
                verdicts.clone(),
            ),
            efficiency: efficiency_axis(&a24, d24, verdicts.as_ref()),
        };

        sensors.push(SensorReport {
            liveness: liveness_best,
            acee,
            availability: beats,
            transport_overall: overall(
                &instances
                    .iter()
                    .map(|i| i.transport.overall)
                    .collect::<Vec<_>>(),
            ),
            activity: Windowed { h24: a24, d7: a7 },
            last_scan_at: instances.iter().filter_map(|i| i.last_scan_at).max(),
            instances,
            sensor,
        });
    }

    let never_seen: Vec<String> = objectives
        .expected
        .iter()
        .filter(|e| !sensors.iter().any(|s| &s.sensor == *e))
        .cloned()
        .collect();

    // Program-level coverage against the matrix: how many of the sensors
    // this deployment expects are up and doing their whole job.
    let operational_expected = objectives
        .expected
        .iter()
        .filter(|e| {
            sensors.iter().any(|s| {
                &s.sensor == *e
                    && s.liveness == Liveness::Healthy
                    && s.acee.availability.operational.state == OperationalState::Ok
            })
        })
        .count() as i64;
    let program = ProgramReport {
        matrix_coverage: reading(
            Some(operational_expected),
            Some(objectives.expected.len() as i64),
            Some(objectives.coverage),
            "expected sensors that are healthy and operational ÷ expected sensors",
        ),
        adversarial,
    };

    Ok(Json(SensorsReport {
        schema_version: SCHEMA_VERSION,
        generated_at: now,
        objectives,
        program,
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
        assert!((a.avg_duration_ms.unwrap() - 20.0).abs() < 1e-9);
        // Coverage at depth needs the unscanned count; a sensor that predates
        // it has no figure, not 100 %.
        assert_eq!(a.coverage(0.95).state, AxisState::Unmeasured);
        a.unscanned = Some(5);
        let c = a.coverage(0.95);
        assert!((c.value.unwrap() - 0.75).abs() < 1e-9);
        assert_eq!(c.state, AxisState::Gap);
        assert_eq!(c.denominator, Some(20));
    }

    #[test]
    fn a_reading_is_judged_against_its_target_and_never_fakes_a_value() {
        let met = reading(Some(99), Some(100), Some(0.99), "x");
        assert_eq!(met.state, AxisState::Met);
        assert!((met.gap.unwrap()).abs() < 1e-9);
        let gap = reading(Some(90), Some(100), Some(0.99), "x");
        assert_eq!(gap.state, AxisState::Gap);
        assert!((gap.gap.unwrap() + 0.09).abs() < 1e-9);
        assert_eq!(
            reading(None, Some(100), Some(0.5), "x").state,
            AxisState::Unmeasured
        );
        assert_eq!(
            reading(Some(0), Some(0), Some(0.5), "x").value,
            None,
            "0/0 is nothing, not 0 %"
        );
        let free = reading(Some(7), Some(10), None, "x");
        assert_eq!(free.state, AxisState::NoTarget);
        assert_eq!(free.gap, None);
        assert_eq!(
            reading(Some(120), Some(100), Some(1.0), "x").value,
            Some(1.0),
            "capped"
        );
    }

    #[test]
    fn overall_is_the_worst_axis_state_never_an_average() {
        assert_eq!(worst(&[AxisState::Met, AxisState::Met]), AxisState::Met);
        assert_eq!(
            worst(&[AxisState::Met, AxisState::Unmeasured]),
            AxisState::Unmeasured
        );
        assert_eq!(
            worst(&[AxisState::Unmeasured, AxisState::Gap]),
            AxisState::Gap
        );
        assert_eq!(
            worst(&[AxisState::NoTarget, AxisState::Met]),
            AxisState::NoTarget
        );
        assert_eq!(worst(&[]), AxisState::Unmeasured);
    }

    #[test]
    fn posture_judgement() {
        let p = |f, i, d: Option<&str>| Posture {
            on_finding: f,
            on_indeterminate: i,
            degraded: d.map(String::from),
        };
        assert_eq!(judge_posture(None).state, OperationalState::NotReported);
        assert_eq!(
            judge_posture(Some(&p(Enforcement::Block, FailMode::Closed, None))).state,
            OperationalState::Ok
        );
        assert_eq!(
            judge_posture(Some(&p(
                Enforcement::Advisory,
                FailMode::NotApplicable,
                None
            )))
            .state,
            OperationalState::Ok
        );
        // Annotate is delegated enforcement: a warning even when it fails closed.
        let smtp = judge_posture(Some(&p(Enforcement::Annotate, FailMode::Closed, None)));
        assert_eq!(smtp.state, OperationalState::Warn);
        assert!(smtp.detail.contains("delegated"));
        // Fail-open is a warning whatever else is true.
        let open = judge_posture(Some(&p(Enforcement::Block, FailMode::Open, None)));
        assert_eq!(open.state, OperationalState::Warn);
        assert!(open.detail.contains("fails open"));
        // Degraded names why.
        let deg = judge_posture(Some(&p(
            Enforcement::Advisory,
            FailMode::NotApplicable,
            Some("pipeline stages disabled: validation"),
        )));
        assert_eq!(deg.state, OperationalState::Warn);
        assert!(deg.detail.contains("validation"));
        // Worst instance wins; nothing reported is unmeasured, not ok.
        let w = worst_operational(&[&deg, &smtp, &judge_posture(None)]);
        assert_eq!(w.state, OperationalState::Warn);
        assert_eq!(worst_operational(&[]).state, OperationalState::NotReported);
    }

    #[test]
    fn availability_is_deployed_and_running_and_operational() {
        let beats = || Windowed {
            h24: reading(Some(2880), Some(2880), Some(0.99), "slots"),
            d7: reading(Some(20160), Some(20160), Some(0.99), "slots"),
        };
        let ok = judge_posture(Some(&Posture {
            on_finding: Enforcement::Block,
            on_indeterminate: FailMode::Closed,
            degraded: None,
        }));
        assert_eq!(
            availability_axis(Liveness::Healthy, beats(), ok.clone()).state,
            AxisState::Met
        );
        // A perfect slot ratio does not rescue a stale sensor…
        assert_eq!(
            availability_axis(Liveness::Stale, beats(), ok.clone()).state,
            AxisState::Gap
        );
        // …nor an audit-only one — that is the book's 99.5 % that was 76 %.
        let audit_only = judge_posture(Some(&Posture {
            on_finding: Enforcement::Annotate,
            on_indeterminate: FailMode::Open,
            degraded: None,
        }));
        assert_eq!(
            availability_axis(Liveness::Healthy, beats(), audit_only).state,
            AxisState::Gap
        );
        // …and an unknown posture leaves the axis unmeasured, not met.
        assert_eq!(
            availability_axis(Liveness::Healthy, beats(), judge_posture(None)).state,
            AxisState::Unmeasured
        );
    }

    #[test]
    fn efficiency_names_what_it_did_not_measure() {
        let a = Activity {
            scans: Some(1000),
            errors: Some(10),
            bytes: Some(2 * 1_048_576),
            ..Default::default()
        };
        let e = efficiency_axis(&a, Some(50_000), None);
        assert!((e.ms_per_scan_24h.unwrap() - 50.0).abs() < 1e-9);
        assert!((e.ms_per_mb_24h.unwrap() - 25_000.0).abs() < 1e-6);
        assert!((e.errors_per_scan_24h.unwrap() - 0.01).abs() < 1e-9);
        assert_eq!(e.measured, vec!["compute"]);
        assert!(e.unmeasured.contains(&"operator attention"));
        assert!(e.unmeasured.contains(&"license cost"));
        let none = efficiency_axis(&Activity::default(), None, None);
        assert!(none.measured.is_empty());
        assert!(none.unmeasured.contains(&"compute"));
    }

    #[test]
    fn objectives_default_and_refuse_bad_targets() {
        let d = Objectives::from_vars(|_| None).unwrap();
        assert_eq!(d, Objectives::defaults());
        assert_eq!(d.source, "defaults");
        assert_eq!(d.expected.len(), 4);
        let o = Objectives::from_vars(|n| match n {
            "EXPECTED" => Some(" siphon-api, siphon-smtp ,".into()),
            "TARGET_PRECISION" => Some("0.9".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(o.expected, vec!["siphon-api", "siphon-smtp"]);
        assert!((o.precision - 0.9).abs() < 1e-9);
        assert!(
            (o.availability - 0.99).abs() < 1e-9,
            "untouched targets keep their default"
        );
        assert_eq!(
            o.source,
            "SIPHON_SENSORS_EXPECTED, SIPHON_SENSORS_TARGET_PRECISION"
        );
        assert!(Objectives::from_vars(|n| (n == "TARGET_CANARY").then(|| "110%".into())).is_err());
        assert!(Objectives::from_vars(|n| (n == "TARGET_COVERAGE").then(|| "1.5".into())).is_err());
        assert!(Objectives::from_vars(|n| (n == "EXPECTED").then(|| " , ".into())).is_err());
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
            posture: None,
            canary: None,
        };
        assert!(validate(&hb, now).is_ok());
        hb.posture = Some(Posture {
            on_finding: Enforcement::Block,
            on_indeterminate: FailMode::Closed,
            degraded: Some(String::new()),
        });
        assert!(
            validate(&hb, now).is_err(),
            "an empty degraded reason is a bug, not a state"
        );
        hb.posture = None;
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
