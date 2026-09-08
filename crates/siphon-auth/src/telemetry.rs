//! What a sensor says about itself, and how it says it.
//!
//! A sensor is a detector — siphon-fs, siphon-icap, siphon-smtp, siphon-api's
//! own text channel. On an interval it reports its identity, its transport
//! state and its counters to `POST /v1/sensors/heartbeat`, authenticating
//! with a key that holds the `Sensor` role and presenting its own listener
//! certificate as a client certificate, because siphon-api requires one.
//!
//! The wire shape lives here so the reporter and the receiver cannot drift;
//! the HTTP client lives behind the `telemetry-client` feature so siphon-api,
//! which only receives, does not link an HTTP client it never uses.
//!
//! # Counters are cumulative
//!
//! Every counter is "since this instance started". The receiver derives a
//! window's activity from the difference between two heartbeats, and a
//! restart is visible as a new `started_at` rather than as a counter that
//! went backwards. `None` means "this sensor does not count that" — a milter
//! has no bytes-scanned figure worth the name — and is reported as absent,
//! never as zero.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The default reporting cadence, and what the receiver assumes when judging
/// staleness: three missed intervals is stale.
pub const DEFAULT_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerState {
    pub tls: bool,
    /// Client certificates required. `tls` without this is encryption
    /// without authentication.
    pub mtls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseState {
    /// `disable` / `require` / `mtls`, as configured.
    pub mode: String,
    pub client_authenticated: bool,
}

/// Which hops this sensor has, and how each is secured. A hop the sensor
/// does not have is `None`, which the receiver renders as "n/a", not "off".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener: Option<ListenerState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scans_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scans_with_findings: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_scanned: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms_sum: Option<u64>,
}

/// One heartbeat, as sent and as received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// `siphon-fs`, `siphon-icap`, `siphon-smtp`, `siphon-api`.
    pub sensor: String,
    /// Pod id — distinguishes replicas of one sensor.
    pub instance: String,
    pub version: String,
    pub started_at: DateTime<Utc>,
    pub interval_secs: u64,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub counters: Counters,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// What to call this instance. The pod name under Kubernetes (`HOSTNAME`),
/// which is what an operator will look for; a random id otherwise, so two
/// compose replicas of one sensor do not collapse into one row.
pub fn instance_id() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim();
        if !h.is_empty() && h.len() <= 128 {
            return h.to_string();
        }
    }
    let mut buf = [0u8; 6];
    getrandom::fill(&mut buf).expect("operating system randomness is unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lock-free counters a sensor bumps on its hot path and snapshots once an
/// interval. `record_scan` is the one call most sensors need.
#[derive(Debug, Default)]
pub struct SensorCounters {
    scans_total: AtomicU64,
    scans_with_findings: AtomicU64,
    findings_total: AtomicU64,
    errors_total: AtomicU64,
    bytes_scanned: AtomicU64,
    duration_ms_sum: AtomicU64,
    /// Unix seconds; 0 = never.
    last_scan_at: AtomicI64,
}

impl SensorCounters {
    pub fn new() -> Self {
        Self::default()
    }

    /// One completed scan: how many findings it produced, how much it read,
    /// how long it took.
    pub fn record_scan(&self, findings: u64, bytes: u64, duration_ms: u64) {
        self.scans_total.fetch_add(1, Ordering::Relaxed);
        if findings > 0 {
            self.scans_with_findings.fetch_add(1, Ordering::Relaxed);
        }
        self.findings_total.fetch_add(findings, Ordering::Relaxed);
        self.bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
        self.duration_ms_sum
            .fetch_add(duration_ms, Ordering::Relaxed);
        self.last_scan_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);
    }

    /// A scan that did not complete — extraction failure, timeout, refused
    /// input. Counted separately because "scanned nothing" and "scanned and
    /// found nothing" are different facts.
    pub fn record_error(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Counters {
        Counters {
            scans_total: Some(self.scans_total.load(Ordering::Relaxed)),
            scans_with_findings: Some(self.scans_with_findings.load(Ordering::Relaxed)),
            findings_total: Some(self.findings_total.load(Ordering::Relaxed)),
            errors_total: Some(self.errors_total.load(Ordering::Relaxed)),
            bytes_scanned: Some(self.bytes_scanned.load(Ordering::Relaxed)),
            duration_ms_sum: Some(self.duration_ms_sum.load(Ordering::Relaxed)),
        }
    }

    pub fn last_scan_at(&self) -> Option<DateTime<Utc>> {
        match self.last_scan_at.load(Ordering::Relaxed) {
            0 => None,
            secs => DateTime::from_timestamp(secs, 0),
        }
    }
}

/// The reporting side: an HTTP client that posts a heartbeat on an interval
/// over mutual TLS.
#[cfg(feature = "telemetry-client")]
pub mod reporter {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    /// `SIPHON_TELEMETRY_URL`, `_KEY`, `_CA`, `_CLIENT_CERT`, `_CLIENT_KEY`,
    /// `_INTERVAL_SECS`.
    #[derive(Debug, Clone)]
    pub struct Settings {
        /// siphon-api's base URL, e.g. `https://siphon-api:8080`.
        pub url: String,
        /// A key holding the `Sensor` role.
        pub key: String,
        pub ca: Option<PathBuf>,
        pub client_cert: Option<PathBuf>,
        pub client_key: Option<PathBuf>,
        pub interval: Duration,
    }

    impl Settings {
        /// `Ok(None)` when telemetry is not configured — a supported
        /// deployment, not a degraded one; the receiver then shows the
        /// sensor as never seen, which is the truth. An error when it is
        /// half configured.
        pub fn from_env() -> Result<Option<Self>, String> {
            let var = |name: &str| {
                std::env::var(format!("SIPHON_TELEMETRY_{name}"))
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            };
            let (url, key) = match (var("URL"), var("KEY")) {
                (Some(u), Some(k)) => (u, k),
                (None, None) => return Ok(None),
                (Some(_), None) => {
                    return Err(
                        "SIPHON_TELEMETRY_URL is set but SIPHON_TELEMETRY_KEY is not".into(),
                    )
                }
                (None, Some(_)) => {
                    return Err(
                        "SIPHON_TELEMETRY_KEY is set but SIPHON_TELEMETRY_URL is not".into(),
                    )
                }
            };
            let (client_cert, client_key) = match (var("CLIENT_CERT"), var("CLIENT_KEY")) {
                (Some(c), Some(k)) => (Some(PathBuf::from(c)), Some(PathBuf::from(k))),
                (None, None) => (None, None),
                _ => {
                    return Err(
                        "SIPHON_TELEMETRY_CLIENT_CERT and SIPHON_TELEMETRY_CLIENT_KEY must be set together"
                            .into(),
                    )
                }
            };
            let interval = var("INTERVAL_SECS")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|s| (5..=3600).contains(s))
                .unwrap_or(DEFAULT_INTERVAL_SECS);
            Ok(Some(Self {
                url,
                key,
                ca: var("CA").map(PathBuf::from),
                client_cert,
                client_key,
                interval: Duration::from_secs(interval),
            }))
        }
    }

    /// Everything about the sensor that does not change between beats.
    #[derive(Debug, Clone)]
    pub struct Identity {
        pub sensor: &'static str,
        pub instance: String,
        pub version: &'static str,
        pub started_at: DateTime<Utc>,
        pub transport: Transport,
    }

    pub struct Reporter {
        client: reqwest::Client,
        endpoint: String,
        key: String,
        interval: Duration,
        identity: Identity,
        counters: Arc<SensorCounters>,
    }

    impl Reporter {
        pub fn new(
            settings: &Settings,
            identity: Identity,
            counters: Arc<SensorCounters>,
        ) -> Result<Self, String> {
            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(10))
                // The organisation's PKI is the only PKI: a heartbeat must not
                // be deliverable to a public-CA impostor at the same name.
                .tls_built_in_root_certs(false);
            if let Some(ca) = &settings.ca {
                let pem = std::fs::read(ca)
                    .map_err(|e| format!("reading SIPHON_TELEMETRY_CA {}: {e}", ca.display()))?;
                for cert in reqwest::Certificate::from_pem_bundle(&pem)
                    .map_err(|e| format!("SIPHON_TELEMETRY_CA {}: {e}", ca.display()))?
                {
                    builder = builder.add_root_certificate(cert);
                }
            } else {
                builder = builder.tls_built_in_root_certs(true);
            }
            if let (Some(cert), Some(key)) = (&settings.client_cert, &settings.client_key) {
                let mut pem = std::fs::read(cert).map_err(|e| {
                    format!(
                        "reading SIPHON_TELEMETRY_CLIENT_CERT {}: {e}",
                        cert.display()
                    )
                })?;
                pem.push(b'\n');
                pem.extend(std::fs::read(key).map_err(|e| {
                    format!("reading SIPHON_TELEMETRY_CLIENT_KEY {}: {e}", key.display())
                })?);
                let id = reqwest::Identity::from_pem(&pem)
                    .map_err(|e| format!("telemetry client identity: {e}"))?;
                builder = builder.identity(id);
            }
            let client = builder
                .build()
                .map_err(|e| format!("building telemetry client: {e}"))?;
            Ok(Self {
                client,
                endpoint: format!(
                    "{}/v1/sensors/heartbeat",
                    settings.url.trim_end_matches('/')
                ),
                key: settings.key.clone(),
                interval: settings.interval,
                identity,
                counters,
            })
        }

        fn heartbeat(&self) -> Heartbeat {
            Heartbeat {
                sensor: self.identity.sensor.to_string(),
                instance: self.identity.instance.clone(),
                version: self.identity.version.to_string(),
                started_at: self.identity.started_at,
                interval_secs: self.interval.as_secs(),
                transport: self.identity.transport.clone(),
                counters: self.counters.snapshot(),
                last_scan_at: self.counters.last_scan_at(),
            }
        }

        /// Send one heartbeat. Errors are the caller's to log; the loop below
        /// logs the first failure of an outage and the recovery, not every beat.
        pub async fn send(&self) -> Result<(), String> {
            let resp = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.key)
                .json(&self.heartbeat())
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                let body = resp.text().await.unwrap_or_default();
                Err(format!(
                    "{status}: {}",
                    body.chars().take(200).collect::<String>()
                ))
            }
        }

        /// Beat forever. Runs as its own task; nothing on the scan path waits
        /// for it.
        pub async fn run(self) {
            let mut failing = false;
            // First beat promptly, so a fresh pod shows up within seconds
            // rather than after a full interval.
            let mut wait = Duration::from_secs(2);
            loop {
                tokio::time::sleep(wait).await;
                wait = self.interval;
                match self.send().await {
                    Ok(()) => {
                        if failing {
                            tracing::info!(sensor = self.identity.sensor, "telemetry recovered");
                            failing = false;
                        }
                    }
                    Err(e) => {
                        if !failing {
                            tracing::warn!(
                                sensor = self.identity.sensor,
                                endpoint = %self.endpoint,
                                error = %e,
                                "telemetry heartbeat failed — the console will show this sensor as stale; scanning is unaffected"
                            );
                            failing = true;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_cumulative_and_absent_is_not_zero() {
        let c = SensorCounters::new();
        assert_eq!(c.last_scan_at(), None, "never scanned is None, not epoch");
        c.record_scan(0, 100, 5);
        c.record_scan(3, 200, 7);
        c.record_error();
        let s = c.snapshot();
        assert_eq!(s.scans_total, Some(2));
        assert_eq!(s.scans_with_findings, Some(1));
        assert_eq!(s.findings_total, Some(3));
        assert_eq!(s.errors_total, Some(1));
        assert_eq!(s.bytes_scanned, Some(300));
        assert_eq!(s.duration_ms_sum, Some(12));
        assert!(c.last_scan_at().is_some());
    }

    #[test]
    fn a_heartbeat_round_trips_with_absent_hops_absent() {
        // The milter has no listener TLS; siphon-icap has no database. Those
        // must arrive as missing, not as {tls:false}.
        let hb = Heartbeat {
            sensor: "siphon-smtp".into(),
            instance: "pod-1".into(),
            version: "0.2.0".into(),
            started_at: Utc::now(),
            interval_secs: 30,
            transport: Transport {
                listener: None,
                database: Some(DatabaseState {
                    mode: "mtls".into(),
                    client_authenticated: true,
                }),
            },
            counters: Counters {
                scans_total: Some(4),
                ..Default::default()
            },
            last_scan_at: None,
        };
        let json = serde_json::to_string(&hb).unwrap();
        assert!(!json.contains("\"listener\""));
        assert!(!json.contains("bytes_scanned"));
        let back: Heartbeat = serde_json::from_str(&json).unwrap();
        assert_eq!(back.transport, hb.transport);
        assert_eq!(back.counters, hb.counters);
    }
}
