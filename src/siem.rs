//! SIEM integration adapters for forwarding DLP audit events.
//!
//! Supports Splunk HEC, Elasticsearch, Syslog (UDP/TCP), generic Webhooks,
//! and Datadog. HTTP adapters are available with the `async-support` feature.

use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for SIEM adapters — all must be thread-safe.
pub trait SIEMAdapter: Send + Sync {
    /// Send an event dict to the SIEM platform.
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String>;
}

/// Enrich an event with timestamp and hostname if not present.
pub fn enrich_event(
    event: &HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    let mut enriched = event.clone();
    enriched
        .entry("timestamp".to_string())
        .or_insert_with(|| serde_json::Value::String(iso8601_now()));
    enriched
        .entry("host".to_string())
        .or_insert_with(|| serde_json::Value::String(hostname()));
    enriched
        .entry("source".to_string())
        .or_insert_with(|| serde_json::Value::String("dlpscan".to_string()));
    enriched
}

// ---------------------------------------------------------------------------
// Syslog Adapter (always available, no HTTP deps)
// ---------------------------------------------------------------------------

/// Syslog adapter — sends JSON events over UDP or TCP.
pub struct SyslogAdapter {
    address: String,
    port: u16,
    facility: u8,
    protocol: String,
    lock: Mutex<()>,
}

impl SyslogAdapter {
    pub fn new() -> Self {
        Self {
            address: "localhost".to_string(),
            port: 514,
            facility: 16, // local0
            protocol: "udp".to_string(),
            lock: Mutex::new(()),
        }
    }

    pub fn with_address(mut self, addr: &str, port: u16) -> Self {
        self.address = addr.to_string();
        self.port = port;
        self
    }

    pub fn with_facility(mut self, facility: &str) -> Self {
        self.facility = match facility {
            "kern" => 0,
            "user" => 1,
            "mail" => 2,
            "daemon" => 3,
            "auth" => 4,
            "syslog" => 5,
            "lpr" => 6,
            "news" => 7,
            "uucp" => 8,
            "cron" => 9,
            "local0" => 16,
            "local1" => 17,
            "local2" => 18,
            "local3" => 19,
            "local4" => 20,
            "local5" => 21,
            "local6" => 22,
            "local7" => 23,
            _ => 16,
        };
        self
    }

    pub fn with_protocol(mut self, proto: &str) -> Self {
        self.protocol = proto.to_lowercase();
        self
    }
}

impl Default for SyslogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SIEMAdapter for SyslogAdapter {
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        let _lock = self.lock.lock().map_err(|e| e.to_string())?;
        let enriched = enrich_event(event);
        let json = serde_json::to_string(&enriched).map_err(|e| e.to_string())?;

        // RFC 5424 priority = facility * 8 + severity (6 = info)
        let priority = self.facility * 8 + 6;
        let msg = format!("<{priority}>1 {} {} dlpscan - - - {json}", iso8601_now(), hostname());

        let addr = format!("{}:{}", self.address, self.port);

        if self.protocol == "tcp" {
            use std::io::Write;
            let mut stream =
                std::net::TcpStream::connect(&addr).map_err(|e| e.to_string())?;
            stream
                .write_all(msg.as_bytes())
                .map_err(|e| e.to_string())?;
        } else {
            let socket =
                std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            socket
                .send_to(msg.as_bytes(), &addr)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HTTP-based adapters (require async-support feature for reqwest)
// ---------------------------------------------------------------------------

/// Splunk HTTP Event Collector adapter.
pub struct SplunkHECAdapter {
    pub(crate) url: String,
    pub(crate) token: String,
    pub(crate) source: String,
    pub(crate) sourcetype: String,
    lock: Mutex<()>,
}

impl SplunkHECAdapter {
    pub fn new(url: &str, token: &str) -> Self {
        Self {
            url: url.to_string(),
            token: token.to_string(),
            source: "dlpscan".to_string(),
            sourcetype: "_json".to_string(),
            lock: Mutex::new(()),
        }
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source = source.to_string();
        self
    }

    pub fn with_sourcetype(mut self, sourcetype: &str) -> Self {
        self.sourcetype = sourcetype.to_string();
        self
    }
}

impl SIEMAdapter for SplunkHECAdapter {
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        let _lock = self.lock.lock().map_err(|e| e.to_string())?;
        let enriched = enrich_event(event);
        let payload = serde_json::json!({
            "event": enriched,
            "source": self.source,
            "sourcetype": self.sourcetype,
        });
        let body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let url = format!("{}/services/collector/event", self.url.trim_end_matches('/'));
        let headers = vec![
            ("Authorization".to_string(), format!("Splunk {}", self.token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        http_post_sync(&url, &body, &headers).map(|_| ())
    }
}

/// Elasticsearch adapter.
pub struct ElasticsearchAdapter {
    pub url: String,
    pub index: String,
    pub api_key: Option<String>,
    lock: Mutex<()>,
}

impl ElasticsearchAdapter {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            index: "dlpscan-events".to_string(),
            api_key: None,
            lock: Mutex::new(()),
        }
    }

    pub fn with_index(mut self, index: &str) -> Self {
        self.index = index.to_string();
        self
    }

    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }
}

impl SIEMAdapter for ElasticsearchAdapter {
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        let _lock = self.lock.lock().map_err(|e| e.to_string())?;
        let enriched = enrich_event(event);
        let body = serde_json::to_vec(&enriched).map_err(|e| e.to_string())?;
        let url = format!(
            "{}/{}/_doc",
            self.url.trim_end_matches('/'),
            self.index
        );
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if let Some(ref key) = self.api_key {
            headers.push(("Authorization".to_string(), format!("ApiKey {key}")));
        }
        http_post_sync(&url, &body, &headers).map(|_| ())
    }
}

/// Generic webhook SIEM adapter.
pub struct WebhookSIEMAdapter {
    pub url: String,
    pub headers: HashMap<String, String>,
    lock: Mutex<()>,
}

impl WebhookSIEMAdapter {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            headers: HashMap::new(),
            lock: Mutex::new(()),
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }
}

impl SIEMAdapter for WebhookSIEMAdapter {
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        let _lock = self.lock.lock().map_err(|e| e.to_string())?;
        let enriched = enrich_event(event);
        let body = serde_json::to_vec(&enriched).map_err(|e| e.to_string())?;
        let headers: Vec<(String, String)> = self.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        http_post_sync(&self.url, &body, &headers).map(|_| ())
    }
}

/// Datadog Logs adapter.
pub struct DatadogAdapter {
    pub api_key: String,
    pub site: String,
    pub source: String,
    pub service: String,
    lock: Mutex<()>,
}

impl DatadogAdapter {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            site: "datadoghq.com".to_string(),
            source: "dlpscan".to_string(),
            service: "dlpscan".to_string(),
            lock: Mutex::new(()),
        }
    }

    pub fn with_site(mut self, site: &str) -> Self {
        self.site = site.to_string();
        self
    }

    pub fn with_service(mut self, service: &str) -> Self {
        self.service = service.to_string();
        self
    }
}

impl SIEMAdapter for DatadogAdapter {
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        let _lock = self.lock.lock().map_err(|e| e.to_string())?;
        let enriched = enrich_event(event);
        let payload = serde_json::json!([{
            "ddsource": self.source,
            "ddtags": "",
            "hostname": hostname(),
            "message": enriched,
            "service": self.service,
        }]);
        let body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let url = format!(
            "https://http-intake.logs.{}/api/v2/logs",
            self.site
        );
        let headers = vec![
            ("DD-API-KEY".to_string(), self.api_key.clone()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        http_post_sync(&url, &body, &headers).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create a SIEM adapter from environment variables.
///
/// - `DLPSCAN_SIEM_TYPE`: splunk, elasticsearch, syslog, webhook, datadog
/// - Splunk: `DLPSCAN_SIEM_URL`, `DLPSCAN_SIEM_TOKEN`
/// - Elasticsearch: `DLPSCAN_SIEM_URL`, `DLPSCAN_SIEM_INDEX`, `DLPSCAN_SIEM_API_KEY`
/// - Syslog: `DLPSCAN_SIEM_HOST`, `DLPSCAN_SIEM_PORT`, `DLPSCAN_SIEM_FACILITY`, `DLPSCAN_SIEM_PROTOCOL`
/// - Webhook: `DLPSCAN_SIEM_URL`
/// - Datadog: `DLPSCAN_SIEM_API_KEY`, `DLPSCAN_SIEM_SITE`
pub fn create_siem_from_env() -> Option<Box<dyn SIEMAdapter>> {
    let siem_type = std::env::var("DLPSCAN_SIEM_TYPE").ok()?;

    match siem_type.to_lowercase().as_str() {
        "splunk" => {
            let url = std::env::var("DLPSCAN_SIEM_URL").ok()?;
            let token = std::env::var("DLPSCAN_SIEM_TOKEN").ok()?;
            let mut adapter = SplunkHECAdapter::new(&url, &token);
            if let Ok(source) = std::env::var("DLPSCAN_SIEM_SOURCE") {
                adapter = adapter.with_source(&source);
            }
            Some(Box::new(adapter))
        }
        "elasticsearch" => {
            let url = std::env::var("DLPSCAN_SIEM_URL").ok()?;
            let mut adapter = ElasticsearchAdapter::new(&url);
            if let Ok(index) = std::env::var("DLPSCAN_SIEM_INDEX") {
                adapter = adapter.with_index(&index);
            }
            if let Ok(key) = std::env::var("DLPSCAN_SIEM_API_KEY") {
                adapter = adapter.with_api_key(&key);
            }
            Some(Box::new(adapter))
        }
        "syslog" => {
            let mut adapter = SyslogAdapter::new();
            if let (Ok(host), Ok(port)) = (
                std::env::var("DLPSCAN_SIEM_HOST"),
                std::env::var("DLPSCAN_SIEM_PORT"),
            ) {
                if let Ok(p) = port.parse() {
                    adapter = adapter.with_address(&host, p);
                }
            }
            if let Ok(facility) = std::env::var("DLPSCAN_SIEM_FACILITY") {
                adapter = adapter.with_facility(&facility);
            }
            if let Ok(proto) = std::env::var("DLPSCAN_SIEM_PROTOCOL") {
                adapter = adapter.with_protocol(&proto);
            }
            Some(Box::new(adapter))
        }
        "webhook" => {
            let url = std::env::var("DLPSCAN_SIEM_URL").ok()?;
            Some(Box::new(WebhookSIEMAdapter::new(&url)))
        }
        "datadog" => {
            let api_key = std::env::var("DLPSCAN_SIEM_API_KEY").ok()?;
            let mut adapter = DatadogAdapter::new(&api_key);
            if let Ok(site) = std::env::var("DLPSCAN_SIEM_SITE") {
                adapter = adapter.with_site(&site);
            }
            Some(Box::new(adapter))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO 8601 without chrono
    let (s, m, h, day, mon, year) = epoch_to_datetime(secs);
    format!("{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn epoch_to_datetime(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = epoch % 60;
    let m = (epoch / 60) % 60;
    let h = (epoch / 3600) % 24;
    let mut days = epoch / 86400;
    let mut year = 1970u64;
    loop {
        let yd = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mon = 0u64;
    for md in mdays {
        if days < md {
            break;
        }
        days -= md;
        mon += 1;
    }
    (s, m, h, days + 1, mon + 1, year)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse a URL into (scheme, host, port, path). Returns `Err` for unsupported schemes.
fn parse_siem_url(url: &str) -> Result<(&str, &str, u16, &str), String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!(
            "Unsupported URL scheme (must be http:// or https://): {}",
            crate::webhooks::sanitize_url(url)
        ));
    };

    // Strip userinfo if present
    let after_userinfo = if let Some(at) = rest.find('@') {
        let slash = rest.find('/').unwrap_or(rest.len());
        if at < slash { &rest[at + 1..] } else { rest }
    } else {
        rest
    };

    let (host_port, path) = after_userinfo
        .find('/')
        .map(|i| (&after_userinfo[..i], &after_userinfo[i..]))
        .unwrap_or((after_userinfo, "/"));

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if let Some(i) = host_port.find(':') {
        (
            &host_port[..i],
            host_port[i + 1..].parse::<u16>().unwrap_or(default_port),
        )
    } else {
        (host_port, default_port)
    };

    Ok((scheme, host, port, path))
}

/// Validate that a SIEM endpoint URL has a supported scheme.
fn validate_siem_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!(
            "SIEM URL must use http:// or https:// scheme (got: {})",
            crate::webhooks::sanitize_url(url)
        ));
    }
    Ok(())
}

/// Synchronous HTTP POST supporting both `http://` and `https://` URL parsing.
///
/// For `http://` URLs, uses a raw `TcpStream`.
/// For `https://` URLs, returns an error directing users to enable the
/// `async-support` feature (TLS requires additional dependencies).
fn http_post_sync(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> Result<u16, String> {
    use std::io::{Read, Write};

    let (scheme, host, port, path) = parse_siem_url(url)?;

    if scheme == "https" {
        return Err(format!(
            "HTTPS URLs require the `async-support` feature for TLS. \
             Cannot connect to {} over plaintext.",
            crate::webhooks::sanitize_url(url)
        ));
    }

    let addr = format!("{host}:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| e.to_string())?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&response[..n]);

    // Parse "HTTP/1.1 200 OK"
    let status = resp
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if (200..300).contains(&status) {
        Ok(status)
    } else {
        Err(format!("HTTP {status}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrich_event() {
        let event = HashMap::new();
        let enriched = enrich_event(&event);
        assert!(enriched.contains_key("timestamp"));
        assert!(enriched.contains_key("host"));
        assert!(enriched.contains_key("source"));
    }

    #[test]
    fn test_syslog_adapter_creation() {
        let adapter = SyslogAdapter::new()
            .with_address("10.0.0.1", 1514)
            .with_facility("local3")
            .with_protocol("tcp");
        assert_eq!(adapter.address, "10.0.0.1");
        assert_eq!(adapter.port, 1514);
        assert_eq!(adapter.facility, 19);
        assert_eq!(adapter.protocol, "tcp");
    }

    #[test]
    fn test_create_siem_from_env_none() {
        // No env vars set → returns None
        assert!(create_siem_from_env().is_none());
    }

    #[test]
    fn test_epoch_to_datetime() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let (s, m, h, d, mon, y) = epoch_to_datetime(1704067200);
        assert_eq!(y, 2024);
        assert_eq!(mon, 1);
        assert_eq!(d, 1);
        assert_eq!(h, 0);
        assert_eq!(m, 0);
        assert_eq!(s, 0);
    }
}
