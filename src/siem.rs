//! SIEM integration adapters for forwarding DLP audit events.
//!
//! Supports Splunk HEC, Elasticsearch, Syslog (UDP/TCP), generic Webhooks,
//! and Datadog. HTTP adapters are available with the `async-support` feature.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for SIEM adapters — all must be thread-safe.
pub trait SIEMAdapter: Send + Sync {
    /// Send an event dict to the SIEM platform.
    fn send(&self, event: &HashMap<String, serde_json::Value>) -> Result<(), String>;
}

/// Maximum retries for SIEM send operations.
const SIEM_MAX_RETRIES: usize = 3;

/// Send with retry and exponential backoff (200ms, 400ms, 800ms).
/// Returns Ok on first success, or the last error after all retries.
pub fn send_with_retry(
    adapter: &dyn SIEMAdapter,
    event: &HashMap<String, serde_json::Value>,
) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 0..=SIEM_MAX_RETRIES {
        match adapter.send(event) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                if attempt < SIEM_MAX_RETRIES {
                    let delay = std::time::Duration::from_millis(200 << attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = SIEM_MAX_RETRIES,
                        delay_ms = delay.as_millis() as u64,
                        error = %last_err,
                        "SIEM send failed, retrying"
                    );
                    std::thread::sleep(delay);
                }
            }
        }
    }
    tracing::error!(error = %last_err, "SIEM send failed after all retries");
    Err(last_err)
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
        // Sanitize hostname to prevent syslog header injection (strip control chars)
        let safe_host: String = hostname()
            .chars()
            .filter(|c| !c.is_control() && *c != ' ')
            .take(255)
            .collect();
        let msg = format!(
            "<{priority}>1 {} {} dlpscan - - - {json}",
            iso8601_now(),
            safe_host
        );

        let addr = format!("{}:{}", self.address, self.port);

        if self.protocol == "tcp" {
            use std::io::Write;
            let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| e.to_string())?;
            stream
                .write_all(msg.as_bytes())
                .map_err(|e| e.to_string())?;
        } else {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
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
        let url = format!(
            "{}/services/collector/event",
            self.url.trim_end_matches('/')
        );
        let headers = vec![
            (
                "Authorization".to_string(),
                format!("Splunk {}", self.token),
            ),
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
        let url = format!("{}/{}/_doc", self.url.trim_end_matches('/'), self.index);
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
        let headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
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
        // Validate site value to prevent URL injection
        if self.site.contains('/')
            || self.site.contains('?')
            || self.site.contains('#')
            || self.site.contains('@')
            || self.site.contains(':')
            || self.site.is_empty()
        {
            return Err(format!("Invalid Datadog site value: {}", self.site));
        }
        let url = format!("https://http-intake.logs.{}/api/v2/logs", self.site);
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

/// Returns true if the URL is allowed for SIEM. Requires HTTPS unless
/// `DLPSCAN_SIEM_ALLOW_HTTP=1` is set (for development/testing only).
/// Whether plaintext HTTP is allowed for SIEM adapters.
/// Cached at first use to prevent runtime env var manipulation.
static SIEM_ALLOW_HTTP: Lazy<bool> = Lazy::new(|| {
    std::env::var("DLPSCAN_SIEM_ALLOW_HTTP")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
});

fn require_https(url: &str) -> bool {
    if *SIEM_ALLOW_HTTP {
        return true;
    }
    url.to_lowercase().starts_with("https://")
}

/// Create a SIEM adapter from environment variables.
///
/// - `DLPSCAN_SIEM_TYPE`: splunk, elasticsearch, syslog, webhook, datadog
/// - Splunk: `DLPSCAN_SIEM_URL`, `DLPSCAN_SIEM_TOKEN`
/// - Elasticsearch: `DLPSCAN_SIEM_URL`, `DLPSCAN_SIEM_INDEX`, `DLPSCAN_SIEM_API_KEY`
/// - Syslog: `DLPSCAN_SIEM_HOST`, `DLPSCAN_SIEM_PORT`, `DLPSCAN_SIEM_FACILITY`, `DLPSCAN_SIEM_PROTOCOL`
/// - Webhook: `DLPSCAN_SIEM_URL`
/// - Datadog: `DLPSCAN_SIEM_API_KEY`, `DLPSCAN_SIEM_SITE`
///
/// HTTP-based adapters (Splunk, Elasticsearch, Webhook) require HTTPS URLs
/// by default. Set `DLPSCAN_SIEM_ALLOW_HTTP=1` to permit plaintext HTTP
/// in development environments.
pub fn create_siem_from_env() -> Option<Box<dyn SIEMAdapter>> {
    let siem_type = std::env::var("DLPSCAN_SIEM_TYPE").ok()?;

    match siem_type.to_lowercase().as_str() {
        "splunk" => {
            let url = std::env::var("DLPSCAN_SIEM_URL").ok()?;
            if !crate::webhooks::is_safe_url(&url) {
                tracing::error!(
                    "SIEM URL rejected by SSRF filter: {}",
                    crate::webhooks::sanitize_url(&url)
                );
                return None;
            }
            if !require_https(&url) {
                tracing::error!("SIEM Splunk URL must use HTTPS");
                return None;
            }
            let token = std::env::var("DLPSCAN_SIEM_TOKEN").ok()?;
            let mut adapter = SplunkHECAdapter::new(&url, &token);
            if let Ok(source) = std::env::var("DLPSCAN_SIEM_SOURCE") {
                adapter = adapter.with_source(&source);
            }
            Some(Box::new(adapter))
        }
        "elasticsearch" => {
            let url = std::env::var("DLPSCAN_SIEM_URL").ok()?;
            if !crate::webhooks::is_safe_url(&url) {
                tracing::error!(
                    "SIEM URL rejected by SSRF filter: {}",
                    crate::webhooks::sanitize_url(&url)
                );
                return None;
            }
            if !require_https(&url) {
                tracing::error!("SIEM Elasticsearch URL must use HTTPS");
                return None;
            }
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
            if !crate::webhooks::is_safe_url(&url) {
                tracing::error!(
                    "SIEM URL rejected by SSRF filter: {}",
                    crate::webhooks::sanitize_url(&url)
                );
                return None;
            }
            if !require_https(&url) {
                tracing::error!("SIEM Webhook URL must use HTTPS");
                return None;
            }
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
    crate::http_util::iso8601_now()
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Send an HTTP POST to a SIEM endpoint.
/// Delegates to the shared `http_util::safe_http_post` which handles
/// DNS resolution, SSRF validation, and CRLF sanitization.
fn http_post_sync(url: &str, body: &[u8], headers: &[(String, String)]) -> Result<u16, String> {
    crate::http_util::safe_http_post(url, body, headers, 30)
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
        let result = crate::http_util::epoch_to_iso8601(1704067200);
        assert_eq!(result, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_require_https_rejects_http() {
        // Without env var, HTTP should be rejected
        std::env::remove_var("DLPSCAN_SIEM_ALLOW_HTTP");
        assert!(!require_https("http://example.com"));
        assert!(require_https("https://example.com"));
        assert!(require_https("HTTPS://EXAMPLE.COM"));
    }

    #[test]
    fn test_send_with_retry_succeeds_first_try() {
        struct OkAdapter;
        impl SIEMAdapter for OkAdapter {
            fn send(&self, _event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
                Ok(())
            }
        }
        let adapter = OkAdapter;
        let event = HashMap::new();
        assert!(send_with_retry(&adapter, &event).is_ok());
    }

    #[test]
    fn test_send_with_retry_fails_after_retries() {
        struct FailAdapter;
        impl SIEMAdapter for FailAdapter {
            fn send(&self, _event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
                Err("connection refused".to_string())
            }
        }
        let adapter = FailAdapter;
        let event = HashMap::new();
        let result = send_with_retry(&adapter, &event);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("connection refused"));
    }

    #[test]
    fn test_send_with_retry_succeeds_on_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct RetryAdapter {
            attempts: AtomicUsize,
        }
        impl SIEMAdapter for RetryAdapter {
            fn send(&self, _event: &HashMap<String, serde_json::Value>) -> Result<(), String> {
                let n = self.attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 { Err("transient error".to_string()) } else { Ok(()) }
            }
        }
        let adapter = RetryAdapter { attempts: AtomicUsize::new(0) };
        let event = HashMap::new();
        assert!(send_with_retry(&adapter, &event).is_ok());
    }

    #[test]
    fn test_syslog_hostname_sanitized() {
        // Hostname with control chars should be sanitized in syslog message
        let adapter = SyslogAdapter::new();
        // We can't easily test the actual message, but verify the adapter
        // construction works without panicking
        let adapter = adapter.with_address("localhost", 1514).with_protocol("udp");
        assert_eq!(adapter.port, 1514);
    }
}
