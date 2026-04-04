//! Webhook notification system for DLP scan findings.
//!
//! Sends HTTP POST notifications to registered URLs when sensitive data is detected.
//! Supports retry with exponential backoff, fire-and-forget delivery in background threads.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::guard::ScanResult;

// ---------------------------------------------------------------------------
// URL safety & sanitisation helpers
// ---------------------------------------------------------------------------

/// Parse a URL into (scheme, userinfo, host, port, path).
/// Returns `Err` if the URL is malformed or has an unsupported scheme.
fn parse_url(url: &str) -> Result<(&str, Option<&str>, &str, u16, &str), String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("Unsupported URL scheme (must be http:// or https://): {}", sanitize_url(url)));
    };

    // Split off userinfo (user:pass@host)
    let (userinfo, after_userinfo) = if let Some(at) = rest.find('@') {
        // Make sure '@' appears before the first '/'
        let slash = rest.find('/').unwrap_or(rest.len());
        if at < slash {
            (Some(&rest[..at]), &rest[at + 1..])
        } else {
            (None, rest)
        }
    } else {
        (None, rest)
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

    Ok((scheme, userinfo, host, port, path))
}

/// Strip credentials (userinfo) from a URL before logging.
pub fn sanitize_url(url: &str) -> String {
    // Find scheme
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[scheme_end..];
    // Check for userinfo
    if let Some(at) = rest.find('@') {
        let slash = rest.find('/').unwrap_or(rest.len());
        if at < slash {
            // Strip userinfo
            return format!("{}***@{}", &url[..scheme_end], &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Check whether a URL is safe to connect to (SSRF protection).
///
/// Rejects:
/// - URLs without http:// or https:// scheme
/// - `localhost` hostname
/// - Private/internal IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
///   192.168.0.0/16, 169.254.0.0/16, ::1, fd00::/8
pub fn is_safe_url(url: &str) -> bool {
    let (_scheme, _userinfo, host, _port, _path) = match parse_url(url) {
        Ok(parts) => parts,
        Err(_) => return false,
    };

    let host_lower = host.to_lowercase();

    // Reject localhost
    if host_lower == "localhost" {
        return false;
    }

    // Reject IPv6 loopback and private
    let trimmed = host_lower.trim_start_matches('[').trim_end_matches(']');
    if trimmed == "::1" || trimmed.starts_with("fd") {
        return false;
    }

    // Try parsing as IPv4
    if let Ok(ip) = trimmed.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        // 127.0.0.0/8
        if octets[0] == 127 {
            return false;
        }
        // 10.0.0.0/8
        if octets[0] == 10 {
            return false;
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
            return false;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return false;
        }
        // 169.254.0.0/16 (link-local)
        if octets[0] == 169 && octets[1] == 254 {
            return false;
        }
    }

    // Try parsing as IPv6
    if let Ok(ip) = trimmed.parse::<std::net::Ipv6Addr>() {
        if ip.is_loopback() {
            return false;
        }
        let segs = ip.segments();
        // fd00::/8  (first byte is 0xfd)
        if (segs[0] >> 8) == 0xfd {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

/// Webhook notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub timestamp: String,
    pub finding_count: usize,
    pub categories: Vec<String>,
    pub source: Option<String>,
    pub details: Vec<FindingDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetail {
    pub category: String,
    pub sub_category: String,
    pub confidence: f64,
    pub redacted_match: String,
}

/// Build a webhook payload from a ScanResult.
pub fn build_payload(result: &ScanResult, source: Option<&str>) -> WebhookPayload {
    WebhookPayload {
        event_type: "dlpscan.finding".to_string(),
        timestamp: iso8601_now(),
        finding_count: result.finding_count(),
        categories: result.categories_found.iter().cloned().collect(),
        source: source.map(|s| s.to_string()),
        details: result
            .findings
            .iter()
            .map(|m| FindingDetail {
                category: m.category.clone(),
                sub_category: m.sub_category.clone(),
                confidence: m.confidence,
                redacted_match: m.redacted_text(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// WebhookNotifier
// ---------------------------------------------------------------------------

/// Webhook notifier that sends findings to registered URLs.
pub struct WebhookNotifier {
    urls: Mutex<Vec<String>>,
    retries: usize,
    timeout_secs: u64,
    backoff_base: f64,
    max_concurrent: usize,
}

impl WebhookNotifier {
    pub fn new(urls: Vec<String>) -> Self {
        Self {
            urls: Mutex::new(urls),
            retries: 2,
            timeout_secs: 10,
            backoff_base: 1.0,
            max_concurrent: 8,
        }
    }

    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_backoff(mut self, base: f64) -> Self {
        self.backoff_base = base;
        self
    }

    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Add a URL to the notification list.
    /// Returns `Err` if the URL fails SSRF safety checks.
    pub fn add_url(&self, url: &str) -> Result<(), String> {
        if !is_safe_url(url) {
            return Err(format!(
                "Refusing to add unsafe/internal URL: {}",
                sanitize_url(url)
            ));
        }
        if let Ok(mut urls) = self.urls.lock() {
            urls.push(url.to_string());
        }
        Ok(())
    }

    /// Remove a URL from the notification list.
    pub fn remove_url(&self, url: &str) {
        if let Ok(mut urls) = self.urls.lock() {
            urls.retain(|u| u != url);
        }
    }

    /// Send notification for scan result.
    /// Spawns a single background thread that delivers to all URLs sequentially,
    /// bounded by `max_concurrent`.
    /// No-op if the result is clean (no findings).
    pub fn notify(&self, result: &ScanResult, source: Option<&str>) {
        if result.is_clean {
            return;
        }

        let payload = build_payload(result, source);
        let urls = self.urls.lock().map(|u| u.clone()).unwrap_or_default();
        let retries = self.retries;
        let timeout = self.timeout_secs;
        let backoff = self.backoff_base;
        let max_concurrent = self.max_concurrent;

        // Spawn a single thread that processes URLs in bounded batches
        std::thread::spawn(move || {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let active = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for url in urls {
                // Wait until we are below the concurrency limit
                while active.load(Ordering::SeqCst) >= max_concurrent {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }

                active.fetch_add(1, Ordering::SeqCst);
                let payload = payload.clone();
                let active = Arc::clone(&active);
                let handle = std::thread::spawn(move || {
                    deliver(&url, &payload, retries, timeout, backoff);
                    active.fetch_sub(1, Ordering::SeqCst);
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.join();
            }
        });
    }
}

/// Deliver payload to URL with retry and exponential backoff.
fn deliver(
    url: &str,
    payload: &WebhookPayload,
    retries: usize,
    timeout_secs: u64,
    backoff_base: f64,
) {
    let safe_url = sanitize_url(url);
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(url = %safe_url, %e, "Failed to serialize webhook payload");
            return;
        }
    };

    for attempt in 0..=retries {
        if attempt > 0 {
            let wait_secs = backoff_base * (2.0_f64).powi(attempt as i32 - 1);
            std::thread::sleep(std::time::Duration::from_secs_f64(wait_secs));
        }

        match http_post(url, &body, timeout_secs) {
            Ok(status) if (200..300).contains(&status) => return,
            Ok(status) => {
                tracing::warn!(url = %safe_url, status, attempt, "Webhook delivery got non-2xx");
            }
            Err(e) => {
                tracing::warn!(url = %safe_url, %e, attempt, "Webhook delivery error");
            }
        }
    }

    tracing::error!(url = %safe_url, retries, "Webhook delivery exhausted all retries");
}

/// HTTP POST supporting both `http://` and `https://` URLs.
///
/// For `http://` URLs, uses a raw `TcpStream`.
/// For `https://` URLs, returns an error directing users to enable the
/// `async-support` feature (TLS requires additional dependencies).
fn http_post(url: &str, body: &[u8], timeout_secs: u64) -> Result<u16, String> {
    use std::io::{Read, Write};

    let (scheme, _userinfo, host, port, path) = parse_url(url)?;

    if scheme == "https" {
        return Err(format!(
            "HTTPS URLs require the `async-support` feature for TLS. \
             Cannot connect to {} over plaintext.",
            sanitize_url(url)
        ));
    }

    let addr = format!("{host}:{port}");
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        timeout,
    )
    .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 512];
    let n = stream.read(&mut response).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&response[..n]);

    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "Could not parse HTTP status".to_string())
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

static NOTIFIERS: Lazy<Mutex<Vec<Arc<WebhookNotifier>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

/// Register a notifier in the global registry.
pub fn register_notifier(notifier: Arc<WebhookNotifier>) {
    if let Ok(mut list) = NOTIFIERS.lock() {
        list.push(notifier);
    }
}

/// Unregister a notifier from the global registry.
pub fn unregister_notifier(notifier: &Arc<WebhookNotifier>) {
    if let Ok(mut list) = NOTIFIERS.lock() {
        list.retain(|n| !Arc::ptr_eq(n, notifier));
    }
}

/// Notify all registered notifiers about scan findings.
pub fn notify_findings(result: &ScanResult, source: Option<&str>) {
    if let Ok(list) = NOTIFIERS.lock() {
        for notifier in list.iter() {
            notifier.notify(result, source);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (s, m, h, day, mon, year) = epoch_to_parts(secs);
    format!("{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn epoch_to_parts(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = epoch % 60;
    let m = (epoch / 60) % 60;
    let h = (epoch / 3600) % 24;
    let mut days = epoch / 86400;
    let mut year = 1970u64;
    loop {
        let yd = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 0u64;
    for md in mdays {
        if days < md { break; }
        days -= md;
        mon += 1;
    }
    (s, m, h, days + 1, mon + 1, year)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_build_payload_clean() {
        let result = ScanResult {
            text: "hello".to_string(),
            is_clean: true,
            findings: vec![],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
        };
        let payload = build_payload(&result, Some("test"));
        assert_eq!(payload.finding_count, 0);
        assert_eq!(payload.source, Some("test".to_string()));
    }

    #[test]
    fn test_notifier_url_management() {
        let notifier = WebhookNotifier::new(vec!["http://a.com".to_string()]);
        notifier.add_url("http://b.com").unwrap();
        assert_eq!(notifier.urls.lock().unwrap().len(), 2);
        notifier.remove_url("http://a.com");
        assert_eq!(notifier.urls.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_add_url_rejects_internal() {
        let notifier = WebhookNotifier::new(vec![]);
        assert!(notifier.add_url("http://127.0.0.1/hook").is_err());
        assert!(notifier.add_url("http://localhost/hook").is_err());
        assert!(notifier.add_url("http://10.0.0.1/hook").is_err());
        assert!(notifier.add_url("http://192.168.1.1/hook").is_err());
        assert!(notifier.add_url("http://172.16.0.1/hook").is_err());
        assert!(notifier.add_url("http://169.254.1.1/hook").is_err());
        assert!(notifier.add_url("ftp://example.com/hook").is_err());
    }

    #[test]
    fn test_is_safe_url_accepts_public() {
        assert!(is_safe_url("http://example.com/hook"));
        assert!(is_safe_url("https://hooks.slack.com/services/T00/B00/xxx"));
    }

    #[test]
    fn test_sanitize_url_strips_credentials() {
        assert_eq!(
            sanitize_url("http://user:pass@example.com/hook"),
            "http://***@example.com/hook"
        );
        assert_eq!(
            sanitize_url("https://example.com/hook"),
            "https://example.com/hook"
        );
    }

    #[test]
    fn test_parse_url_both_schemes() {
        let (scheme, _, host, port, path) = parse_url("http://example.com/test").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/test");

        let (scheme, _, host, port, _) = parse_url("https://secure.example.com:8443/api").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_epoch_to_parts() {
        let (s, m, h, d, mon, y) = epoch_to_parts(0);
        assert_eq!((y, mon, d, h, m, s), (1970, 1, 1, 0, 0, 0));
    }
}
