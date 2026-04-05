//! Shared HTTP and network utilities for webhooks and SIEM adapters.
//!
//! Provides URL parsing, SSRF validation, and a safe HTTP POST client
//! with DNS rebinding protection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// Parsed URL components.
pub struct ParsedUrl<'a> {
    pub scheme: &'a str,
    pub userinfo: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

/// Parse a URL into components.
/// Returns `Err` if the URL is malformed or has an unsupported scheme.
pub fn parse_url(url: &str) -> Result<ParsedUrl<'_>, String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("Unsupported URL scheme (must be http:// or https://)".to_string());
    };

    let (userinfo, after_userinfo) = if let Some(at) = rest.find('@') {
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

    Ok(ParsedUrl {
        scheme,
        userinfo,
        host,
        port,
        path,
    })
}

/// Strip credentials (userinfo) from a URL before logging.
pub fn sanitize_url(url: &str) -> String {
    if let Ok(parsed) = parse_url(url) {
        if parsed.userinfo.is_some() {
            let default_port = if parsed.scheme == "https" { 443 } else { 80 };
            if parsed.port == default_port {
                return format!("{}://***@{}{}", parsed.scheme, parsed.host, parsed.path);
            }
            return format!(
                "{}://***@{}:{}{}",
                parsed.scheme, parsed.host, parsed.port, parsed.path
            );
        }
    }
    url.to_string()
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Check whether an IP address is in a private/reserved range.
///
/// Returns `true` if the IP is private (should be BLOCKED for SSRF).
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            ipv4.is_loopback()
                || ipv4.is_unspecified()
                || o[0] == 10                                           // 10.0.0.0/8
                || (o[0] == 172 && (16..=31).contains(&o[1]))           // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168)                         // 192.168.0.0/16
                || (o[0] == 169 && o[1] == 254)                         // 169.254.0.0/16 link-local
                || (o[0] == 100 && (64..=127).contains(&o[1]))          // 100.64.0.0/10 CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))         // 198.18.0.0/15 benchmarking
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unspecified() || {
                let seg0 = ipv6.segments()[0];
                (seg0 >> 8) == 0xfd                                 // fd00::/8 ULA
                        || (seg0 >> 8) == 0xfc                          // fc00::/8 ULA
                        || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
            }
        }
    }
}

/// Check whether a URL is safe to connect to (pre-resolution SSRF check).
///
/// Rejects localhost, private IPs, and reserved ranges.
pub fn is_safe_url(url: &str) -> bool {
    let parsed = match parse_url(url) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let host_lower = parsed.host.to_lowercase();

    // Reject localhost aliases
    if host_lower == "localhost" || host_lower == "localhost.localdomain" || host_lower == "0.0.0.0"
    {
        return false;
    }

    // Check IPv6 string patterns (before parsing)
    let trimmed = host_lower.trim_start_matches('[').trim_end_matches(']');
    if trimmed == "::1"
        || trimmed.starts_with("fd")
        || trimmed.starts_with("fc")
        || trimmed.starts_with("fe80")
    {
        return false;
    }

    // Parse and check IPv4
    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        if is_private_ip(IpAddr::V4(ip)) {
            return false;
        }
    }

    // Parse and check IPv6
    if let Ok(ip) = trimmed.parse::<std::net::Ipv6Addr>() {
        if is_private_ip(IpAddr::V6(ip)) {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Safe HTTP POST with DNS rebinding protection
// ---------------------------------------------------------------------------

/// Perform a synchronous HTTP POST with SSRF and DNS rebinding protection.
///
/// Resolves the hostname, validates the resolved IP against private ranges,
/// then connects. Rejects HTTPS (use `reqwest` with `async-support` feature for TLS).
pub fn safe_http_post(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<u16, String> {
    use std::io::{Read, Write};

    let parsed = parse_url(url)?;

    if parsed.scheme == "https" {
        return Err(format!(
            "HTTPS requires the `async-support` feature for TLS. Cannot connect to {} over plaintext.",
            sanitize_url(url)
        ));
    }

    let addr = format!("{}:{}", parsed.host, parsed.port);
    let timeout = Duration::from_secs(timeout_secs);

    // DNS rebinding protection: resolve and validate IP before connecting
    let socket_addr: SocketAddr = {
        let resolved = addr
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed: {e}"))?
            .next()
            .ok_or("DNS resolution returned no addresses")?;

        if is_private_ip(resolved.ip()) {
            return Err(format!(
                "Target resolved to private/reserved IP: {}",
                resolved.ip()
            ));
        }
        resolved
    };

    let mut stream =
        TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();

    // Build HTTP request with CRLF-sanitized headers
    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        parsed.path,
        parsed.host,
        body.len()
    );
    for (k, v) in headers {
        let safe_k = k.replace(['\r', '\n'], "");
        let safe_v = v.replace(['\r', '\n'], "");
        req.push_str(&format!("{safe_k}: {safe_v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&response[..n]);

    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "Could not parse HTTP status".to_string())
}

// ---------------------------------------------------------------------------
// Shared timestamp utility
// ---------------------------------------------------------------------------

/// Get the current time as ISO 8601 UTC string.
pub fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_to_iso8601(secs)
}

/// Convert a Unix epoch timestamp to ISO 8601 string.
pub fn epoch_to_iso8601(secs: u64) -> String {
    // Howard Hinnant's civil calendar algorithm
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if mon <= 2 { 1 } else { 0 };

    format!("{year:04}-{mon:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

use std::time::SystemTime;
