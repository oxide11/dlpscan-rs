//! Polygon Siphon ICAP — RFC 3507 network DLP server.
//!
//! Lets any ICAP-capable HTTP proxy (Squid, nginx ICAP module, Blue Coat,
//! Zscaler, McAfee Web Gateway) offload DLP inspection to Siphon without
//! changing application code. The proxy sends every HTTP request or response
//! to this service; Siphon scans the body and either allows (flag mode) or
//! blocks (block mode).
//!
//! ## Supported ICAP methods
//!
//! - `OPTIONS /dlp` — capability advertisement (required by all ICAP clients)
//! - `REQMOD  /dlp` — outgoing request body inspection (uploads, POSTs)
//! - `RESPMOD /dlp` — incoming response body inspection (downloads)
//!
//! ## Configuration
//!
//! | Variable | Default | Notes |
//! |---|---|---|
//! | `SIPHON_ICAP_PORT` | 1344 | Standard ICAP port |
//! | `SIPHON_ICAP_BIND` | 0.0.0.0 | Bind address |
//! | `SIPHON_ICAP_ALLOWED_NETS` | **required** | Comma-separated IP/CIDR allowlist. Use `0.0.0.0/0` for dev. Connections outside the list are dropped immediately. |
//! | `SIPHON_ICAP_ACTION` | flag | `flag` — annotate headers and allow; `block` — return 403 block page. An unknown value refuses to start |
//! | `SIPHON_ICAP_ON_UNSCANNABLE` | pass | What happens to content seen and not read — a body over the limit, or a binary one. `pass` allows it, tagged `X-DLP-Action: unscanned`; `block` refuses it. An unknown value refuses to start |
//! | `SIPHON_ICAP_MIN_CONFIDENCE` | 0.6 | Confidence threshold that triggers a block (block mode only) |
//! | `SIPHON_ICAP_MAX_BODY_BYTES` | 10485760 | Bodies larger than this are not scanned; `SIPHON_ICAP_ON_UNSCANNABLE` decides what happens to them |
//! | `SIPHON_ICAP_SERVICE_NAME` | dlp | ICAP URI path (`/dlp`) |
//! | `SIPHON_ICAP_MAX_CONNECTIONS` | 256 | Max concurrent connections; extras are dropped immediately |

use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── IP/CIDR allowlist ────────────────────────────────────────────

#[derive(Clone)]
enum IpNet {
    Exact(IpAddr),
    V4Cidr { addr: u32, mask: u32 },
    V6Cidr { addr: u128, mask: u128 },
    Any,
}

impl IpNet {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "0.0.0.0/0" || s == "::/0" {
            return Some(IpNet::Any);
        }
        if let Some((ip_s, prefix_s)) = s.split_once('/') {
            let bits: u8 = prefix_s.parse().ok()?;
            if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                if bits > 32 {
                    return None;
                }
                let addr = u32::from(ip);
                let mask = if bits == 0 {
                    0u32
                } else {
                    !0u32 << (32 - bits)
                };
                return Some(IpNet::V4Cidr {
                    addr: addr & mask,
                    mask,
                });
            }
            if let Ok(ip) = ip_s.parse::<std::net::Ipv6Addr>() {
                if bits > 128 {
                    return None;
                }
                let addr = u128::from(ip);
                let mask = if bits == 0 {
                    0u128
                } else {
                    !0u128 << (128 - bits)
                };
                return Some(IpNet::V6Cidr {
                    addr: addr & mask,
                    mask,
                });
            }
            None
        } else {
            let ip: IpAddr = s.parse().ok()?;
            Some(IpNet::Exact(ip))
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            IpNet::Any => true,
            IpNet::Exact(a) => a == ip,
            IpNet::V4Cidr { addr, mask } => match ip {
                IpAddr::V4(v4) => (u32::from(*v4) & mask) == *addr,
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        (u32::from(v4) & mask) == *addr
                    } else {
                        false
                    }
                }
            },
            IpNet::V6Cidr { addr, mask } => match ip {
                IpAddr::V6(v6) => (u128::from(*v6) & mask) == *addr,
                IpAddr::V4(v4) => {
                    let v6 = v4.to_ipv6_mapped();
                    (u128::from(v6) & mask) == *addr
                }
            },
        }
    }
}

fn is_allowed(ip: &IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

// ── ICAP action ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum IcapAction {
    Flag,
    Block,
}

/// What to do with content this sensor saw and could not read.
///
/// Every other detector in the fleet lets the operator choose this direction:
/// siphon-fs marks an oversized file **not scanned** rather than clean, and
/// siphon-smtp defers by default and says so in `SIPHON_SMTP_ON_INDETERMINATE`.
/// siphon-icap always passed, with no knob and nothing on the wire, so
/// "send it in one body larger than the limit" was a complete bypass of a
/// deployment that believed it was enforcing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Unscannable {
    /// Allow it through. The default, because flipping it would start
    /// blocking large transfers on upgrade for every existing deployment,
    /// which is the operator's call and not an upgrade's.
    Pass,
    /// Refuse it. What to set when the proxy hop is meant to enforce.
    Block,
}

impl Unscannable {
    /// An unknown value is a startup error, never a fallback — the same rule
    /// as `SIPHON_SMTP_ON_INDETERMINATE` and `SIPHON_DATABASE_TLS`. Silently
    /// treating a typo as `pass` picks the operator's failure direction for
    /// them, in the permissive direction, on a sensor they think is enforcing.
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "pass" => Ok(Self::Pass),
            "block" => Ok(Self::Block),
            other => Err(format!(
                "SIPHON_ICAP_ON_UNSCANNABLE: unknown value {other:?} (expected \"pass\" or \"block\")"
            )),
        }
    }
}

// ── App state ────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    allowed_nets: Arc<Vec<IpNet>>,
    action: IcapAction,
    /// What happens to content that was seen and could not be read.
    on_unscannable: Unscannable,
    min_confidence: f64,
    max_body_bytes: usize,
    service_name: String,
    max_connections: usize,
    /// This pod as a sensor: what it scanned, for its heartbeat.
    sensor: Arc<siphon_auth::telemetry::SensorCounters>,
}

// ── ICAP request ─────────────────────────────────────────────────

struct IcapRequest {
    method: String,
    /// e.g. "/dlp"
    uri_path: String,
    headers: Vec<(String, String)>,
    /// Original encapsulated HTTP headers (req-hdr or res-hdr section), if any
    http_headers_raw: Vec<u8>,
    /// Extracted HTTP body bytes (from req-body or res-body), if any
    body: Vec<u8>,
    /// True when the body exceeded `max_body_bytes` and was partially drained
    /// without storing. Scanning would be incomplete; `handle_scan` returns 204.
    body_truncated: bool,
}

fn hdr<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let lower = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == lower)
        .map(|(_k, v)| v.as_str())
}

// ── ICAP request parser ──────────────────────────────────────────

async fn parse_icap_request<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_body: usize,
) -> std::io::Result<Option<IcapRequest>> {
    // Read ICAP request line
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(None); // EOF / closed
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']).to_string();
    if request_line.is_empty() {
        return Ok(None);
    }

    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let uri = parts.next().unwrap_or("").to_string();
    let _version = parts.next().unwrap_or("");

    // Extract path from uri (may be icap://host/path or just /path)
    let uri_path = if let Some(after_scheme) = uri.strip_prefix("icap://") {
        after_scheme
            .find('/')
            .map(|i| after_scheme[i..].to_string())
            .unwrap_or_else(|| "/".to_string())
    } else {
        uri
    };

    // Read ICAP headers, capped to reject header-flood attacks.
    const MAX_REQUEST_HEADERS: usize = 256;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // blank line = end of headers
        }
        if headers.len() >= MAX_REQUEST_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ICAP request header count exceeds limit of {MAX_REQUEST_HEADERS}"),
            ));
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    // Parse Encapsulated header
    // e.g. "req-hdr=0, req-body=412" or "req-hdr=0, null-body=412"
    let encapsulated = hdr(&headers, "Encapsulated").unwrap_or("").to_string();
    let sections: Vec<(&str, usize)> = encapsulated
        .split(',')
        .filter_map(|part| {
            let p = part.trim();
            let (name, off) = p.split_once('=')?;
            let offset: usize = off.trim().parse().ok()?;
            Some((name.trim(), offset))
        })
        .collect();

    let mut http_headers_raw = Vec::new();
    let mut body = Vec::new();
    let mut truncated = false;

    for (i, (section_name, _offset)) in sections.iter().enumerate() {
        let bytes_to_read = if i + 1 < sections.len() {
            let next_offset = sections[i + 1].1;
            let this_offset = sections[i].1;
            next_offset.saturating_sub(this_offset)
        } else {
            0 // last section — handled below
        };

        if i + 1 < sections.len() {
            // Not the last section: read exactly bytes_to_read bytes.
            // Reject attacker-supplied offsets that would force a giant allocation.
            const MAX_SECTION_HDR_BYTES: usize = 1024 * 1024; // 1 MiB
            if bytes_to_read > MAX_SECTION_HDR_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "icap: encapsulated section size exceeds 1 MiB hard cap",
                ));
            }
            let mut buf = vec![0u8; bytes_to_read];
            reader.read_exact(&mut buf).await?;
            if section_name.ends_with("-hdr") {
                http_headers_raw = buf;
            }
        } else {
            // Last section
            if *section_name == "null-body" {
                // No body
            } else if section_name.ends_with("-body") {
                // Chunked
                // We need a plain AsyncReadExt here; reader is BufReader
                // We read chunked from the BufReader directly
                let (b, trunc) = read_chunked_buf(reader, max_body).await?;
                body = b;
                truncated = trunc;
            }
        }
    }

    Ok(Some(IcapRequest {
        method,
        uri_path,
        headers,
        http_headers_raw,
        body,
        body_truncated: truncated,
    }))
}

/// Read chunked transfer encoding from a BufReader.
///
/// Returns `(bytes, truncated)`. `truncated` is true when one or more chunks
/// were drained without storing because the cumulative body would have exceeded
/// `max_bytes`. Callers must check this flag — `bytes.len() <= max_bytes` is
/// always true regardless of truncation, so the flag is the only way to tell
/// a legitimately small body from one that was silently clipped.
async fn read_chunked_buf<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut truncated = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let size_str = line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16).unwrap_or(0);
        if size == 0 {
            // Consume trailing CRLF
            let mut crlf = String::new();
            reader.read_line(&mut crlf).await?;
            break;
        }
        // Cap individual chunk size to prevent OOM from a malicious huge hex size.
        const MAX_CHUNK: usize = 64 * 1024 * 1024; // 64 MiB hard cap per chunk
        if size > MAX_CHUNK {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "icap: chunk size exceeds hard cap",
            ));
        }
        let start = buf.len();
        let fits = buf.len() + size <= max_bytes;
        if fits {
            buf.resize(start + size, 0u8);
            reader.read_exact(&mut buf[start..]).await?;
        } else {
            // Body would exceed cap — drain without storing.
            truncated = true;
            let mut remaining = size;
            let mut scratch = [0u8; 8192];
            while remaining > 0 {
                let n = remaining.min(scratch.len());
                reader.read_exact(&mut scratch[..n]).await?;
                remaining -= n;
            }
        }
        // Consume CRLF after chunk data
        let mut crlf = String::new();
        reader.read_line(&mut crlf).await?;
    }
    Ok((buf, truncated))
}

// ── Response builders ────────────────────────────────────────────

fn icap_date() -> String {
    // RFC 1123 date — use a fixed format without chrono dep
    // Format: "Thu, 03 Sep 2026 00:00:00 GMT"
    // Since we don't have chrono, use a static-ish approximation that
    // satisfies ICAP clients (they use it for cache freshness, not strict
    // time comparison in most implementations).
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple RFC 1123 formatter using integer arithmetic
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let s = secs;
    let day_of_week = ((s / 86400 + 4) % 7) as usize; // 1970-01-01 was Thursday (4)
    let mut y = 1970u32;
    let mut remaining = s;
    loop {
        let leap =
            (y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))) as u64;
        let year_secs = (365 + leap) * 86400;
        if remaining < year_secs {
            break;
        }
        remaining -= year_secs;
        y += 1;
    }
    let leap = (y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))) as u64;
    let month_days: [u64; 12] = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    while m < 11 && remaining >= month_days[m] * 86400 {
        remaining -= month_days[m] * 86400;
        m += 1;
    }
    let day = remaining / 86400 + 1;
    remaining %= 86400;
    let hour = remaining / 3600;
    remaining %= 3600;
    let min = remaining / 60;
    let sec = remaining % 60;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        days[day_of_week], day, months[m], y, hour, min, sec
    )
}

fn istag() -> String {
    format!("\"siphon-{VERSION}\"")
}

fn response_204() -> Vec<u8> {
    format!(
        "ICAP/1.0 204 No Content\r\nISTag: {}\r\nDate: {}\r\n\r\n",
        istag(),
        icap_date()
    )
    .into_bytes()
}

fn response_400() -> Vec<u8> {
    "ICAP/1.0 400 Bad Request\r\n\r\n".to_string().into_bytes()
}

fn response_404() -> Vec<u8> {
    "ICAP/1.0 404 ICAP Service Not Found\r\n\r\n"
        .to_string()
        .into_bytes()
}

fn response_500() -> Vec<u8> {
    "ICAP/1.0 500 Server Error\r\n\r\n".to_string().into_bytes()
}

fn response_options(service_name: &str) -> Vec<u8> {
    format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Date: {}\r\n\
         Methods: REQMOD, RESPMOD\r\n\
         Service: Siphon DLP ICAP/{}\r\n\
         Service-ID: {}\r\n\
         Max-Connections: 100\r\n\
         Options-TTL: 3600\r\n\
         Preview: 4096\r\n\
         Transfer-Preview: *\r\n\
         Transfer-Ignore: jpg,jpeg,png,gif,bmp,webp,svg,mp4,mp3,pdf,exe,zip,gz,br\r\n\
         Transfer-Complete: \r\n\
         Allow: 204\r\n\
         \r\n",
        istag(),
        icap_date(),
        VERSION,
        service_name,
    )
    .into_bytes()
}

/// Flag-mode response: allow but annotate findings in X-DLP-* headers.
fn response_flagged(req: &IcapRequest, finding_count: usize, categories: &str) -> Vec<u8> {
    // Reflect the original HTTP headers back so the proxy can forward them.
    // If there were no HTTP headers, we return a null-body response.
    if req.http_headers_raw.is_empty() {
        let hdrs = format!(
            "ICAP/1.0 200 OK\r\n\
             ISTag: {}\r\n\
             Date: {}\r\n\
             X-DLP-Findings: {}\r\n\
             X-DLP-Categories: {}\r\n\
             X-DLP-Action: flagged\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
            istag(),
            icap_date(),
            finding_count,
            categories,
        );
        return hdrs.into_bytes();
    }

    let hdr_len = req.http_headers_raw.len();
    let icap_hdr = format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Date: {}\r\n\
         X-DLP-Findings: {}\r\n\
         X-DLP-Categories: {}\r\n\
         X-DLP-Action: flagged\r\n\
         Encapsulated: req-hdr=0, null-body={}\r\n\
         \r\n",
        istag(),
        icap_date(),
        finding_count,
        categories,
        hdr_len,
    );
    let mut out = icap_hdr.into_bytes();
    out.extend_from_slice(&req.http_headers_raw);
    out
}

/// A 204 that says *why* nothing was adapted.
///
/// A bare 204 means "no adaptation needed", and a proxy is entitled to read
/// that as "we looked and it was clean". These bodies were not clean; they
/// were not read. The headers keep the response a 204, so no proxy changes
/// behaviour on upgrade, while giving anything that logs ICAP responses the
/// difference between the two.
fn response_204_unscanned(reason: &str) -> Vec<u8> {
    format!(
        "ICAP/1.0 204 No Content\r\n\
         ISTag: {}\r\n\
         Date: {}\r\n\
         X-DLP-Action: unscanned\r\n\
         X-DLP-Reason: {}\r\n\
         \r\n",
        istag(),
        icap_date(),
        reason,
    )
    .into_bytes()
}

/// Block-mode response for content that could not be read, as opposed to
/// content that was read and found to carry sensitive data. The distinction
/// matters to whoever gets the page: "we could not inspect this" is a
/// different thing to explain than "this contained a card number".
fn response_blocked_unscanned(reason: &str) -> Vec<u8> {
    let body = format!(
        "<html><head><title>Access Blocked by DLP</title></head>\
         <body><h1>Access Blocked</h1>\
         <p>Siphon DLP could not inspect this content ({reason}), and this \
         deployment is configured to refuse what it cannot read.</p>\
         <p>Contact your security team if you believe this is an error.</p>\
         </body></html>"
    );
    let body_bytes = body.as_bytes();
    let body_len = body_bytes.len();
    let res_hdr = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {body_len}\r\n\
         \r\n"
    );
    let res_hdr_bytes = res_hdr.as_bytes();
    let res_body_offset = res_hdr_bytes.len();

    let icap_hdr = format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Date: {}\r\n\
         X-DLP-Action: blocked-unscanned\r\n\
         X-DLP-Reason: {reason}\r\n\
         Encapsulated: res-hdr=0, res-body={res_body_offset}\r\n\
         \r\n",
        istag(),
        icap_date(),
    );

    let chunk_size = format!("{:x}\r\n", body_len);
    let mut out = icap_hdr.into_bytes();
    out.extend_from_slice(res_hdr_bytes);
    out.extend_from_slice(chunk_size.as_bytes());
    out.extend_from_slice(body_bytes);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

/// Block-mode response: return a synthetic 403 to the proxy.
fn response_blocked(finding_count: usize, categories: &str) -> Vec<u8> {
    let body = format!(
        "<html><head><title>Access Blocked by DLP</title></head>\
         <body><h1>Access Blocked</h1>\
         <p>This content was blocked by Siphon DLP because it contains \
         sensitive data ({finding_count} finding(s): {categories}).</p>\
         <p>Contact your security team if you believe this is an error.</p>\
         </body></html>"
    );
    let body_bytes = body.as_bytes();
    let body_len = body_bytes.len();
    let res_hdr = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {body_len}\r\n\
         \r\n"
    );
    let res_hdr_bytes = res_hdr.as_bytes();
    let res_body_offset = res_hdr_bytes.len();

    let icap_hdr = format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Date: {}\r\n\
         X-DLP-Findings: {finding_count}\r\n\
         X-DLP-Categories: {categories}\r\n\
         X-DLP-Action: blocked\r\n\
         Encapsulated: res-hdr=0, res-body={res_body_offset}\r\n\
         \r\n",
        istag(),
        icap_date(),
    );

    let chunk_size = format!("{:x}\r\n", body_len);
    let mut out = icap_hdr.into_bytes();
    out.extend_from_slice(res_hdr_bytes);
    out.extend_from_slice(chunk_size.as_bytes());
    out.extend_from_slice(body_bytes);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

// ── Connection handler ───────────────────────────────────────────

async fn handle_connection(stream: TcpStream, peer: SocketAddr, state: Arc<AppState>) {
    let client_ip = peer.ip();
    if !is_allowed(&client_ip, &state.allowed_nets) {
        tracing::debug!(ip = %client_ip, "icap: connection rejected — not in allowed nets");
        return;
    }

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);

    loop {
        let req = match parse_icap_request(&mut reader, state.max_body_bytes).await {
            Ok(Some(r)) => r,
            Ok(None) => break, // clean EOF
            Err(e) => {
                tracing::debug!(ip = %client_ip, error = %e, "icap: parse error");
                let _ = writer.write_all(&response_400()).await;
                break;
            }
        };

        let keep_alive = hdr(&req.headers, "Connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or(true);

        // Validate service name
        let expected_path = format!("/{}", state.service_name);
        let path_ok = req.uri_path == expected_path
            || req.uri_path.starts_with(&format!("{expected_path}?"))
            || req.uri_path.starts_with(&format!("{expected_path}/"));
        if !path_ok && req.method != "OPTIONS" {
            tracing::warn!(ip = %client_ip, path = %req.uri_path, "icap: unknown service");
            let _ = writer.write_all(&response_404()).await;
            break;
        }

        let resp_bytes = match req.method.as_str() {
            "OPTIONS" => response_options(&state.service_name),
            "REQMOD" | "RESPMOD" => handle_scan(&req, &state, &client_ip.to_string()).await,
            other => {
                tracing::warn!(ip = %client_ip, method = %other, "icap: unknown method");
                response_400()
            }
        };

        if let Err(e) = writer.write_all(&resp_bytes).await {
            tracing::debug!(ip = %client_ip, error = %e, "icap: write error");
            break;
        }

        if !keep_alive {
            break;
        }
    }
}

/// Apply `SIPHON_ICAP_ON_UNSCANNABLE` to content this sensor could not read.
///
/// Counted as unscanned either way — the coverage figure is about what was
/// read, not about what was allowed — and the reason travels into both the
/// audit record and the ICAP response, so "passed unread" is never
/// indistinguishable from "scanned clean".
fn unscannable_verdict(
    state: &AppState,
    req: &IcapRequest,
    client_ip: &str,
    start: Instant,
    reason: &'static str,
) -> Vec<u8> {
    state.sensor.record_unscanned();
    let duration_ms = start.elapsed().as_millis();
    match state.on_unscannable {
        Unscannable::Pass => {
            emit_audit(
                req.method.as_str(),
                client_ip,
                0,
                &format!("pass-unscanned:{reason}"),
                duration_ms,
            );
            response_204_unscanned(reason)
        }
        Unscannable::Block => {
            emit_audit(
                req.method.as_str(),
                client_ip,
                0,
                &format!("block-unscanned:{reason}"),
                duration_ms,
            );
            response_blocked_unscanned(reason)
        }
    }
}

async fn handle_scan(req: &IcapRequest, state: &AppState, client_ip: &str) -> Vec<u8> {
    let start = Instant::now();

    if req.body.is_empty() {
        emit_audit(
            req.method.as_str(),
            client_ip,
            0,
            "pass",
            start.elapsed().as_millis(),
        );
        return response_204();
    }

    let text = String::from_utf8_lossy(&req.body);

    // An empty body is not a coverage gap: there was nothing to read, so
    // there is nothing this sensor failed to see. It used to be counted as
    // unscanned alongside binary bodies, which made coverage fall the more
    // ordinary bodyless traffic the proxy sent through — a figure that got
    // worse as the deployment got quieter.
    if text.trim().is_empty() {
        emit_audit(
            req.method.as_str(),
            client_ip,
            0,
            "pass-empty",
            start.elapsed().as_millis(),
        );
        return response_204();
    }

    // Everything below is content that reached this sensor and could not be
    // read. One policy covers all of it, because on the wire they are the
    // same event: traffic went past and nobody can say what was in it.
    //
    // Truncation is checked first: once the body was cut off at the limit,
    // what is left in `req.body` is a prefix, and asking whether a prefix
    // looks binary answers a question about the prefix, not the transfer.
    if req.body_truncated {
        tracing::warn!(
            client_ip = %client_ip,
            stored = req.body.len(),
            limit = state.max_body_bytes,
            policy = ?state.on_unscannable,
            "icap: body exceeded limit and was not scanned"
        );
        return unscannable_verdict(state, req, client_ip, start, "body-exceeds-limit");
    }

    if looks_binary(&req.body) {
        return unscannable_verdict(state, req, client_ip, start, "binary-body");
    }

    let config = ScanConfig {
        min_confidence: state.min_confidence,
        ..Default::default()
    };

    let matches = match scan_text_with_config(&text, &config) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(client_ip = %client_ip, error = %e, "icap: scan failed");
            state.sensor.record_error();
            return response_500();
        }
    };

    let finding_count = matches.len();
    let duration_ms = start.elapsed().as_millis();
    state
        .sensor
        .record_scan(finding_count as u64, text.len() as u64, duration_ms as u64);

    if finding_count == 0 {
        emit_audit(req.method.as_str(), client_ip, 0, "clean", duration_ms);
        return response_204();
    }

    // Collect unique categories
    let mut cats: Vec<&str> = matches
        .iter()
        .map(|m| m.category.as_str())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    cats.sort_unstable();
    let categories = cats.join(", ");

    match state.action {
        IcapAction::Flag => {
            emit_audit(
                req.method.as_str(),
                client_ip,
                finding_count,
                "flagged",
                duration_ms,
            );
            response_flagged(req, finding_count, &categories)
        }
        IcapAction::Block => {
            emit_audit(
                req.method.as_str(),
                client_ip,
                finding_count,
                "blocked",
                duration_ms,
            );
            response_blocked(finding_count, &categories)
        }
    }
}

/// Heuristic: if more than 30% of the first 512 bytes are non-UTF8-printable
/// (bytes < 0x09 or in 0x0e–0x1f range excluding tab/lf/cr), treat as binary.
fn looks_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(512)];
    let control_count = sample
        .iter()
        .filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20))
        .count();
    control_count * 100 / sample.len().max(1) > 30
}

fn emit_audit(method: &str, client_ip: &str, findings: usize, action: &str, duration_ms: u128) {
    use siphon_core::audit::iso8601_now;
    let line = serde_json::json!({
        "ts": iso8601_now(),
        "event": "ICAP_SCAN",
        "method": method,
        "client_ip": client_ip,
        "findings": findings,
        "action": action,
        "duration_ms": duration_ms,
    });
    // Write to stdout so log aggregators pick it up alongside the tracing output.
    println!("{line}");
}

// ── Startup ──────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("SIPHON_ICAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1344);
    let bind_addr = std::env::var("SIPHON_ICAP_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr: std::net::SocketAddr = format!("{bind_addr}:{port}").parse()?;

    // SIPHON_ICAP_ALLOWED_NETS is required — fail closed at startup.
    let allowed_nets_raw = std::env::var("SIPHON_ICAP_ALLOWED_NETS").unwrap_or_default();
    if allowed_nets_raw.trim().is_empty() {
        eprintln!(
            "FATAL: SIPHON_ICAP_ALLOWED_NETS is not set.\n\
             ICAP has no built-in auth layer — the allowlist is the only access\n\
             control. Set it to the proxy's IP/CIDR (e.g. \"10.0.0.0/8\").\n\
             For local dev use \"0.0.0.0/0\" to allow all.\n"
        );
        std::process::exit(1);
    }
    let allowed_nets: Vec<IpNet> = allowed_nets_raw
        .split(',')
        .filter_map(|s| {
            let net = IpNet::parse(s.trim());
            if net.is_none() {
                tracing::warn!(
                    entry = s.trim(),
                    "SIPHON_ICAP_ALLOWED_NETS: skipping unparseable entry"
                );
            }
            net
        })
        .collect();
    if allowed_nets.is_empty() {
        eprintln!("FATAL: SIPHON_ICAP_ALLOWED_NETS contains no valid entries. Refusing to start.");
        std::process::exit(1);
    }

    // An unknown value is fatal rather than a silent fall back to `flag`.
    // `SIPHON_ICAP_ACTION=blok` used to start an advisory sensor in a
    // deployment that had asked for an enforcing one, and nothing said so.
    let action = match std::env::var("SIPHON_ICAP_ACTION")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "flag" => IcapAction::Flag,
        "block" => IcapAction::Block,
        other => {
            eprintln!(
                "FATAL: SIPHON_ICAP_ACTION has unknown value {other:?} \
                 (expected \"flag\" or \"block\"). Refusing to start rather than \
                 guess which direction this sensor should fail."
            );
            std::process::exit(1);
        }
    };

    let on_unscannable = match Unscannable::parse(
        &std::env::var("SIPHON_ICAP_ON_UNSCANNABLE").unwrap_or_default(),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {e}. Refusing to start.");
            std::process::exit(1);
        }
    };
    if on_unscannable == Unscannable::Pass {
        tracing::warn!(
            "SIPHON_ICAP_ON_UNSCANNABLE=pass — content this sensor cannot read \
             (bodies over SIPHON_ICAP_MAX_BODY_BYTES, binary bodies) is allowed \
             through unscanned. Set it to \"block\" if this hop is meant to enforce."
        );
    }

    let min_confidence: f64 = std::env::var("SIPHON_ICAP_MIN_CONFIDENCE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.6);

    let max_body_bytes: usize = std::env::var("SIPHON_ICAP_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10 * 1024 * 1024);

    let service_name =
        std::env::var("SIPHON_ICAP_SERVICE_NAME").unwrap_or_else(|_| "dlp".to_string());

    let max_connections: usize = std::env::var("SIPHON_ICAP_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);

    let sensor = Arc::new(siphon_auth::telemetry::SensorCounters::new());
    let state = Arc::new(AppState {
        allowed_nets: Arc::new(allowed_nets),
        action,
        on_unscannable,
        min_confidence,
        max_body_bytes,
        service_name: service_name.clone(),
        max_connections,
        sensor: sensor.clone(),
    });

    // Report in, if told where. ICAP itself carries no TLS and this service
    // has no database, so the heartbeat's transport section is empty — the
    // console shows both hops as n/a, which is the truth, not a gap.
    match siphon_auth::telemetry::reporter::Settings::from_env() {
        Ok(Some(settings)) => {
            let identity = siphon_auth::telemetry::reporter::Identity {
                sensor: "siphon-icap",
                instance: siphon_auth::telemetry::instance_id(),
                version: VERSION,
                started_at: siphon_auth::chrono::Utc::now(),
                transport: siphon_auth::telemetry::Transport::default(),
            };
            // Posture: `block` stops the traffic itself; `flag` annotates and
            // lets the proxy pass it, which is audit-only from here. A scan
            // that errors returns 500 to the proxy, whose own bypass setting
            // then decides — so there is no fail mode of this sensor's own.
            // The canary runs the fixture through the same scan this sensor
            // gives a body, at the same confidence floor.
            let probe: siphon_auth::telemetry::reporter::Probe = Arc::new(move || {
                use siphon_auth::telemetry::{judge_canary, Enforcement, FailMode, Posture};
                let config = ScanConfig {
                    min_confidence,
                    ..Default::default()
                };
                let canary =
                    match scan_text_with_config(siphon_auth::telemetry::CANARY_TEXT, &config) {
                        Ok(m) => {
                            judge_canary(&m.iter().map(|m| m.category.as_str()).collect::<Vec<_>>())
                        }
                        Err(_) => judge_canary::<&str>(&[]),
                    };
                siphon_auth::telemetry::reporter::Observation {
                    posture: Posture {
                        on_finding: match action {
                            IcapAction::Block => Enforcement::Block,
                            IcapAction::Flag => Enforcement::Annotate,
                        },
                        on_indeterminate: FailMode::NotApplicable,
                        degraded: None,
                    },
                    canary: Some(canary),
                }
            });
            match siphon_auth::telemetry::reporter::Reporter::new(
                &settings, identity, sensor, probe,
            ) {
                Ok(r) => {
                    info!(endpoint = %settings.url, "telemetry enabled");
                    tokio::spawn(r.run());
                }
                Err(e) => {
                    tracing::error!(error = %e, "telemetry client could not be built; refusing to start");
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => info!("SIPHON_TELEMETRY_URL not set — this sensor will show as never seen"),
        Err(e) => {
            tracing::error!(error = %e, "telemetry misconfigured; refusing to start");
            std::process::exit(1);
        }
    }

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "icap: bind failed");
            std::process::exit(1);
        }
    };

    info!(
        service = "siphon-icap",
        version = VERSION,
        core = siphon_core::VERSION,
        bind = %addr,
        service_path = %format!("/{service_name}"),
        action = match action { IcapAction::Flag => "flag", IcapAction::Block => "block" },
        min_confidence = min_confidence,
        max_body_mb = max_body_bytes / (1024 * 1024),
        max_connections = max_connections,
        "siphon-icap starting"
    );

    let shutdown = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl-C handler");
        };
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c   => {},
            _ = terminate => {},
        }
        info!("icap: shutdown signal received, draining connections");
    };

    tokio::select! {
        _ = accept_loop(listener, state) => {},
        _ = shutdown => {},
    }

    Ok(())
}

async fn accept_loop(listener: TcpListener, state: Arc<AppState>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(state.max_connections));
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let permit = match sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(peer = %peer, "icap: max_connections reached, dropping");
                        drop(stream);
                        continue;
                    }
                };
                let state = state.clone();
                tokio::spawn(async move {
                    handle_connection(stream, peer, state).await;
                    drop(permit);
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "icap: accept error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SIPHON_ICAP_ON_UNSCANNABLE ────────────────────────────────

    /// A typo used to start an advisory sensor in a deployment that asked for
    /// an enforcing one, silently. Both knobs refuse instead.
    #[test]
    fn an_unknown_policy_value_is_refused_not_guessed() {
        for bad in ["blok", "allow", "defer", "true", "0"] {
            assert!(
                Unscannable::parse(bad).is_err(),
                "{bad:?} should be refused, not read as a policy"
            );
        }
    }

    #[test]
    fn the_policy_defaults_to_pass_and_reads_both_values() {
        assert_eq!(Unscannable::parse("").unwrap(), Unscannable::Pass);
        assert_eq!(Unscannable::parse("pass").unwrap(), Unscannable::Pass);
        assert_eq!(Unscannable::parse("block").unwrap(), Unscannable::Block);
        // Case and surrounding whitespace are the operator's, not a value.
        assert_eq!(Unscannable::parse("  BLOCK ").unwrap(), Unscannable::Block);
    }

    /// The bug: a body over the limit got a bare 204, which on the wire is
    /// the same answer as "we read it and it was clean". A proxy logging ICAP
    /// responses could not tell an unread transfer from an inspected one.
    #[test]
    fn a_pass_through_says_it_was_not_read() {
        let out = String::from_utf8(response_204_unscanned("body-exceeds-limit")).unwrap();
        assert!(out.starts_with("ICAP/1.0 204"), "still a 204: {out}");
        assert!(out.contains("X-DLP-Action: unscanned"), "{out}");
        assert!(out.contains("X-DLP-Reason: body-exceeds-limit"), "{out}");
        // A plain 204 carries neither, which is what made the two identical.
        let plain = String::from_utf8(response_204()).unwrap();
        assert!(!plain.contains("X-DLP-Action"));
    }

    /// Blocking unread content explains itself as unread, not as a finding —
    /// whoever reads the page has a different problem to solve.
    #[test]
    fn blocking_unread_content_does_not_claim_a_finding() {
        let out = String::from_utf8(response_blocked_unscanned("binary-body")).unwrap();
        assert!(out.contains("403 Forbidden"), "{out}");
        assert!(out.contains("X-DLP-Action: blocked-unscanned"), "{out}");
        assert!(out.contains("could not inspect"), "{out}");
        assert!(
            !out.contains("X-DLP-Findings"),
            "a block for unread content must not report findings: {out}"
        );
    }

    /// The canary fixture and its expected categories live in siphon-auth,
    /// which cannot scan. This is the consumer's test of the generator: the
    /// fixture, scanned as a body would be at the default confidence floor,
    /// must produce every planted category — so a pattern rename fails a
    /// build here rather than every heartbeat in production.
    #[test]
    fn the_canary_fixture_passes_through_the_real_scanner() {
        let config = ScanConfig {
            min_confidence: 0.6,
            ..Default::default()
        };
        let matches = scan_text_with_config(siphon_auth::telemetry::CANARY_TEXT, &config)
            .expect("canary text scans");
        let found: Vec<&str> = matches.iter().map(|m| m.category.as_str()).collect();
        let canary = siphon_auth::telemetry::judge_canary(&found);
        assert!(
            canary.passed,
            "canary missing {:?}; scanner produced {:?}",
            canary.missing, found
        );
    }
}
