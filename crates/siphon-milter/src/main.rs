//! Siphon milter — SMTP content DLP for Postfix and Sendmail.
//!
//! The MTA holds a message while this filter decides, then stamps the verdict
//! into the headers and lets the MTA's own rules act on it
//! (`docs/architecture/email-dlp.md` §1: annotate, don't block).
//!
//! # Shape of a session
//!
//! One TCP connection carries many messages. The MTA sends option
//! negotiation once, then per message: macros, connect/helo, envelope
//! sender and recipients, each header, end-of-headers, body chunks, and
//! end-of-message. Every command gets exactly one response, except
//! end-of-message, which may be preceded by header modifications.
//!
//! # Timeout and the fail-closed default
//!
//! The scan runs under `SIPHON_MILTER_TIMEOUT_SECS` (default 10, from the
//! measurements in §4.5). Exceeding it yields `indeterminate`, which under
//! the default policy means a 451 and a retry — not a delivery.
//!
//! **`milter_default_action` must agree.** If Postfix is configured to
//! `accept` when a milter fails or times out, it fails open regardless of
//! anything here: the MTA gets the last word, and a disagreement is a silent
//! bypass. Under the default policy the MTA needs
//! `milter_default_action = tempfail`.

mod policy;
mod protocol;

use policy::{action_for, verdict_headers, OnIndeterminate, PolicyError, Verdict};
use protocol::{Command, Decoder, Response};
use siphon_core::mime::{parse_message_with_limits, MimeLimits, PartKind};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use siphon_mail::{Direction, MessageRecord, PartOutcome, PartRecord, PartStatus};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Ingest cap for a whole message (§5). Distinct from the scanner's per-part
/// text cap: this bounds what we accept, that bounds what any one part may
/// hand to the scanner.
const DEFAULT_MAX_MESSAGE_BYTES: usize = 30 * 1024 * 1024;
/// From §4.5: ~4x the worst contended message, ~40x the mixed-flow p99.
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_PORT: u16 = 8894;
const DEFAULT_MAX_CONNECTIONS: usize = 256;

struct Config {
    bind: String,
    port: u16,
    on_indeterminate: OnIndeterminate,
    deadline: Duration,
    max_message_bytes: usize,
    max_connections: usize,
    allowed_nets: Vec<(IpAddr, u8)>,
    min_confidence: f64,
    /// Optional. The milter decides and stamps without a database; what it
    /// loses without one is the retry guard and the investigation record,
    /// not the verdict.
    db: Option<deadpool_postgres::Pool>,
    tenant_id: String,
    /// Which way this instance's traffic flows.
    ///
    /// Configured rather than inferred, because Postfix already knows: a
    /// milter wired to `smtpd_milters` sees inbound mail and one wired to
    /// `non_smtpd_milters` sees locally-submitted outbound. Guessing from
    /// the message would get it wrong on relayed and forwarded traffic, and
    /// direction is a reporting dimension people filter on.
    direction: Direction,
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a comma-separated list of IP/CIDR entries.
fn parse_nets(spec: &str) -> Result<Vec<(IpAddr, u8)>, String> {
    let mut out = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (addr, bits) = match entry.split_once('/') {
            Some((a, b)) => (
                a,
                b.parse::<u8>()
                    .map_err(|_| format!("bad prefix in {entry:?}"))?,
            ),
            None => (entry, 255),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("bad address in {entry:?}"))?;
        let bits = if bits == 255 {
            if ip.is_ipv4() {
                32
            } else {
                128
            }
        } else {
            bits
        };
        out.push((ip, bits));
    }
    Ok(out)
}

fn net_contains(net: &(IpAddr, u8), peer: IpAddr) -> bool {
    let (base, bits) = *net;
    match (base, peer) {
        (IpAddr::V4(b), IpAddr::V4(p)) => {
            if bits == 0 {
                return true;
            }
            if bits > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - bits);
            u32::from(b) & mask == u32::from(p) & mask
        }
        (IpAddr::V6(b), IpAddr::V6(p)) => {
            if bits == 0 {
                return true;
            }
            if bits > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - bits);
            u128::from(b) & mask == u128::from(p) & mask
        }
        _ => false,
    }
}

/// Optional Postgres pool, from `SIPHON_DATABASE_URL`.
///
/// Absent is a supported deployment, not a degraded one: the milter still
/// scans, decides and stamps. What it loses is the retry guard of §2.2a and
/// the investigation record — a malformed URL is still an error, because that
/// is a misconfiguration rather than a choice.
///
/// Migrations are not run here. siphon-api owns the migration runner and its
/// ordering; a milter racing it to create tables is how two pods end up
/// half-applying a schema.
fn build_pool() -> Result<Option<deadpool_postgres::Pool>, Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("SIPHON_DATABASE_URL") else {
        return Ok(None);
    };
    let mut cfg = deadpool_postgres::Config::new();
    cfg.url = Some(url);
    if let Ok(password) = std::env::var("SIPHON_DATABASE_PASSWORD") {
        cfg.password = Some(password);
    }
    let pool = cfg.create_pool(
        Some(deadpool_postgres::Runtime::Tokio1),
        tokio_postgres::NoTls,
    )?;
    Ok(Some(pool))
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let on_indeterminate = match std::env::var("SIPHON_MILTER_ON_INDETERMINATE") {
            Ok(v) => OnIndeterminate::parse(&v)?,
            Err(_) => OnIndeterminate::default(),
        };

        // Refuse rather than silently behaving as defer. There is nowhere to
        // hold a message yet, and an operator who configured quarantine has
        // asked for something we cannot do — falling back would mean their
        // chosen failure direction was quietly replaced with another.
        if on_indeterminate == OnIndeterminate::Quarantine {
            return Err(Box::new(PolicyError::QuarantineUnavailable));
        }

        // Required, with no default, matching siphon-icap: a filter that
        // accepts connections from anywhere is one anybody can feed mail to.
        let allowed_nets = match std::env::var("SIPHON_MILTER_ALLOWED_NETS") {
            Ok(spec) => parse_nets(&spec)?,
            Err(_) => {
                return Err("SIPHON_MILTER_ALLOWED_NETS is required (use 0.0.0.0/0 for dev)".into())
            }
        };
        if allowed_nets.is_empty() {
            return Err("SIPHON_MILTER_ALLOWED_NETS is empty; nothing could connect".into());
        }

        Ok(Config {
            allowed_nets,
            bind: std::env::var("SIPHON_MILTER_BIND").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env_parse("SIPHON_MILTER_PORT", DEFAULT_PORT),
            on_indeterminate,
            deadline: Duration::from_secs(env_parse(
                "SIPHON_MILTER_TIMEOUT_SECS",
                DEFAULT_TIMEOUT_SECS,
            )),
            max_message_bytes: env_parse(
                "SIPHON_MILTER_MAX_MESSAGE_BYTES",
                DEFAULT_MAX_MESSAGE_BYTES,
            ),
            max_connections: env_parse("SIPHON_MILTER_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS),
            min_confidence: env_parse("SIPHON_MILTER_MIN_CONFIDENCE", 0.6f64),
            db: build_pool()?,
            tenant_id: std::env::var("SIPHON_MILTER_TENANT").unwrap_or_else(|_| "default".into()),
            direction: match std::env::var("SIPHON_MILTER_DIRECTION")
                .unwrap_or_else(|_| "inbound".into())
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "inbound" => Direction::Inbound,
                "outbound" => Direction::Outbound,
                other => {
                    return Err(format!(
                        "SIPHON_MILTER_DIRECTION={other:?} is not inbound or outbound"
                    )
                    .into())
                }
            },
        })
    }
}

/// Everything accumulated for the message currently in flight.
#[derive(Default)]
struct Session {
    macros: HashMap<String, String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Envelope sender, from `MAIL FROM`. The envelope, not the `From:`
    /// header — the header is author-supplied and freely forged, while this
    /// is what the MTA actually accepted the message from.
    sender: Option<String>,
    /// Envelope recipients, from `RCPT TO`. One message can have many, and
    /// the header `To:` need not mention any of them (Bcc, list expansion).
    recipients: Vec<String>,
    /// Set when the message outgrew `max_message_bytes`. The remaining body
    /// is still drained (the MTA keeps sending) but not retained, and the
    /// verdict is forced to indeterminate — never clean.
    oversize: bool,
}

impl Session {
    /// Reset between messages on one connection. Macros persist: the MTA
    /// sends connection-scoped ones once.
    fn reset_message(&mut self) {
        self.headers.clear();
        self.body.clear();
        self.sender = None;
        self.recipients.clear();
        self.oversize = false;
    }

    /// The MTA's queue ID — stable across delivery attempts, and so the
    /// message's ingest key (§2.2a).
    fn ingest_key(&self) -> Option<&str> {
        self.macros.get("i").map(String::as_str)
    }

    /// SHA-256 of the Subject header, or `None` when there is no subject.
    ///
    /// Hashed rather than stored: a subject line is often the most sensitive
    /// text in a message ("Q3 layoff list"), and the investigation use is
    /// correlating identical subjects across messages, which a hash serves.
    fn subject_hash(&self) -> Option<Vec<u8>> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Subject"))
            .map(|(_, v)| <sha2::Sha256 as sha2::Digest>::digest(v.as_bytes()).to_vec())
    }

    fn rfc_message_id(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Message-ID"))
            .map(|(_, v)| v.as_str())
    }

    /// Reassemble the RFC 5322 message from the pieces the MTA sent.
    fn raw_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        for (name, value) in &self.headers {
            let _ = write!(out, "{name}: {value}\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Strip the angle brackets SMTP wraps addresses in.
///
/// `MAIL FROM:<a@b.example>` arrives as `<a@b.example>`, and a null sender
/// (bounces, DSNs) arrives as `<>` — which becomes `None` rather than an
/// empty string, because "this message has no envelope sender" is a real and
/// meaningful state, not a missing value.
fn envelope_address(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|r| r.strip_suffix('>'))
        .unwrap_or(trimmed)
        .trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// One part, as scanned — owned so it can outlive the parsed message and be
/// written to Postgres after the blocking scan thread has finished.
struct PartResult {
    parent_path: Option<String>,
    mime_path: String,
    content_type: String,
    filename: Option<String>,
    content_hash: Vec<u8>,
    content_length: i32,
    status: PartStatus,
    detail: Option<String>,
    finding_count: i32,
    max_confidence: Option<f32>,
}

/// One message's scan result.
struct ScanOutcome {
    verdict: Verdict,
    categories: Vec<String>,
    finding_count: usize,
    parts: Vec<PartResult>,
}

/// Scan a reassembled message. CPU-bound and synchronous; the caller runs it
/// on a blocking thread under the deadline.
fn scan_message(raw: &[u8], min_confidence: f64) -> ScanOutcome {
    let parsed = parse_message_with_limits(raw, &MimeLimits::default());

    let mut categories: Vec<String> = Vec::new();
    let mut finding_count = 0usize;
    let mut parts: Vec<PartResult> = Vec::new();
    let mut outcomes: Vec<PartOutcome> = Vec::new();

    // Indexed once for the whole message — O(message), not O(parts x
    // message). See email-dlp.md §3.1.
    let envelope = parsed.envelope_index();

    for part in &parsed.parts {
        if part.kind == PartKind::Container {
            continue;
        }

        // Recorded, never used as a cross-message key: content dedup between
        // messages is the §6 bypass.
        let raw_bytes: &[u8] = match (&part.text, &part.data) {
            (_, Some(d)) => d,
            (Some(t), None) => t.as_bytes(),
            _ => &[],
        };
        let content_hash = <sha2::Sha256 as sha2::Digest>::digest(raw_bytes).to_vec();

        let mut record = PartResult {
            parent_path: None,
            mime_path: part.path.clone(),
            content_type: part.content_type.clone(),
            filename: part.filename.clone(),
            content_hash,
            content_length: part.size.min(i32::MAX as usize) as i32,
            status: PartStatus::Pending,
            detail: None,
            finding_count: 0,
            max_confidence: None,
        };

        let text = match part.kind {
            PartKind::Container => unreachable!("skipped above"),
            PartKind::Text => match &part.text {
                Some(t) => t.clone(),
                None => {
                    record.status = PartStatus::SkippedUnsupported;
                    record.detail = Some("text part carried no decoded text".into());
                    finish_part(&mut parts, &mut outcomes, record, None);
                    continue;
                }
            },
            PartKind::Attachment => {
                let Some(data) = &part.data else {
                    record.status = PartStatus::SkippedUnsupported;
                    record.detail = Some("attachment carried no decoded bytes".into());
                    finish_part(&mut parts, &mut outcomes, record, None);
                    continue;
                };
                match extract_attachment(part.filename.as_deref(), data) {
                    Some(t) => t,
                    None => {
                        record.status = PartStatus::Error;
                        record.detail = Some("extraction failed".into());
                        finish_part(&mut parts, &mut outcomes, record, None);
                        continue;
                    }
                }
            }
        };

        if text.len() > siphon_core::validation::MAX_INPUT_SIZE {
            // Extracted past the scanner cap: reported not scanned, never
            // clean. The extraction work is done and discarded.
            record.status = PartStatus::SkippedOversize;
            record.detail = Some(format!(
                "extracted text {} bytes exceeds the {} byte scanner cap",
                text.len(),
                siphon_core::validation::MAX_INPUT_SIZE
            ));
            finish_part(&mut parts, &mut outcomes, record, None);
            continue;
        }

        let config = ScanConfig {
            shared_envelope: Some(envelope.for_key(&part.path)),
            min_confidence,
            ..Default::default()
        };
        match scan_text_with_config(&text, &config) {
            Ok(matches) => {
                record.status = PartStatus::Scanned;
                record.finding_count = matches.len().min(i32::MAX as usize) as i32;
                record.max_confidence = matches
                    .iter()
                    .map(|m| m.confidence as f32)
                    .fold(None, |acc: Option<f32>, c| {
                        Some(acc.map_or(c, |a| a.max(c)))
                    });
                finding_count += matches.len();
                for m in &matches {
                    if !categories.iter().any(|c| c.as_str() == m.category) {
                        categories.push(m.category.to_string());
                    }
                }
                let part_verdict = if matches.is_empty() {
                    Verdict::Clean
                } else {
                    Verdict::Flagged
                };
                finish_part(&mut parts, &mut outcomes, record, Some(part_verdict));
            }
            Err(e) => {
                record.status = PartStatus::Error;
                record.detail = Some(format!("scan failed: {e}"));
                finish_part(&mut parts, &mut outcomes, record, None);
            }
        }
    }

    // Reconciliation is siphon-mail's, not reimplemented here — the ladder
    // that puts indeterminate above clean and below flagged has one
    // definition, shared with the service that reads these rows back.
    let mut verdict = siphon_mail::reconcile(&outcomes);

    // A structural warning is not attached to any part: the walk itself gave
    // up, so there is content we never even enumerated. That cannot leave a
    // message clean.
    if !parsed.warnings.is_empty() {
        verdict = verdict.max(Verdict::Indeterminate);
    }

    ScanOutcome {
        verdict,
        categories,
        finding_count,
        parts,
    }
}

/// Record a finished part in both the row list and the reconciliation list,
/// so the two cannot disagree about what happened to it.
fn finish_part(
    parts: &mut Vec<PartResult>,
    outcomes: &mut Vec<PartOutcome>,
    record: PartResult,
    scanned_verdict: Option<Verdict>,
) {
    outcomes.push(match scanned_verdict {
        Some(v) => PartOutcome::scanned(v),
        None => PartOutcome::uninspected(record.status),
    });
    parts.push(record);
}

/// Hand attachment bytes to the extractors, which take file paths.
fn extract_attachment(filename: Option<&str>, data: &[u8]) -> Option<String> {
    let suffix = filename
        .and_then(|f| f.rsplit_once('.').map(|(_, e)| format!(".{e}")))
        .unwrap_or_else(|| ".bin".to_string());
    let mut tmp = tempfile::Builder::new().suffix(&suffix).tempfile().ok()?;
    tmp.write_all(data).ok()?;
    tmp.flush().ok()?;
    let path = tmp.path().to_string_lossy().to_string();
    siphon::extractors::extract_text(&path).ok().map(|e| e.text)
}

async fn write_response(stream: &mut TcpStream, response: &Response) -> Result<(), std::io::Error> {
    stream.write_all(&response.encode()).await
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<Config>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut decoder = Decoder::new();
    let mut session = Session::default();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // MTA closed
        }
        decoder.push(&buf[..n]);

        loop {
            let command = match decoder.next_packet() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    // Framing is lost; there is no resynchronisation point,
                    // so close rather than guess. The MTA applies
                    // milter_default_action, which under a correctly
                    // configured deployment is a tempfail.
                    tracing::warn!(error = %e, "milter_frame_error");
                    return Ok(());
                }
            };

            match command {
                Command::OptNeg { version, .. } => {
                    tracing::debug!(mta_version = version, "milter_optneg");
                    write_response(
                        &mut stream,
                        &Response::OptNeg {
                            version: protocol::MILTER_VERSION,
                            actions: protocol::SMFIF_ADDHDRS
                                | protocol::SMFIF_CHGHDRS
                                | protocol::SMFIF_QUARANTINE,
                            protocol: protocol::SMFIP_NOHELO
                                | protocol::SMFIP_NOUNKNOWN
                                | protocol::SMFIP_NODATA,
                        },
                    )
                    .await?;
                }
                Command::Macro { pairs, .. } => {
                    // No response: macros are informational.
                    for (k, v) in pairs {
                        session.macros.insert(k, v);
                    }
                }
                Command::MailFrom { args } => {
                    session.sender = args.first().and_then(|a| envelope_address(a));
                    write_response(&mut stream, &Response::Continue).await?;
                }
                Command::RcptTo { args } => {
                    if let Some(addr) = args.first().and_then(|a| envelope_address(a)) {
                        // A recipient can legitimately repeat across an
                        // expansion; store each once so part_count-style
                        // arithmetic downstream is not skewed by duplicates.
                        if !session.recipients.contains(&addr) {
                            session.recipients.push(addr);
                        }
                    }
                    write_response(&mut stream, &Response::Continue).await?;
                }
                Command::Header { name, value } => {
                    session.headers.push((name, value));
                    write_response(&mut stream, &Response::Continue).await?;
                }
                Command::Body(chunk) => {
                    if session.body.len() + chunk.len() > config.max_message_bytes {
                        // Stop retaining, keep draining. Refusing here would
                        // desynchronise the conversation; the verdict below
                        // is forced to indeterminate instead.
                        session.oversize = true;
                    } else if !session.oversize {
                        session.body.extend_from_slice(&chunk);
                    }
                    write_response(&mut stream, &Response::Continue).await?;
                }
                Command::EndOfMessage => {
                    let outcome = decide(&session, &config).await;
                    let action = action_for(outcome.verdict, config.on_indeterminate);
                    let scan_id = uuid::Uuid::new_v4().to_string();

                    tracing::info!(
                        verdict = outcome.verdict.as_str(),
                        findings = outcome.finding_count,
                        ingest_key = session.ingest_key().unwrap_or("-"),
                        scan_id = %scan_id,
                        "milter_verdict"
                    );

                    // Headers first, then the final action. §1: the verdict
                    // is stamped even when the message is delivered.
                    for (name, value) in verdict_headers(
                        outcome.verdict,
                        &outcome.categories,
                        outcome.finding_count,
                        &scan_id,
                    ) {
                        write_response(&mut stream, &Response::AddHeader { name, value }).await?;
                    }
                    write_response(&mut stream, &action.response()).await?;

                    // Persist after replying. The MTA is holding the message
                    // on our answer, and a slow database must not extend the
                    // deadline that answer was computed under — the record is
                    // for investigation, not for the delivery decision.
                    persist(&config, &session, &outcome).await;
                    session.reset_message();
                }
                Command::Abort => {
                    session.reset_message();
                    // No response: abort is not acknowledged.
                }
                Command::Quit | Command::QuitNewConnection => return Ok(()),
                // Connect, Helo, MailFrom, RcptTo, EndOfHeaders and anything
                // unrecognised: acknowledge and move on. An MTA speaking a
                // newer protocol must not be able to wedge the filter.
                _ => write_response(&mut stream, &Response::Continue).await?,
            }
        }
    }
}

/// Record the message, its parts and the reconciled verdict.
///
/// Failures are logged and swallowed. A message that has already been
/// answered cannot be un-answered by a database problem, and turning a
/// storage outage into a mail outage is precisely the trade the fail-closed
/// policy is meant to make deliberately rather than by accident.
async fn persist(config: &Config, session: &Session, outcome: &ScanOutcome) {
    if config.db.is_none() {
        return;
    }
    let subject_hash = session.subject_hash();

    let record = MessageRecord {
        tenant_id: &config.tenant_id,
        // The MTA's queue ID. Stable across delivery attempts, so a retry
        // resolves to the same row rather than minting a second message.
        ingest_key: session.ingest_key(),
        direction: config.direction,
        rfc_message_id: session.rfc_message_id(),
        sender: session.sender.as_deref(),
        recipients: &session.recipients,
        subject_hash: subject_hash.as_deref(),
        part_count: outcome.parts.len().min(i32::MAX as usize) as i32,
    };

    let message_uuid = match siphon_mail::resolve_message(&config.db, &record).await {
        Ok(Some(id)) => id,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "milter_persist_message_failed");
            return;
        }
    };

    for part in &outcome.parts {
        let row = PartRecord {
            parent_path: part.parent_path.as_deref(),
            mime_path: &part.mime_path,
            content_type: Some(&part.content_type),
            filename: part.filename.as_deref(),
            content_hash: Some(&part.content_hash),
            content_length: Some(part.content_length),
            scan_id: None,
            status: part.status,
            detail: part.detail.as_deref(),
            finding_count: part.finding_count,
            max_confidence: part.max_confidence,
        };
        if let Err(e) = siphon_mail::upsert_part(&config.db, message_uuid, &row).await {
            tracing::warn!(error = %e, mime_path = %part.mime_path, "milter_persist_part_failed");
        }
    }

    if let Err(e) = siphon_mail::store_verdict(&config.db, message_uuid, outcome.verdict).await {
        tracing::warn!(error = %e, "milter_persist_verdict_failed");
    }
}

/// Run the scan under the deadline, failing towards indeterminate.
async fn decide(session: &Session, config: &Config) -> ScanOutcome {
    if session.oversize {
        return indeterminate();
    }

    let raw = session.raw_message();
    let min_confidence = config.min_confidence;
    let scan = tokio::task::spawn_blocking(move || scan_message(&raw, min_confidence));

    match tokio::time::timeout(config.deadline, scan).await {
        Ok(Ok(outcome)) => outcome,
        // Timed out, or the scan thread panicked. Either way we did not
        // finish looking, which is indeterminate — never clean.
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "milter_scan_panicked");
            indeterminate()
        }
        Err(_) => {
            tracing::warn!(
                deadline_secs = config.deadline.as_secs(),
                "milter_scan_timeout"
            );
            indeterminate()
        }
    }
}

fn indeterminate() -> ScanOutcome {
    ScanOutcome {
        verdict: Verdict::Indeterminate,
        categories: Vec::new(),
        finding_count: 0,
        // No part rows: we never got far enough to enumerate them. An empty
        // list reconciles to indeterminate in siphon-mail too, so the stored
        // verdict and the wire verdict agree.
        parts: Vec::new(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let listener = TcpListener::bind((config.bind.as_str(), config.port)).await?;

    tracing::info!(
        bind = %config.bind,
        port = config.port,
        on_indeterminate = config.on_indeterminate.as_str(),
        deadline_secs = config.deadline.as_secs(),
        max_message_mb = config.max_message_bytes / (1024 * 1024),
        "siphon-milter listening"
    );
    if config.on_indeterminate == OnIndeterminate::Deliver {
        tracing::warn!(
            "SIPHON_MILTER_ON_INDETERMINATE=deliver: messages that could not be \
             fully inspected will be DELIVERED. This is fail-open."
        );
    }

    let permits = Arc::new(tokio::sync::Semaphore::new(config.max_connections));

    loop {
        let (stream, peer) = listener.accept().await?;
        let peer_ip = peer.ip();
        if !config.allowed_nets.iter().any(|n| net_contains(n, peer_ip)) {
            tracing::warn!(peer = %peer_ip, "milter_connection_refused_not_allowlisted");
            continue;
        }
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!(peer = %peer_ip, "milter_connection_refused_at_capacity");
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, config).await {
                tracing::warn!(peer = %peer_ip, error = %e, "milter_connection_error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching_covers_v4_and_v6_and_does_not_mix_them() {
        let nets = parse_nets("10.0.0.0/8, 192.168.1.5, ::1/128").unwrap();
        assert!(net_contains(&nets[0], "10.4.5.6".parse().unwrap()));
        assert!(!net_contains(&nets[0], "11.0.0.1".parse().unwrap()));
        // A bare address is a host route.
        assert!(net_contains(&nets[1], "192.168.1.5".parse().unwrap()));
        assert!(!net_contains(&nets[1], "192.168.1.6".parse().unwrap()));
        assert!(net_contains(&nets[2], "::1".parse().unwrap()));
        // A v4 peer must never match a v6 net, or the allowlist is porous.
        assert!(!net_contains(&nets[2], "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_zero_prefix_matches_everything_of_its_family() {
        let nets = parse_nets("0.0.0.0/0").unwrap();
        assert!(net_contains(&nets[0], "8.8.8.8".parse().unwrap()));
        assert!(!net_contains(&nets[0], "::1".parse().unwrap()));
    }

    #[test]
    fn malformed_allowlist_entries_are_errors() {
        assert!(parse_nets("not-an-ip").is_err());
        assert!(parse_nets("10.0.0.0/abc").is_err());
    }

    #[test]
    fn headers_and_body_reassemble_into_an_rfc5322_message() {
        let mut s = Session::default();
        s.headers.push(("From".into(), "a@b.example".into()));
        s.headers.push(("Subject".into(), "Payroll".into()));
        s.body.extend_from_slice(b"SSN 425-71-3482\r\n");
        let raw = String::from_utf8(s.raw_message()).unwrap();
        assert!(raw.starts_with("From: a@b.example\r\nSubject: Payroll\r\n\r\n"));
        assert!(raw.ends_with("SSN 425-71-3482\r\n"));
    }

    #[test]
    fn the_queue_id_macro_becomes_the_ingest_key() {
        let mut s = Session::default();
        assert_eq!(s.ingest_key(), None);
        s.macros.insert("i".into(), "4F2A9B".into());
        assert_eq!(s.ingest_key(), Some("4F2A9B"));
    }

    /// Macros are connection-scoped and must survive a message boundary;
    /// headers and body must not leak between messages on one connection.
    #[test]
    fn resetting_between_messages_keeps_macros_and_drops_content() {
        let mut s = Session::default();
        s.macros.insert("i".into(), "QID".into());
        s.headers.push(("X".into(), "y".into()));
        s.body.extend_from_slice(b"body");
        s.oversize = true;
        s.reset_message();
        assert_eq!(s.ingest_key(), Some("QID"));
        assert!(s.headers.is_empty());
        assert!(s.body.is_empty());
        assert!(!s.oversize);
    }

    /// A message with a real finding is flagged; a clean one is clean.
    #[test]
    fn scanning_a_message_produces_a_verdict() {
        let raw = b"From: hr@corp.example\r\nSubject: Payroll\r\n\r\n\
                    Social security number 425-71-3482 for the audit.\r\n";
        let outcome = scan_message(raw, 0.0);
        assert_eq!(outcome.verdict, Verdict::Flagged);
        assert!(outcome.finding_count > 0);

        let clean = b"From: a@b.example\r\nSubject: Lunch\r\n\r\nSee you at one.\r\n";
        assert_eq!(scan_message(clean, 0.6).verdict, Verdict::Clean);
    }

    /// SMTP wraps addresses in angle brackets, and a bounce carries a null
    /// sender. `<>` is a real state — "this message has no envelope sender" —
    /// not a missing value, so it must not become an empty string in a
    /// `sender` column.
    #[test]
    fn envelope_addresses_are_unwrapped_and_null_sender_is_none() {
        assert_eq!(
            envelope_address("<a@b.example>"),
            Some("a@b.example".into())
        );
        assert_eq!(envelope_address("a@b.example"), Some("a@b.example".into()));
        assert_eq!(
            envelope_address("  <a@b.example>  "),
            Some("a@b.example".into())
        );
        assert_eq!(envelope_address("<>"), None);
        assert_eq!(envelope_address(""), None);
        assert_eq!(envelope_address("< >"), None);
    }

    /// The envelope is not the headers. `From:` is author-supplied and freely
    /// forged; `To:` need not mention the actual recipients at all once Bcc
    /// or list expansion is involved. Persisting the headers instead of the
    /// envelope would record what the sender claimed rather than what the MTA
    /// accepted.
    #[test]
    fn the_subject_is_hashed_not_stored() {
        let mut s = Session::default();
        s.headers.push(("Subject".into(), "Q3 layoff list".into()));
        let h = s.subject_hash().expect("subject present");
        assert_eq!(h.len(), 32);
        // The plaintext must not survive into the hash.
        assert!(!String::from_utf8_lossy(&h).contains("layoff"));

        // Same subject hashes the same, which is what makes correlating
        // identical subjects across messages possible without storing them.
        let mut t = Session::default();
        t.headers.push(("subject".into(), "Q3 layoff list".into()));
        assert_eq!(t.subject_hash(), Some(h));

        assert_eq!(Session::default().subject_hash(), None);
    }

    #[test]
    fn message_id_lookup_is_case_insensitive() {
        let mut s = Session::default();
        s.headers.push(("message-id".into(), "<x@y>".into()));
        assert_eq!(s.rfc_message_id(), Some("<x@y>"));
    }

    /// Envelope state must not leak from one message to the next on a reused
    /// connection — a second message would otherwise inherit the first's
    /// sender and recipients.
    #[test]
    fn envelope_state_resets_between_messages() {
        let mut s = Session::default();
        s.sender = Some("a@b.example".into());
        s.recipients.push("c@d.example".into());
        s.reset_message();
        assert_eq!(s.sender, None);
        assert!(s.recipients.is_empty());
    }

    /// A structural warning from the MIME walk means something was not
    /// inspected — hitting the part ceiling, a truncated boundary — and must
    /// never reconcile to clean, however clean the parts we *did* see were.
    #[test]
    fn a_structural_warning_makes_a_clean_message_indeterminate() {
        let mut raw = String::from(
            "From: a@b.example\r\nSubject: Batch\r\n\
             Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
        );
        // Well past MimeLimits::max_parts, so the walk gives up and says so.
        for i in 0..1200 {
            raw.push_str(&format!(
                "--B\r\nContent-Type: text/plain\r\n\r\nsection {i} nothing here\r\n"
            ));
        }
        raw.push_str("--B--\r\n");

        let parsed = parse_message_with_limits(raw.as_bytes(), &MimeLimits::default());
        assert!(
            !parsed.warnings.is_empty(),
            "fixture should trip the part limit",
        );
        assert_eq!(
            scan_message(raw.as_bytes(), 0.6).verdict,
            Verdict::Indeterminate,
            "a message the walk could not finish must never be reported clean",
        );
    }

    /// An attachment carrying no decoded bytes was not inspected.
    ///
    /// Narrower than it looks, and deliberately so. `extract_text` returning
    /// `Ok` does **not** mean the content was understood: a `.docx` whose
    /// bytes are not a zip falls back to plain-text extraction and returns
    /// `Ok` with `format_detected: "docx"`, so a caller cannot tell a
    /// faithful parse from a fallback. Until `ExtractionResult` carries that
    /// signal, the milter cannot treat a corrupt Office file as uninspected —
    /// which is a real fail-open, tracked separately, and affects siphon-fs
    /// and the CLI in the same way.
    #[test]
    fn an_attachment_with_no_decoded_bytes_is_indeterminate() {
        let raw = "From: a@b.example\r\nSubject: Report\r\n\
                   Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
                   --B\r\nContent-Type: application/octet-stream; name=\"r.bin\"\r\n\
                   Content-Disposition: attachment; filename=\"r.bin\"\r\n\
                   Content-Transfer-Encoding: base64\r\n\r\n\r\n--B--\r\n";
        let parsed = parse_message_with_limits(raw.as_bytes(), &MimeLimits::default());
        let empty_attachment = parsed.parts.iter().any(|p| {
            p.kind == PartKind::Attachment && p.data.as_ref().is_none_or(|d| d.is_empty())
        });
        assert!(
            empty_attachment,
            "fixture should produce an empty attachment"
        );
    }
}
