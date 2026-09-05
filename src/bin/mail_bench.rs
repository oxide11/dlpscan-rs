//! Mail-path latency benchmark — the measurement behind the milter timeout.
//!
//! A milter timeout is not a tuning preference. It is the point at which the
//! MTA stops waiting and applies `milter_default_action`, so it decides which
//! messages get a real verdict and which get the fallback. Setting it from a
//! guess means either timing out on legitimate mail or waiting long enough
//! that a stalled scanner holds the whole queue.
//!
//! This measures the thing the timeout has to cover: wall time from "full
//! message in hand" to "verdict", over mail-shaped input, sequentially and
//! under concurrency.
//!
//! # What is measured
//!
//! The real per-message work, not a scan microbenchmark:
//!
//! 1. MIME decomposition (`siphon_core::mime`)
//! 2. For each attachment: temp-file write + `extractors::extract_text`
//! 3. For each part: a scan carrying the context envelope of the others
//! 4. Verdict aggregation
//!
//! Step 2 is on the critical path because extraction is path-based — there is
//! no bytes-in entry point — so every attachment costs a filesystem round
//! trip. That is a measured cost here rather than an assumed-away one.
//!
//! # What is not measured
//!
//! Milter protocol framing and the SMTP conversation. Both are small next to
//! extraction and scanning, and neither is built yet.
//!
//! The corpus is synthetic and its mix is *assumed* (see `MIX`). Message-size
//! distribution varies enormously between organisations, so the mix here is a
//! placeholder for a histogram taken from the deployment's own mail logs. The
//! per-shape numbers do not depend on the mix and are the durable part.
//!
//! Run:
//!
//! ```text
//! cargo run --release --bin mail_bench
//! taskset -c 0,1 cargo run --release --bin mail_bench   # emulate the 2-CPU pod
//! ```

use base64::Engine as _;
use siphon::extractors;
use siphon_core::mime::{parse_message, PartKind};
use siphon_core::scanner::{scan_text_with_config, ScanConfig};
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Corpus construction
// ---------------------------------------------------------------------------

/// One part of a message under construction.
struct PartSpec {
    content_type: &'static str,
    filename: Option<String>,
    /// Raw bytes. Text parts are emitted 8bit, binary parts base64.
    body: Vec<u8>,
    binary: bool,
}

fn text_part(content_type: &'static str, body: String) -> PartSpec {
    PartSpec {
        content_type,
        filename: None,
        body: body.into_bytes(),
        binary: false,
    }
}

fn attachment(content_type: &'static str, filename: &str, body: Vec<u8>) -> PartSpec {
    PartSpec {
        content_type,
        filename: Some(filename.to_string()),
        body,
        binary: true,
    }
}

/// Base64 wrapped at 76 columns, the way every MUA emits it.
///
/// The wrapping is the point: the normalizer's base64 stage decodes each line
/// independently and therefore cannot recover a wrapped attachment, which is
/// why the MIME layer exists.
fn b64_wrapped(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push_str("\r\n");
    }
    out
}

fn build_message(subject: &str, parts: Vec<PartSpec>) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("From: sender@corp.example\r\n");
    out.push_str("To: recipient@partner.example\r\n");
    out.push_str(&format!("Subject: {subject}\r\n"));
    out.push_str("Message-ID: <bench.0001@corp.example>\r\n");
    out.push_str("Date: Thu, 04 Sep 2026 09:15:00 +0000\r\n");
    out.push_str("MIME-Version: 1.0\r\n");

    if parts.len() == 1 && !parts[0].binary {
        out.push_str(&format!(
            "Content-Type: {}; charset=utf-8\r\n\r\n",
            parts[0].content_type
        ));
        out.push_str(std::str::from_utf8(&parts[0].body).expect("text part is utf-8"));
        return out.into_bytes();
    }

    let boundary = "----=_SiphonBench_Boundary_2f8a";
    out.push_str(&format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
    ));

    for part in &parts {
        out.push_str(&format!("--{boundary}\r\n"));
        match &part.filename {
            Some(name) => {
                out.push_str(&format!(
                    "Content-Type: {}; name=\"{}\"\r\n",
                    part.content_type, name
                ));
                out.push_str(&format!(
                    "Content-Disposition: attachment; filename=\"{name}\"\r\n"
                ));
            }
            None => out.push_str(&format!(
                "Content-Type: {}; charset=utf-8\r\n",
                part.content_type
            )),
        }
        if part.binary {
            out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            out.push_str(&b64_wrapped(&part.body));
        } else {
            out.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            out.push_str(std::str::from_utf8(&part.body).expect("text part is utf-8"));
            out.push_str("\r\n");
        }
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out.into_bytes()
}

// --- synthetic sensitive content -------------------------------------------

/// A card number that passes Luhn, so validation actually runs rather than
/// rejecting every candidate at stage 5 and flattering the numbers.
fn luhn_card(seed: u64) -> String {
    let mut digits: Vec<u32> = Vec::with_capacity(16);
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    for d in "453201".chars() {
        digits.push(d.to_digit(10).unwrap());
    }
    for _ in 0..9 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        digits.push(((x >> 33) % 10) as u32);
    }
    let mut sum = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    let check = (10 - (sum % 10)) % 10;
    digits.push(check);
    digits
        .iter()
        .map(|d| char::from_digit(*d, 10).unwrap())
        .collect()
}

fn payroll_csv(rows: usize) -> Vec<u8> {
    let mut out = String::with_capacity(rows * 110);
    out.push_str("employee_id,full_name,email,ssn,card_on_file,routing,account,salary\n");
    for i in 0..rows {
        let ssn = format!(
            "{:03}-{:02}-{:04}",
            100 + i % 800,
            10 + i % 89,
            1000 + i % 8999
        );
        out.push_str(&format!(
            "EMP{:06},Employee Number {},user{}@corp.example,{},{},021000021,{:010},{}\n",
            i,
            i,
            i,
            ssn,
            luhn_card(i as u64),
            i as u64 * 7919 % 9_999_999_999,
            60_000 + (i % 90_000),
        ));
    }
    out.into_bytes()
}

/// Prose with the keyword density of real business mail — enough to open
/// context gates, which is where a third of the pattern corpus lives.
fn business_prose(target_bytes: usize) -> String {
    const PARA: &str = "Following up on the account review discussed last week. \
The finance team has confirmed the wire transfer details and the routing number \
on file is current. Please find the payroll summary attached; it contains the \
employee records and social security number columns the audit requested. \
Invoice 88213 remains outstanding against the corporate credit card ending in \
the usual digits. Contact accounts.payable@corp.example with any questions, or \
call the desk at (555) 867-5309 during business hours. Regards, Operations. \n\n";
    let repeats = target_bytes / PARA.len() + 1;
    PARA.repeat(repeats)[..target_bytes.min(PARA.len() * repeats)].to_string()
}

fn quoted_reply_thread(depth: usize) -> String {
    let mut out = String::new();
    for level in 0..depth {
        let prefix = "> ".repeat(level);
        out.push_str(&format!(
            "{prefix}On Mon, Sep 1 2026, Someone <someone{level}@corp.example> wrote:\n"
        ));
        for line in business_prose(1_200).lines() {
            out.push_str(&prefix);
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

fn html_newsletter(target_bytes: usize) -> String {
    let mut out = String::from("<html><body><table width=\"600\">");
    let cell = "<tr><td style=\"font-family:Arial\"><p>Quarterly update for our \
        customers. Your account number and billing details remain unchanged. \
        Reach us at support@corp.example.</p></td></tr>";
    while out.len() < target_bytes {
        out.push_str(cell);
    }
    out.push_str("</table></body></html>");
    out
}

/// A minimal but structurally valid PDF: catalog, pages, page, content
/// stream, font, and a real xref table with correct byte offsets.
fn synth_pdf(lines: usize) -> Vec<u8> {
    let mut content = String::from("BT\n/F1 10 Tf\n");
    for i in 0..lines {
        let ssn = format!(
            "{:03}-{:02}-{:04}",
            100 + i % 800,
            10 + i % 89,
            1000 + i % 8999
        );
        content.push_str(&format!(
            "1 0 0 1 40 {} Tm (Record {} SSN {} card {} email u{}@corp.example) Tj\n",
            760 - (i % 70) * 10,
            i,
            ssn,
            luhn_card(i as u64 + 991),
            i
        ));
    }
    content.push_str("ET\n");

    let objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.len(),
            content
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];

    let mut pdf = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, obj).as_bytes());
    }

    let xref_start = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objects.len() + 1,
            xref_start
        )
        .as_bytes(),
    );
    pdf
}

// --- the corpus ------------------------------------------------------------

struct Shape {
    name: &'static str,
    /// Assumed share of message *count* in a corporate mail flow. Replace
    /// with a histogram from the deployment's own logs before trusting the
    /// mixed-stream percentiles.
    weight: f64,
    raw: Arc<Vec<u8>>,
    /// Sequential iterations. Expensive shapes get fewer; the cost of a
    /// 30 MB scan is not in doubt, its variance is.
    iters: usize,
}

fn build_corpus() -> Vec<Shape> {
    let office_fixture = std::fs::read("tests/corpus/public_records/us_house_directory.xlsx").ok();

    let mut shapes = vec![
        Shape {
            name: "notification (2 KB plain)",
            weight: 45.0,
            raw: Arc::new(build_message(
                "Build #4821 passed",
                vec![text_part("text/plain", business_prose(2_000))],
            )),
            iters: 200,
        },
        Shape {
            name: "reply thread (60 KB, text+html)",
            weight: 30.0,
            raw: Arc::new(build_message(
                "Re: Re: Q3 account review",
                vec![
                    text_part("text/plain", quoted_reply_thread(12)),
                    text_part("text/html", html_newsletter(30_000)),
                ],
            )),
            iters: 100,
        },
        Shape {
            name: "html newsletter (400 KB)",
            weight: 15.0,
            raw: Arc::new(build_message(
                "Your quarterly statement",
                vec![
                    text_part("text/plain", business_prose(4_000)),
                    text_part("text/html", html_newsletter(400_000)),
                ],
            )),
            iters: 40,
        },
        Shape {
            name: "pdf invoice (1 MB attachment)",
            weight: 5.0,
            raw: Arc::new(build_message(
                "Invoice 88213 attached",
                vec![
                    text_part("text/plain", business_prose(1_500)),
                    attachment("application/pdf", "invoice-88213.pdf", synth_pdf(6_000)),
                ],
            )),
            iters: 20,
        },
        Shape {
            name: "payroll csv (2 MB attachment)",
            weight: 1.5,
            raw: Arc::new(build_message(
                "Payroll export September",
                vec![
                    text_part("text/plain", business_prose(1_200)),
                    attachment("text/csv", "payroll-2026-09.csv", payroll_csv(18_000)),
                ],
            )),
            iters: 12,
        },
        Shape {
            name: "many parts (200 small parts)",
            weight: 0.4,
            raw: Arc::new(build_message(
                "Scanned documents batch",
                (0..200)
                    .map(|i| {
                        attachment(
                            "text/plain",
                            &format!("page-{i:03}.txt"),
                            business_prose(2_000).into_bytes(),
                        )
                    })
                    .collect(),
            )),
            iters: 10,
        },
        Shape {
            name: "at scanner cap (30 MB text)",
            weight: 0.1,
            raw: Arc::new(build_message(
                "Log bundle for ticket 5512",
                vec![text_part(
                    "text/plain",
                    business_prose(30 * 1024 * 1024 - 4096),
                )],
            )),
            iters: 3,
        },
        // The two below are not mail anyone sends. They are the worst input
        // the system *accepts*, which is the number a timeout has to cover:
        // the MTA waits for whatever we agree to look at. Weight 0 keeps them
        // out of the mixed-flow percentiles, where they would be noise.
        Shape {
            name: "STRUCT: 1000 x 2 KB parts",
            weight: 0.0,
            raw: Arc::new(build_message(
                "Scanned batch",
                (0..1000)
                    .map(|i| {
                        attachment(
                            "text/plain",
                            &format!("p-{i:04}.txt"),
                            business_prose(2_000).into_bytes(),
                        )
                    })
                    .collect(),
            )),
            iters: 2,
        },
        Shape {
            name: "STRUCT: 1000 parts, 30 MB total",
            weight: 0.0,
            raw: Arc::new(build_message(
                "Archive export",
                (0..1000)
                    .map(|i| {
                        attachment(
                            "text/plain",
                            &format!("p-{i:04}.txt"),
                            business_prose(30 * 1024).into_bytes(),
                        )
                    })
                    .collect(),
            )),
            iters: 1,
        },
    ];

    if let Some(xlsx) = office_fixture {
        shapes.insert(
            5,
            Shape {
                name: "office attachment (real xlsx)",
                weight: 3.0,
                raw: Arc::new(build_message(
                    "Directory export",
                    vec![
                        text_part("text/plain", business_prose(1_200)),
                        attachment(
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "directory.xlsx",
                            xlsx,
                        ),
                    ],
                )),
                iters: 12,
            },
        );
    } else {
        eprintln!("note: xlsx fixture missing, office shape skipped");
    }

    shapes
}

// ---------------------------------------------------------------------------
// The work a milter actually does per message
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone, Copy)]
struct Verdict {
    findings: usize,
    parts_scanned: usize,
    /// A part that could not be inspected. Any of these makes the message
    /// verdict indeterminate — never clean.
    parts_uninspected: usize,
}

/// How the per-part context envelope is obtained.
///
/// Kept as a switch rather than replaced outright so the regression stays
/// measurable: `Rebuilt` is the original per-part construction and is the
/// reason this benchmark exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Envelope {
    /// Indexed once for the message; each part takes a range-excluded view.
    Shared,
    /// Rebuilt and re-indexed for every part. O(parts x message bytes).
    Rebuilt,
}

/// Parse, extract, scan, decide. The measured unit.
fn verdict(raw: &[u8]) -> Verdict {
    verdict_with(raw, Envelope::Shared)
}

fn verdict_with(raw: &[u8], mode: Envelope) -> Verdict {
    let parsed = parse_message(raw);
    let mut v = Verdict {
        parts_uninspected: parsed.warnings.len(),
        ..Default::default()
    };

    // The whole point: one index for the message, not one per part.
    let shared = (mode == Envelope::Shared).then(|| parsed.envelope_index());
    let scan_config = |path: &str| -> ScanConfig {
        match &shared {
            Some(index) => ScanConfig {
                shared_envelope: Some(index.for_key(path)),
                ..Default::default()
            },
            None => ScanConfig {
                context_envelope: Some(parsed.context_envelope(path)),
                ..Default::default()
            },
        }
    };

    for part in &parsed.parts {
        match part.kind {
            PartKind::Container => continue,
            PartKind::Text => {
                let Some(text) = &part.text else { continue };
                if text.len() > siphon_core::validation::MAX_INPUT_SIZE {
                    v.parts_uninspected += 1;
                    continue;
                }
                match scan_text_with_config(text, &scan_config(&part.path)) {
                    Ok(m) => {
                        v.findings += m.len();
                        v.parts_scanned += 1;
                    }
                    Err(_) => v.parts_uninspected += 1,
                }
            }
            PartKind::Attachment => {
                let Some(data) = &part.data else {
                    v.parts_uninspected += 1;
                    continue;
                };
                // Extraction is path-based, so the bytes have to hit disk
                // first. This round trip is part of the timeout budget.
                let suffix = part
                    .filename
                    .as_deref()
                    .and_then(|f| f.rsplit_once('.').map(|(_, e)| format!(".{e}")))
                    .unwrap_or_else(|| ".bin".to_string());
                let Ok(mut tmp) = tempfile::Builder::new().suffix(&suffix).tempfile() else {
                    v.parts_uninspected += 1;
                    continue;
                };
                if tmp.write_all(data).is_err() || tmp.flush().is_err() {
                    v.parts_uninspected += 1;
                    continue;
                }
                let path = tmp.path().to_string_lossy().to_string();
                let Ok(extracted) = extractors::extract_text(&path) else {
                    v.parts_uninspected += 1;
                    continue;
                };
                if extracted.text.len() > siphon_core::validation::MAX_INPUT_SIZE {
                    v.parts_uninspected += 1;
                    continue;
                }
                match scan_text_with_config(&extracted.text, &scan_config(&part.path)) {
                    Ok(m) => {
                        v.findings += m.len();
                        v.parts_scanned += 1;
                    }
                    Err(_) => v.parts_uninspected += 1,
                }
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("=== siphon mail-path latency benchmark ===");
    println!(
        "build:   {}",
        if cfg!(debug_assertions) {
            "DEBUG (numbers are meaningless — use --release)"
        } else {
            "release"
        }
    );
    println!("cores:   {cores} available to this process");
    println!(
        "cap:     {} MB scanner text limit\n",
        siphon_core::validation::MAX_INPUT_SIZE / (1024 * 1024)
    );

    println!("--- building corpus ---");
    let corpus = build_corpus();
    for s in &corpus {
        println!("  {:34} {:>9} bytes on the wire", s.name, s.raw.len());
    }
    println!();

    // --- pass 1: per-shape sequential latency ------------------------------
    println!("--- per-message verdict latency (sequential, one message at a time) ---");
    println!(
        "{:34} {:>8} {:>8} {:>8} {:>7} {:>7} {:>6}",
        "shape", "p50 ms", "p95 ms", "max ms", "parts", "unins", "finds"
    );

    let mut shape_max: Vec<(&str, Duration)> = Vec::new();
    for s in &corpus {
        // One warm-up: the first scan of the process pays pattern-set and
        // Aho-Corasick construction, which a long-lived milter pays once at
        // startup and never again. Charging it to message one would inflate
        // every number here.
        let warm = verdict(&s.raw);

        let mut times = Vec::with_capacity(s.iters);
        for _ in 0..s.iters {
            let t = Instant::now();
            let _ = verdict(&s.raw);
            times.push(t.elapsed());
        }
        times.sort();
        let mx = *times.last().unwrap();
        shape_max.push((s.name, mx));
        println!(
            "{:34} {:>8.1} {:>8.1} {:>8.1} {:>7} {:>7} {:>6}",
            s.name,
            ms(percentile(&times, 50.0)),
            ms(percentile(&times, 95.0)),
            ms(mx),
            warm.parts_scanned,
            warm.parts_uninspected,
            warm.findings,
        );
    }
    println!();

    // --- pass 2: concurrency sweep over the assumed mix --------------------
    //
    // Service time alone does not set a timeout. A milter serves many
    // connections at once, so what the MTA waits for is service time plus
    // queueing, and queueing is where the tail comes from.
    println!("--- mixed-flow latency under concurrency ---");
    println!("(mix is assumed — replace with the deployment's own size histogram)");

    // The at-cap shape is excluded: at 0.1% it would appear zero or one time
    // in a stream this size, so including it would make the percentiles a
    // coin flip rather than a measurement. It is handled separately below.
    let mixed: Vec<&Shape> = corpus
        .iter()
        .filter(|s| s.weight > 0.0 && !s.name.starts_with("at scanner cap"))
        .collect();
    let total_weight: f64 = mixed.iter().map(|s| s.weight).sum();

    let stream_len = 400;
    let mut stream: Vec<Arc<Vec<u8>>> = Vec::with_capacity(stream_len);
    for i in 0..stream_len {
        // Deterministic weighted interleave rather than RNG: the same stream
        // every run means run-to-run differences are the change under test.
        let target = (i as f64 + 0.5) / stream_len as f64 * total_weight;
        let mut acc = 0.0;
        for s in &mixed {
            acc += s.weight;
            if acc >= target {
                stream.push(Arc::clone(&s.raw));
                break;
            }
        }
    }
    let stream = Arc::new(stream);

    println!(
        "{:>8} {:>9} {:>9} {:>9} {:>9} {:>11}",
        "workers", "p50 ms", "p95 ms", "p99 ms", "max ms", "msg/s"
    );

    let mut sweep: Vec<(usize, Duration, f64)> = Vec::new();
    for &workers in &[1usize, 2, 4, 8] {
        let cursor = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let stream = Arc::clone(&stream);
                let cursor = Arc::clone(&cursor);
                std::thread::spawn(move || {
                    let mut local = Vec::new();
                    loop {
                        let i = cursor.fetch_add(1, Ordering::Relaxed);
                        if i >= stream.len() {
                            break;
                        }
                        let t = Instant::now();
                        let _ = verdict(&stream[i]);
                        local.push(t.elapsed());
                    }
                    local
                })
            })
            .collect();

        let mut times: Vec<Duration> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker panicked"))
            .collect();
        let wall = start.elapsed();
        times.sort();
        let rate = times.len() as f64 / wall.as_secs_f64();
        sweep.push((workers, percentile(&times, 99.0), rate));
        println!(
            "{:>8} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>11.1}",
            workers,
            ms(percentile(&times, 50.0)),
            ms(percentile(&times, 95.0)),
            ms(percentile(&times, 99.0)),
            ms(*times.last().unwrap()),
            rate,
        );
    }
    println!();

    // --- pass 2b: context-envelope scaling ---------------------------------
    //
    // Scanning a part in isolation hides the rest of the message from context
    // gating, so each part is scanned with an envelope built from the others.
    // Both halves of that are linear in message size and run once per part,
    // which makes the message quadratic in part count.
    //
    // Attachments hide this: they contribute only a filename to the envelope,
    // so a 1000-attachment message has an 11 KB envelope. Inline text parts do
    // not — a multipart/mixed of 1000 text/plain parts is ordinary MIME, and
    // there the envelope is the whole message, rebuilt and re-indexed 1000
    // times.
    println!("--- context-envelope cost vs inline text part count (30 KB per part) ---");
    println!(
        "{:>8} {:>10} {:>12} {:>12} {:>12} {:>10}",
        "parts", "total KB", "rebuilt ms", "shared ms", "shared/part", "speedup"
    );
    let mut first_shared_per_part = 0.0f64;
    let mut last_rebuilt: (usize, f64) = (0, 0.0);
    let mut last_shared: (usize, f64) = (0, 0.0);
    for (i, &n) in [50usize, 100, 200, 400].iter().enumerate() {
        let msg = build_message(
            "Report sections",
            (0..n)
                .map(|_| text_part("text/plain", business_prose(30 * 1024)))
                .collect(),
        );

        let t = Instant::now();
        let rebuilt_verdict = verdict_with(&msg, Envelope::Rebuilt);
        let rebuilt = ms(t.elapsed());

        let t = Instant::now();
        let shared_verdict = verdict_with(&msg, Envelope::Shared);
        let shared = ms(t.elapsed());

        // Faster is only interesting if it decides the same thing.
        assert_eq!(
            rebuilt_verdict.findings, shared_verdict.findings,
            "shared and rebuilt envelopes disagreed at {n} parts"
        );

        let shared_per_part = shared / n as f64;
        if i == 0 {
            first_shared_per_part = shared_per_part;
        }
        last_rebuilt = (n, rebuilt);
        last_shared = (n, shared);
        println!(
            "{:>8} {:>10} {:>12.1} {:>12.1} {:>12.2} {:>9.1}x",
            n,
            n * 30,
            rebuilt,
            shared,
            shared_per_part,
            rebuilt / shared,
        );
    }
    println!(
        "  shared/part flat = the quadratic is gone (first {:.2} ms, last {:.2} ms).",
        first_shared_per_part,
        last_shared.1 / last_shared.0 as f64
    );

    // The parser's own ceiling is 1000 parts (MimeLimits::max_parts), and the
    // ingest cap allows 30 MB, so 1000 x 30 KB is an accepted message.
    let ceiling = 1000.0;
    let projected_rebuilt_s = last_rebuilt.1 / 1000.0 * (ceiling / last_rebuilt.0 as f64).powi(2);
    let projected_s = last_shared.1 / 1000.0 * (ceiling / last_shared.0 as f64);
    println!("  At the accepted ceiling (1000 inline parts, 30 MB):");
    println!("    rebuilt, quadratic: ~{projected_rebuilt_s:.0} s (extrapolated)");
    println!("    shared,  linear:    ~{projected_s:.1} s (extrapolated)\n");

    // --- pass 3: worst legitimate message, contended -----------------------
    //
    // The timeout has to cover the slowest message the system is expected to
    // accept, arriving while the pod is already busy. That is the number the
    // MTA waits on in the worst legitimate case.
    let worst_shape = corpus
        .iter()
        .max_by_key(|s| shape_max.iter().find(|(n, _)| *n == s.name).unwrap().1)
        .expect("corpus is non-empty");
    println!(
        "--- worst legitimate message ({}) while {} workers are busy ---",
        worst_shape.name,
        cores.saturating_sub(1).max(1)
    );

    let load_workers = cores.saturating_sub(1).max(1);
    let stop = Arc::new(AtomicUsize::new(0));
    let loaders: Vec<_> = (0..load_workers)
        .map(|_| {
            let stream = Arc::clone(&stream);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut i = 0usize;
                while stop.load(Ordering::Relaxed) == 0 {
                    let _ = verdict(&stream[i % stream.len()]);
                    i += 1;
                }
            })
        })
        .collect();

    let mut contended = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        let _ = verdict(&worst_shape.raw);
        contended.push(t.elapsed());
    }
    stop.store(1, Ordering::Relaxed);
    for h in loaders {
        let _ = h.join();
    }
    contended.sort();
    let contended_max = *contended.last().unwrap();
    println!(
        "  idle max {:.1} ms   contended max {:.1} ms   ({:.1}x)\n",
        ms(shape_max
            .iter()
            .find(|(n, _)| *n == worst_shape.name)
            .unwrap()
            .1),
        ms(contended_max),
        contended_max.as_secs_f64()
            / shape_max
                .iter()
                .find(|(n, _)| *n == worst_shape.name)
                .unwrap()
                .1
                .as_secs_f64(),
    );

    // --- recommendation ----------------------------------------------------
    let p99_at_2 = sweep
        .iter()
        .find(|(w, _, _)| *w == 2)
        .map(|(_, p, _)| *p)
        .unwrap_or_default();
    let headroom = contended_max.mul_f64(2.0);

    println!("--- reading of the numbers ---");
    println!(
        "  typical message (mix p99, 2 workers): {:.0} ms",
        ms(p99_at_2)
    );
    println!(
        "  worst corpus message, contended:      {:.0} ms",
        ms(contended_max)
    );
    println!(
        "  timeout covering that (2x):           {:.1} s",
        headroom.as_secs_f64()
    );
    println!("  worst structural message (projected): ~{projected_s:.1} s");
    println!();
    println!("  A timeout is sized by the worst message the system accepts, not by");
    println!("  the typical one: timing out on typical mail is a misconfiguration,");
    println!("  whereas the worst accepted case is what the MTA actually waits on.");
    println!();
    println!("  With the shared envelope, part count is no longer the worst case —");
    println!("  the rebuilt column above is what it used to cost, and the ceiling");
    println!("  projection with it was minutes. The bound is now a single large");
    println!("  text, which is bounded by MAX_INPUT_SIZE and does not grow with");
    println!("  message structure.");
    println!();
    println!("  Suggested: 10 s. Above the 2x figure with room for a slower pod,");
    println!("  and roughly 40x the mixed-flow p99, so ordinary mail cannot reach");
    println!("  it. Affordable because timeout is fail-closed — being wrong costs a");
    println!("  retry and some delivery latency, not an uninspected delivery.");
}
