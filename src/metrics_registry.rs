//! A small Prometheus-compatible metrics registry.
//!
//! # Why this is not the `prometheus` crate
//!
//! It was. That crate brought 23 transitive dependencies — `procfs`,
//! `procfs-core`, `parking_lot`, `parking_lot_core`, `lock_api`, `rustix`,
//! `linux-raw-sys`, `syn`, `quote`, `proc-macro2`, `thiserror` and the rest —
//! to serve four counters, two histograms, a gauge and one labelled counter,
//! exposed on a single endpoint.
//!
//! The precedent for replacing it was already in the tree: `siphon-api`, the
//! service that actually runs in production, never used the crate. It counts
//! with `AtomicU64` and renders the text format by hand, and has done so for
//! its whole life.
//!
//! # What is deliberately not implemented
//!
//! No pushgateway, no exemplars, no protobuf exposition, no process
//! collector, no custom registries. The process collector is the notable
//! omission: `prometheus` shipped `procfs` to publish `process_cpu_seconds`
//! and friends, which is most of the 23 crates. Nothing in this workspace
//! scraped those — the pod's own cAdvisor metrics already carry them, and
//! duplicating them from inside the process is how two sources of truth
//! disagree about the same number.
//!
//! # Correctness of the exposition format
//!
//! The text format is stable and specified, and the parts that are easy to
//! get subtly wrong are covered by tests: histogram buckets are cumulative,
//! `+Inf` always exists and equals `_count`, and label values are escaped.
//! A malformed line does not error — Prometheus simply drops the metric on
//! scrape, which is the failure mode that looks like "the counter is zero".

use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A monotonically increasing counter.
///
/// Stored as the bits of an `f64` in an `AtomicU64` rather than as an integer.
/// Prometheus counters are floating point, and `inc_by` is called with
/// fractional values in some callers; keeping an integer here would silently
/// truncate them.
#[derive(Debug)]
pub struct Counter {
    bits: AtomicU64,
}

impl Counter {
    const fn new() -> Self {
        Self {
            bits: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.inc_by(1.0);
    }

    pub fn inc_by(&self, v: f64) {
        // A counter that goes backwards is a counter Prometheus will read as
        // a reset and a wrap, inventing an enormous rate. Refuse rather than
        // record it.
        if v < 0.0 || !v.is_finite() {
            return;
        }
        let mut cur = self.bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(cur) + v).to_bits();
            match self
                .bits
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

/// A value that can go up or down.
#[derive(Debug)]
pub struct Gauge {
    bits: AtomicU64,
}

impl Gauge {
    const fn new() -> Self {
        Self {
            bits: AtomicU64::new(0),
        }
    }

    pub fn set(&self, v: f64) {
        self.bits.store(v.to_bits(), Ordering::Relaxed);
    }

    pub fn add(&self, v: f64) {
        let mut cur = self.bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(cur) + v).to_bits();
            match self
                .bits
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn inc(&self) {
        self.add(1.0);
    }

    pub fn dec(&self) {
        self.add(-1.0);
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

/// A histogram with fixed upper bounds.
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [f64],
    /// One counter per bound, plus nothing for `+Inf` — that bucket is
    /// `count`, so storing it twice would be two things to keep in step.
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_bits: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_bits: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, v: f64) {
        if !v.is_finite() {
            return;
        }
        // Buckets are stored non-cumulatively and summed at render time.
        // Incrementing every matching bucket here instead would make an
        // observation O(buckets) under contention for no benefit.
        if let Some(i) = self.bounds.iter().position(|&b| v <= b) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut cur = self.sum_bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(cur) + v).to_bits();
            match self.sum_bits.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> f64 {
        f64::from_bits(self.sum_bits.load(Ordering::Relaxed))
    }
}

/// A counter family keyed by label values.
///
/// `BTreeMap` rather than `HashMap` so the exposition output is ordered and
/// therefore diffable between scrapes; a metrics endpoint whose line order
/// changes on every request is needlessly hard to eyeball.
#[derive(Debug)]
pub struct CounterVec {
    labels: &'static [&'static str],
    series: Mutex<BTreeMap<Vec<String>, f64>>,
}

impl CounterVec {
    fn new(labels: &'static [&'static str]) -> Self {
        Self {
            labels,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn inc(&self, values: &[&str]) {
        // A cardinality mismatch would render as a malformed line, which
        // Prometheus drops silently on scrape — indistinguishable from the
        // counter being zero. Drop it here instead, where a test can see it.
        if values.len() != self.labels.len() {
            return;
        }
        let key: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let mut g = self.series.lock().unwrap_or_else(|e| e.into_inner());
        *g.entry(key).or_insert(0.0) += 1.0;
    }
}

/// Escape a label value per the exposition format: backslash, double quote
/// and newline. Without this a path containing a quote produces a line that
/// silently fails to parse at scrape time.
fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a float the way the exposition format expects: integers without a
/// trailing `.0`, and `+Inf` spelled out.
fn num(v: f64) -> String {
    if v.is_infinite() {
        return if v > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

const REQ_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0];
const SCAN_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0];

pub static HTTP_REQUESTS_TOTAL: Lazy<CounterVec> =
    Lazy::new(|| CounterVec::new(&["method", "path", "status"]));
pub static HTTP_REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| Histogram::new(REQ_BUCKETS));
pub static SCAN_DURATION: Lazy<Histogram> = Lazy::new(|| Histogram::new(SCAN_BUCKETS));
pub static ACTIVE_CONNECTIONS: Gauge = Gauge::new();
pub static SCAN_MATCHES_TOTAL: Counter = Counter::new();
pub static SCANS_TOTAL: Counter = Counter::new();
pub static SCAN_ERRORS_TOTAL: Counter = Counter::new();
pub static RATE_LIMIT_REJECTIONS: Counter = Counter::new();

pub fn record_request(method: &str, path: &str, status: &str, duration_secs: f64) {
    HTTP_REQUESTS_TOTAL.inc(&[method, path, status]);
    HTTP_REQUEST_DURATION.observe(duration_secs);
}

pub fn record_matches(count: usize) {
    SCAN_MATCHES_TOTAL.inc_by(count as f64);
}

pub fn record_scan(duration_secs: f64, match_count: usize) {
    SCANS_TOTAL.inc();
    SCAN_DURATION.observe(duration_secs);
    SCAN_MATCHES_TOTAL.inc_by(match_count as f64);
}

pub fn record_scan_error() {
    SCAN_ERRORS_TOTAL.inc();
}

pub fn record_rate_limit_rejection() {
    RATE_LIMIT_REJECTIONS.inc();
}

fn counter_block(out: &mut String, name: &str, help: &str, value: f64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    out.push_str(&format!("{name} {}\n", num(value)));
}

fn histogram_block(out: &mut String, name: &str, help: &str, h: &Histogram) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
    // Buckets are cumulative in the exposition format even though they are
    // stored non-cumulatively. Emitting the raw per-bucket counts is the
    // classic way to produce a histogram whose quantiles are quietly wrong.
    let mut running = 0u64;
    for (i, bound) in h.bounds.iter().enumerate() {
        running += h.buckets[i].load(Ordering::Relaxed);
        out.push_str(&format!(
            "{name}_bucket{{le=\"{}\"}} {running}\n",
            num(*bound)
        ));
    }
    let count = h.count();
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
    out.push_str(&format!("{name}_sum {}\n", num(h.sum())));
    out.push_str(&format!("{name}_count {count}\n"));
}

/// Render every metric in the Prometheus text exposition format.
pub fn render() -> String {
    let mut out = String::with_capacity(2048);

    let series = HTTP_REQUESTS_TOTAL
        .series
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    out.push_str("# HELP dlpscan_requests_total Total HTTP requests\n");
    out.push_str("# TYPE dlpscan_requests_total counter\n");
    for (values, v) in series.iter() {
        let pairs: Vec<String> = HTTP_REQUESTS_TOTAL
            .labels
            .iter()
            .zip(values.iter())
            .map(|(l, val)| format!("{l}=\"{}\"", escape(val)))
            .collect();
        out.push_str(&format!(
            "dlpscan_requests_total{{{}}} {}\n",
            pairs.join(","),
            num(*v)
        ));
    }
    drop(series);

    histogram_block(
        &mut out,
        "dlpscan_request_duration_seconds",
        "HTTP request duration in seconds",
        &HTTP_REQUEST_DURATION,
    );
    histogram_block(
        &mut out,
        "dlpscan_scan_duration_seconds",
        "Scan operation duration in seconds",
        &SCAN_DURATION,
    );
    counter_block(
        &mut out,
        "dlpscan_scan_matches_total",
        "Total sensitive data matches found",
        SCAN_MATCHES_TOTAL.get(),
    );
    counter_block(
        &mut out,
        "dlpscan_scans_total",
        "Total scan operations completed",
        SCANS_TOTAL.get(),
    );
    counter_block(
        &mut out,
        "dlpscan_scan_errors_total",
        "Total scan errors",
        SCAN_ERRORS_TOTAL.get(),
    );
    counter_block(
        &mut out,
        "dlpscan_rate_limit_rejections_total",
        "Total rate limit rejections",
        RATE_LIMIT_REJECTIONS.get(),
    );
    out.push_str("# HELP dlpscan_active_connections Number of active HTTP connections\n");
    out.push_str("# TYPE dlpscan_active_connections gauge\n");
    out.push_str(&format!(
        "dlpscan_active_connections {}\n",
        num(ACTIVE_CONNECTIONS.get())
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_accumulates_and_refuses_to_go_backwards() {
        let c = Counter::new();
        c.inc();
        c.inc_by(2.5);
        assert_eq!(c.get(), 3.5);
        // A decreasing counter reads to Prometheus as a reset and a wrap,
        // inventing an enormous rate out of nothing.
        c.inc_by(-5.0);
        assert_eq!(c.get(), 3.5);
        c.inc_by(f64::NAN);
        assert_eq!(c.get(), 3.5);
    }

    #[test]
    fn a_gauge_moves_in_both_directions() {
        let g = Gauge::new();
        g.inc();
        g.inc();
        g.dec();
        assert_eq!(g.get(), 1.0);
        g.set(42.0);
        assert_eq!(g.get(), 42.0);
    }

    /// The bug this guards: buckets are stored per-bound but the exposition
    /// format wants them cumulative. Emitting the raw counts produces a
    /// histogram whose quantiles are quietly wrong.
    #[test]
    fn histogram_buckets_render_cumulatively() {
        static B: &[f64] = &[1.0, 2.0, 5.0];
        let h = Histogram::new(B);
        for v in [0.5, 1.5, 1.9, 4.0, 100.0] {
            h.observe(v);
        }
        let mut out = String::new();
        histogram_block(&mut out, "t", "t", &h);

        let le = |b: &str| -> u64 {
            out.lines()
                .find(|l| l.starts_with(&format!("t_bucket{{le=\"{b}\"}}")))
                .and_then(|l| l.rsplit(' ').next())
                .unwrap()
                .parse()
                .unwrap()
        };
        assert_eq!(le("1"), 1, "one observation <= 1");
        assert_eq!(le("2"), 3, "cumulative: 0.5, 1.5, 1.9");
        assert_eq!(le("5"), 4, "cumulative: plus 4.0");
        // 100.0 exceeds every bound, so it appears only in +Inf.
        assert_eq!(le("+Inf"), 5);
    }

    /// +Inf must equal _count, or the histogram is internally inconsistent
    /// and rate() over it produces nonsense.
    #[test]
    fn the_infinity_bucket_equals_the_count() {
        static B: &[f64] = &[0.1];
        let h = Histogram::new(B);
        for v in [0.05, 9.0, 9.0] {
            h.observe(v);
        }
        let mut out = String::new();
        histogram_block(&mut out, "t", "t", &h);
        assert!(out.contains("t_bucket{le=\"+Inf\"} 3"));
        assert!(out.contains("t_count 3"));
        assert!(out.contains("t_sum 18.05"));
    }

    /// A quote or backslash in a label value produces a line Prometheus
    /// silently drops on scrape, which looks exactly like a zero counter.
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), "a\\nb");
    }

    #[test]
    fn integers_render_without_a_decimal_point() {
        assert_eq!(num(3.0), "3");
        assert_eq!(num(3.5), "3.5");
        assert_eq!(num(f64::INFINITY), "+Inf");
    }

    /// A cardinality mismatch renders a malformed line that Prometheus drops
    /// silently. Dropping it here means a test can see it instead.
    #[test]
    fn a_label_cardinality_mismatch_is_dropped_not_rendered() {
        let v = CounterVec::new(&["a", "b"]);
        v.inc(&["only-one"]);
        assert!(v.series.lock().unwrap().is_empty());
        v.inc(&["one", "two"]);
        assert_eq!(v.series.lock().unwrap().len(), 1);
    }

    /// Every block must carry HELP and TYPE, and the output must parse as
    /// well-formed exposition: no blank metric lines, no unbalanced braces.
    #[test]
    fn rendered_output_is_well_formed() {
        record_request("GET", "/scan", "200", 0.01);
        record_scan(0.02, 3);
        record_scan_error();
        record_rate_limit_rejection();
        ACTIVE_CONNECTIONS.set(2.0);

        let out = render();
        for name in [
            "dlpscan_requests_total",
            "dlpscan_request_duration_seconds",
            "dlpscan_scan_duration_seconds",
            "dlpscan_scans_total",
            "dlpscan_scan_errors_total",
            "dlpscan_rate_limit_rejections_total",
            "dlpscan_active_connections",
        ] {
            assert!(
                out.contains(&format!("# HELP {name} ")),
                "missing HELP {name}"
            );
            assert!(
                out.contains(&format!("# TYPE {name} ")),
                "missing TYPE {name}"
            );
        }
        for line in out.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            assert_eq!(
                line.matches('{').count(),
                line.matches('}').count(),
                "unbalanced braces: {line}"
            );
            let (_, value) = line.rsplit_once(' ').expect("metric line has a value");
            assert!(
                value.parse::<f64>().is_ok() || value == "+Inf",
                "unparseable value in: {line}"
            );
        }
    }
}
