//! Benchmarks for the scanning engine.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dlpscan::scanner;

fn generate_text(size: usize) -> String {
    let base = "The quick brown fox jumps over the lazy dog. \
                Contact john@example.com for details. \
                SSN: 123-45-6789. Card: 4532-0151-1283-0366. ";
    base.repeat(size / base.len() + 1)[..size].to_string()
}

/// Produce a short input that triggers the scanner's alternative-
/// decodings fallback: no regex matches in the primary scan AND
/// `text.len() < 4096`. The scanner then runs
/// `generate_alternative_decodings` and walks every compiled pattern
/// against every alternative — this is the quadratic hot path the
/// performance audit called out, so the bench here measures exactly
/// that path end-to-end.
fn clean_short_text(size: usize) -> String {
    // Use a vocabulary that no pattern in the baseline ruleset will
    // match: ordinary English words, no digits, no @, no `.com`, no
    // SSN-shaped sequences.
    let base = "The quick brown fox jumps over a sleepy dog near the old oak tree \
                while songbirds whistle their morning tune above the meadow. ";
    let mut out = String::with_capacity(size + base.len());
    while out.len() < size {
        out.push_str(base);
    }
    out.truncate(size);
    out
}

fn bench_scan_text(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_scanning");

    for size in [1024, 10_240, 102_400, 1_048_576] {
        let text = generate_text(size);
        let label = format!("{} KB", size / 1024);

        group.bench_with_input(BenchmarkId::new("scan_text", &label), &text, |b, text| {
            b.iter(|| scanner::scan_text(black_box(text)));
        });
    }

    group.finish();
}

fn bench_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalization");
    let text = generate_text(10_240);

    group.bench_function("normalize_text/10KB", |b| {
        b.iter(|| dlpscan::normalize::normalize_text(black_box(&text)));
    });

    group.bench_function("strip_zero_width/10KB", |b| {
        b.iter(|| dlpscan::normalize::strip_zero_width(black_box(&text)));
    });

    group.bench_function("normalize_leet/10KB", |b| {
        b.iter(|| dlpscan::normalize::normalize_leet(black_box(&text)));
    });

    group.finish();
}

/// Benchmark the alternative-decodings fallback path specifically.
///
/// Inputs are short and deliberately match nothing, so the scanner
/// runs:
///   - the primary phase (normalize + per-pattern find_iter), which
///     finds 0 matches;
///   - then the alt-decodings second pass, which produces ~5
///     transformations and re-scans each one.
///
/// Whatever cost the second pass carries dominates this bench. The
/// perf audit identified this loop as a quadratic
/// `patterns × alternatives` hot spot for short documents.
fn bench_alt_decodings_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("alt_decodings");

    for size in [256, 1024, 2048] {
        let text = clean_short_text(size);
        let label = format!("{} B", size);
        group.bench_with_input(
            BenchmarkId::new("scan_clean_short", &label),
            &text,
            |b, text| {
                b.iter(|| scanner::scan_text(black_box(text)));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_scan_text, bench_normalize, bench_alt_decodings_path);
criterion_main!(benches);
