//! Benchmarks for the scanning engine.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon::scanner;
use std::hint::black_box;

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
        b.iter(|| siphon::normalize::normalize_text(black_box(&text)));
    });

    group.bench_function("strip_zero_width/10KB", |b| {
        b.iter(|| siphon::normalize::strip_zero_width(black_box(&text)));
    });

    group.bench_function("normalize_leet/10KB", |b| {
        b.iter(|| siphon::normalize::normalize_leet(black_box(&text)));
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

/// Benchmark the context hit-index / has_hit_in_range hot path.
///
/// Inputs are constructed with many context keywords alongside
/// sensitive values so that `build_hit_index` produces a sizeable
/// `hits` map and `has_hit_in_range` gets called ~560 times per scan
/// (once per compiled pattern during the active_gated filter).
/// Any changes to the per-scan `reverse`-map construction or the
/// per-call lookup path show up here.
fn context_heavy_text(copies: usize) -> String {
    // Mix of keywords and sensitive values that forces both the AC
    // prefilter (lots of keyword matches) and the regex scan path
    // (several PII sub_categories fire).
    let block = "Patient John Smith date of birth 01/15/1980. \
                 SSN 123-45-6789, medical record MRN 789456, \
                 insurance policy POL123456789, \
                 email contact@example.com, phone +14155551234. \
                 Prescriber DEA AB1234567, diagnosis ICD-10 E11.9. \
                 Credit card 4532-0151-1283-0366 expires 12/28. \
                 Employee id EMP0042, department code HR. ";
    block.repeat(copies)
}

fn bench_context_hit_index(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_index");

    for copies in [1, 5, 20] {
        let text = context_heavy_text(copies);
        let label = format!("{}x block ({} B)", copies, text.len());
        group.bench_with_input(
            BenchmarkId::new("scan_context_heavy", &label),
            &text,
            |b, text| {
                b.iter(|| scanner::scan_text(black_box(text)));
            },
        );
    }

    group.finish();
}

/// Benchmark the entropy-gated scan path specifically.
///
/// The input is a block of text where every line looks like a
/// configuration file pairing identifier-shaped keys with
/// high-entropy values. Running with `EntropyMode::Gated` forces the
/// scanner through `scan_high_entropy_tokens`, which tokenizes by
/// delimiters, re-finds each token's byte position, and computes
/// Shannon entropy per character. Any changes to the token-walk
/// loop or the per-character histogram (`char_entropy`) show up here.
fn entropy_heavy_text(copies: usize) -> String {
    let block = "api_key=xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs\n\
                 db_password=aJ3kLp9QrWxZnC2mBvFeTdHyUiOoPlRk\n\
                 session_token=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0\n\
                 github_token=ghp_abcDEFghiJKLmnoPQRstuVWXyz0123456789\n\
                 aws_secret=AKIAabcdef1234567890ABCDEF0987654321xyZZ\n\
                 auth_header=Bearer Qm9iYWxpY2VfQm9iYWxpY2VfQm9iYWxpY2U=\n";
    block.repeat(copies)
}

fn bench_entropy_gated(c: &mut Criterion) {
    use siphon::scanner::{scan_text_with_config, EntropyMode, ScanConfig};
    let mut group = c.benchmark_group("entropy_gated");

    for copies in [1, 5, 20] {
        let text = entropy_heavy_text(copies);
        let label = format!("{}x block ({} B)", copies, text.len());
        group.bench_with_input(
            BenchmarkId::new("scan_entropy_heavy", &label),
            &text,
            |b, text| {
                let config = ScanConfig {
                    entropy_scan: EntropyMode::Gated,
                    min_confidence: 0.0,
                    ..Default::default()
                };
                b.iter(|| scan_text_with_config(black_box(text), &config));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_scan_text,
    bench_normalize,
    bench_alt_decodings_path,
    bench_context_hit_index,
    bench_entropy_gated
);
criterion_main!(benches);
