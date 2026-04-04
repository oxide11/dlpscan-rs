//! Benchmarks for the scanning engine.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dlpscan::scanner;

fn generate_text(size: usize) -> String {
    let base = "The quick brown fox jumps over the lazy dog. \
                Contact john@example.com for details. \
                SSN: 123-45-6789. Card: 4532-0151-1283-0366. ";
    base.repeat(size / base.len() + 1)[..size].to_string()
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

criterion_group!(benches, bench_scan_text, bench_normalize);
criterion_main!(benches);
