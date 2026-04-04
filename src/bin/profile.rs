//! Quick profiling to find the bottleneck.

use std::time::Instant;

fn main() {
    let text = "The quick brown fox jumps over the lazy dog. No sensitive data here. ".repeat(15);
    // ~1KB of clean text

    // 1. Time normalize_text
    let start = Instant::now();
    for _ in 0..100 {
        let _ = dlpscan::normalize::normalize_text(&text);
    }
    let norm_time = start.elapsed().as_micros() as f64 / 100.0;
    eprintln!("normalize_text (1KB): {:.1} us", norm_time);

    // 2. Time just the RegexSet matching
    let (normalized, _) = dlpscan::normalize::normalize_text(&text);

    // Force lazy init
    let _ = dlpscan::scanner::scan_text(&text);

    let start = Instant::now();
    for _ in 0..100 {
        let _ = dlpscan::scanner::scan_text(&normalized);
    }
    let scan_time = start.elapsed().as_micros() as f64 / 100.0;
    eprintln!("scan_text (1KB): {:.1} us", scan_time);

    // 3. Time context build_hit_index
    let start = Instant::now();
    for _ in 0..100 {
        let _ = dlpscan::context::build_hit_index(&normalized);
    }
    let ctx_time = start.elapsed().as_micros() as f64 / 100.0;
    eprintln!("build_hit_index (1KB): {:.1} us", ctx_time);

    // 4. Count patterns
    let patterns = dlpscan::patterns::PATTERNS;
    eprintln!("Total patterns: {}", patterns.len());
}
