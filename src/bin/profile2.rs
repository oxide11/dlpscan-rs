//! Deeper profiling — RegexSet vs Phase 2.

use regex::{Regex, RegexSet, RegexSetBuilder};
use std::time::Instant;

fn main() {
    let text = "The quick brown fox jumps over the lazy dog. No sensitive data here. ".repeat(15);

    let patterns = dlpscan::patterns::PATTERNS;
    eprintln!("Total patterns: {}", patterns.len());

    // Build a RegexSet from all patterns
    let mut regex_strings = Vec::new();
    let mut regexes = Vec::new();

    for pat in patterns.iter() {
        let regex_str = if pat.case_insensitive {
            format!("(?i){}", pat.regex)
        } else {
            pat.regex.to_string()
        };
        if let Ok(re) = Regex::new(&regex_str) {
            regex_strings.push(regex_str);
            regexes.push(re);
        }
    }

    eprintln!("Compiled regexes: {}", regexes.len());

    let regex_set = RegexSetBuilder::new(regex_strings.iter().map(|s| s.as_str()))
        .size_limit(50 * 1024 * 1024)
        .build()
        .unwrap();

    // Time Phase 1: RegexSet
    let start = Instant::now();
    let mut total_matches = 0;
    for _ in 0..100 {
        let matching = regex_set.matches(&text);
        total_matches = matching.into_iter().count();
    }
    let phase1_time = start.elapsed().as_micros() as f64 / 100.0;
    eprintln!("Phase 1 (RegexSet matches, 1KB): {:.1} us, {} patterns match", phase1_time, total_matches);

    // Time Phase 2: individual regex extraction for matching patterns
    let matching: Vec<usize> = regex_set.matches(&text).into_iter().collect();
    eprintln!("Matching patterns: {:?}", matching.iter().take(20).collect::<Vec<_>>());

    // Print which patterns match
    for &idx in &matching {
        let pat = &patterns[idx];
        eprintln!("  Pattern {}: {} / {}", idx, pat.category, pat.sub_category);
    }

    let start = Instant::now();
    for _ in 0..100 {
        for &idx in &matching {
            let _ = regexes[idx].find_iter(&text).count();
        }
    }
    let phase2_time = start.elapsed().as_micros() as f64 / 100.0;
    eprintln!("Phase 2 (individual regex, 1KB): {:.1} us", phase2_time);

    // Time Phase 1 with 10KB
    let text_10k = "The quick brown fox jumps over the lazy dog. No sensitive data here. ".repeat(150);
    let start = Instant::now();
    for _ in 0..10 {
        let _ = regex_set.matches(&text_10k);
    }
    let phase1_10k = start.elapsed().as_micros() as f64 / 10.0;
    eprintln!("Phase 1 (RegexSet, 10KB): {:.1} us", phase1_10k);

    // Try individual regexes on 1KB to see which are slow
    let mut slowest = Vec::new();
    for (idx, re) in regexes.iter().enumerate() {
        let start = Instant::now();
        for _ in 0..10 {
            let _ = re.find_iter(&text).count();
        }
        let time_us = start.elapsed().as_micros() as f64 / 10.0;
        slowest.push((time_us, idx));
    }
    slowest.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    eprintln!("\nTop 10 slowest individual patterns on 1KB:");
    for (time_us, idx) in slowest.iter().take(10) {
        let pat = &patterns[*idx];
        eprintln!("  {:.1} us: {} / {} — {}", time_us, pat.category, pat.sub_category, &pat.regex[..pat.regex.len().min(60)]);
    }
}
