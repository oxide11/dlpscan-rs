//! Benchmark binary for dlpscan-rs.
//!
//! Compares full scan (560 patterns) vs baseline-only (~108 always-run patterns).

use dlpscan::guard::{Action, InputGuard, Mode, Preset};
use std::time::Instant;

const CLEAN_TEXT: &str = "The quick brown fox jumps over the lazy dog. No sensitive data here. ";

const MIXED_TEXT: &str = "Contact john.doe@example.com for details. \
    SSN: 425-71-3482. \
    Card: 4532-0151-1283-0366. \
    Phone: (555) 867-5309. \
    AWS key: AKIAIOSFODNN7EXAMPLE. \
    Normal text padding to make it more realistic. ";

const DENSE_TEXT: &str = "4532015112830366 \
    john@example.com \
    425-71-3482 \
    AKIAIOSFODNN7EXAMPLE \
    5425233430109903 \
    jane@test.org \
    318-42-7156 ";

// Text with many context keywords that trigger context-gated patterns to run,
// but no actual sensitive data matching those patterns.
const KEYWORD_HEAVY_TEXT: &str = "The employee badge number and personnel \
    record indicates the staff member. Account number and routing number \
    for wire transfer and bank details. Social security number and \
    date of birth on the insurance policy. Medical record number and \
    health plan identifier for the patient. Tax identification number \
    and passport number on the immigration form. Credit card number \
    and expiry date on the receipt. Driver license and vehicle \
    identification for the registration. Check number and balance \
    on the bank statement. Biometric hash and template for access. ";

fn generate_text(template: &str, target_size: usize) -> String {
    let repeats = target_size / template.len() + 1;
    template.repeat(repeats)[..target_size].to_string()
}

struct BenchResult {
    name: String,
    median_ms: f64,
}

fn bench<F>(name: &str, warmup: usize, iterations: usize, mut f: F) -> BenchResult
where
    F: FnMut(),
{
    for _ in 0..warmup {
        f();
    }

    let mut times_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        times_ms.push(elapsed);
    }

    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = times_ms[times_ms.len() / 2];

    BenchResult {
        name: name.to_string(),
        median_ms: median,
    }
}

fn make_guard(baseline_only: bool) -> InputGuard {
    InputGuard::new()
        .with_presets(vec![
            Preset::PciDss,
            Preset::Pii,
            Preset::Credentials,
            Preset::Healthcare,
            Preset::ContactInfo,
        ])
        .with_action(Action::Flag)
        .with_mode(Mode::Denylist)
        .with_baseline_only(baseline_only)
}

fn main() {
    let guard_full = make_guard(false);
    let guard_baseline = make_guard(true);

    let sizes: Vec<usize> = vec![1024, 10240, 102400, 1048576];
    let templates: Vec<(&str, &str)> = vec![
        ("clean", CLEAN_TEXT),
        ("mixed", MIXED_TEXT),
        ("dense", DENSE_TEXT),
        ("kw_heavy", KEYWORD_HEAVY_TEXT),
    ];

    let mut rows: Vec<(BenchResult, BenchResult)> = Vec::new();

    eprintln!("Rust dlpscan: Full (560 patterns) vs Baseline (~108 always-run patterns)");
    eprintln!("{}", "=".repeat(76));
    eprintln!(
        "  {:35}  {:>10}  {:>10}  {:>8}",
        "Test", "Full (ms)", "Base (ms)", "Speedup"
    );
    eprintln!("  {}", "-".repeat(71));

    for &size in &sizes {
        let label = format!("{}KB", size / 1024);
        for &(template_name, template) in &templates {
            let text = generate_text(template, size);
            let iters = if size <= 102400 { 20 } else { 5 };
            let name = format!("scan_{}_{}", template_name, label);

            let full = bench(&format!("{}_full", name), 2, iters, || {
                let _ = guard_full.scan(&text);
            });
            let base = bench(&format!("{}_base", name), 2, iters, || {
                let _ = guard_baseline.scan(&text);
            });

            let speedup = if base.median_ms > 0.001 {
                full.median_ms / base.median_ms
            } else {
                1.0
            };
            eprintln!(
                "  {:35}  {:10.2}  {:10.2}  {:7.1}x",
                name, full.median_ms, base.median_ms, speedup
            );
            rows.push((full, base));
        }
    }

    // Redaction comparison
    let text_10k = generate_text(MIXED_TEXT, 10240);
    let guard_redact_full = InputGuard::new()
        .with_presets(vec![
            Preset::PciDss,
            Preset::Pii,
            Preset::Credentials,
            Preset::Healthcare,
            Preset::ContactInfo,
        ])
        .with_action(Action::Redact)
        .with_mode(Mode::Denylist);
    let guard_redact_baseline = InputGuard::new()
        .with_presets(vec![
            Preset::PciDss,
            Preset::Pii,
            Preset::Credentials,
            Preset::Healthcare,
            Preset::ContactInfo,
        ])
        .with_action(Action::Redact)
        .with_mode(Mode::Denylist)
        .with_baseline_only(true);

    let full = bench("redact_mixed_10KB_full", 2, 20, || {
        let _ = guard_redact_full.scan(&text_10k);
    });
    let base = bench("redact_mixed_10KB_base", 2, 20, || {
        let _ = guard_redact_baseline.scan(&text_10k);
    });
    let speedup = full.median_ms / base.median_ms;
    eprintln!(
        "  {:35}  {:10.2}  {:10.2}  {:7.1}x",
        "redact_mixed_10KB", full.median_ms, base.median_ms, speedup
    );
    rows.push((full, base));

    // Throughput summary
    eprintln!("\n{}", "=".repeat(76));
    eprintln!("Throughput (1MB):");
    eprintln!("  {:35}  {:>12}  {:>12}", "Scenario", "Full", "Baseline");
    eprintln!("  {}", "-".repeat(61));
    for (full, base) in &rows {
        if full.name.contains("1024KB") {
            let full_mbps = 1.0 / (full.median_ms / 1000.0);
            let base_mbps = 1.0 / (base.median_ms / 1000.0);
            let scenario = full.name.replace("_full", "");
            eprintln!(
                "  {:35}  {:9.1} MB/s  {:9.1} MB/s",
                scenario, full_mbps, base_mbps
            );
        }
    }

    // Finding count comparison
    eprintln!("\n{}", "=".repeat(76));
    eprintln!("Finding counts:");
    for (template_name, template) in &[
        ("mixed_10KB", MIXED_TEXT),
        ("kw_heavy_10KB", KEYWORD_HEAVY_TEXT),
    ] {
        let text = generate_text(template, 10240);
        let full_result = guard_full.scan(&text).unwrap();
        let base_result = guard_baseline.scan(&text).unwrap();
        eprintln!(
            "  {} — full: {} findings, baseline: {} findings",
            template_name,
            full_result.findings.len(),
            base_result.findings.len()
        );

        // Show category diff
        let full_cats = &full_result.categories_found;
        let base_cats = &base_result.categories_found;
        let only_full: Vec<_> = full_cats.difference(base_cats).collect();
        if !only_full.is_empty() {
            eprintln!("    Categories only in full: {:?}", only_full);
        }
    }

    // Pattern count info — classification uses the scanner's own
    // `is_always_run` so this report can't drift out of sync with
    // `CRITICAL_ALWAYS_RUN` the way the previous hand-copied list
    // did. See the doc comment on `scanner::is_always_run`.
    eprintln!("\nPattern classification:");
    let compiled = dlpscan::patterns::PATTERNS;
    let always_run = compiled
        .iter()
        .filter(|p| dlpscan::scanner::is_always_run(p.sub_category))
        .count();
    eprintln!("  Total patterns:     {}", compiled.len());
    eprintln!("  Always-run:         {} (baseline)", always_run);
    eprintln!(
        "  Context-gated:      {} (skipped in baseline mode)",
        compiled.len() - always_run
    );
}
