//! `siphon-conformance` — run the conformance matrix and report coverage.
//!
//! The matrix itself lives in `siphon::conformance` so that this binary, the
//! `tests/conformance.rs` gate and `scripts/conformance.sh` all run the same
//! cases. This is the developer-facing entry point: it prints what passed,
//! what failed and why, and what Siphon claims to support but has no cases
//! for.
//!
//! ```text
//! siphon-conformance                 # everything, human-readable
//! siphon-conformance --capability docx
//! siphon-conformance --json          # machine-readable, for CI to archive
//! siphon-conformance --list          # what would run, without running it
//! ```
//!
//! Exit status is 0 only when every case passed *and* nothing advertised is
//! unaccounted for, so it drops straight into a pre-push hook or a CI step.

use siphon::conformance::{self, Axis, Slot};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut json = false;
    let mut list = false;
    let mut only: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--list" => list = true,
            "-h" | "--help" => {
                print_help();
                return std::process::ExitCode::SUCCESS;
            }
            "--capability" | "-c" => {
                i += 1;
                match args.get(i) {
                    Some(v) => only = Some(v.clone()),
                    None => {
                        eprintln!("--capability needs a value");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("unknown argument: {other}\n");
                print_help();
                return std::process::ExitCode::from(2);
            }
        }
        i += 1;
    }

    if list {
        let cases = conformance::formats::cases();
        let mut current = "";
        for c in &cases {
            if c.capability != current {
                current = c.capability;
                println!("\n{current}");
            }
            println!("  {:<11} {}", c.slot.name(), first_line(c.note));
        }
        println!("\n{} cases", cases.len());
        return std::process::ExitCode::SUCCESS;
    }

    let report = conformance::run_all(only.as_deref());

    if report.results.is_empty() {
        eprintln!(
            "no cases matched{}",
            only.map(|f| format!(" capability {f:?}"))
                .unwrap_or_default()
        );
        return std::process::ExitCode::from(2);
    }

    if json {
        println!("{}", report.to_json());
        return exit_code(&report);
    }

    print_text(&report);
    exit_code(&report)
}

fn exit_code(report: &conformance::Report) -> std::process::ExitCode {
    if report.ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

fn first_line(s: &str) -> String {
    // Notes are wrapped across source lines with continuations; collapse the
    // runs of whitespace so a listing stays one line per case.
    let joined: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.len() > 92 {
        format!("{}…", &joined[..91])
    } else {
        joined
    }
}

fn print_text(report: &conformance::Report) {
    println!("Siphon conformance matrix");
    println!("{}", "=".repeat(70));
    println!();

    for (capability, passed, total) in report.by_axis(Some(Axis::Format)) {
        let broken = report
            .results
            .iter()
            .any(|r| r.capability == capability && r.is_failure());
        let mark = if broken { "FAIL" } else { "ok  " };
        print!("  {mark}  {capability:<10} {passed}/{total}  ");
        for slot in Slot::ALL {
            let r = report
                .results
                .iter()
                .find(|r| r.capability == capability && r.slot == slot);
            match r {
                // A documented gap is marked, but not as a failure: it is
                // behaving exactly as the note says it does.
                Some(r) if r.expected_failure() => print!("~{} ", slot.name()),
                Some(r) if r.passed() => print!("{} ", slot.name()),
                Some(_) => print!("[{}] ", slot.name()),
                None => print!("- "),
            }
        }
        println!();
    }

    // 511 patterns will not fit on a screen and would bury the format table
    // if they tried. What is worth seeing at a glance is the total, the
    // per-slot breakdown, and anything that broke — the rest is available
    // through --capability.
    let det: Vec<_> = report
        .results
        .iter()
        .filter(|r| r.axis == Axis::Detection)
        .collect();
    if !det.is_empty() {
        let (covered, total_patterns) = report.pattern_coverage;
        println!();
        println!("  detections");
        println!(
            "        {covered} of {total_patterns} patterns · {} cases",
            det.len()
        );
        for slot in Slot::ALL {
            let in_slot: Vec<_> = det.iter().filter(|r| r.slot == slot).collect();
            let pass = in_slot.iter().filter(|r| r.passed()).count();
            let gaps = in_slot.iter().filter(|r| r.expected_failure()).count();
            println!(
                "        {:<11} {pass}/{}{}",
                slot.name(),
                in_slot.len(),
                if gaps > 0 {
                    format!(
                        "  ({gaps} declared gap{})",
                        if gaps == 1 { "" } else { "s" }
                    )
                } else {
                    String::new()
                }
            );
        }
        if !report.unseeded.is_empty() {
            println!(
                "        {:<11} {} pattern(s) with no observable example",
                "unseeded",
                report.unseeded.len()
            );
        }
    }

    println!();
    println!(
        "  {} cases, {} passed, {} failed, {} documented gaps",
        report.results.len(),
        report.passed(),
        report.failed(),
        report.expected_failures().len()
    );

    let failures: Vec<_> = report.results.iter().filter(|r| r.is_failure()).collect();
    if !failures.is_empty() {
        println!();
        println!("{}", "-".repeat(70));
        println!("Failures");
        println!();
        for f in failures {
            println!("  {} / {}", f.capability, f.slot.name());
            for line in f.failure.as_deref().unwrap_or("").lines() {
                println!("    {}", line.trim());
            }
            println!();
        }
    }

    let fixed = report.fixed_gaps();
    if !fixed.is_empty() {
        println!("{}", "-".repeat(70));
        println!("Documented gaps that now PASS — remove the gap() wrapper:");
        for f in fixed {
            println!("  {} / {}", f.capability, f.slot.name());
        }
        println!();
    }

    let expected = report.expected_failures();
    if !expected.is_empty() {
        println!("{}", "-".repeat(70));
        println!(
            "Documented gaps ({}) — behaviour Siphon does not have yet:",
            expected.len()
        );
        println!();
        for e in expected {
            println!("  ~ {} / {}", e.capability, e.slot.name());
            println!("      want: {}", wrap(e.note, 8));
            println!("      why:  {}", wrap(e.known_gap.unwrap_or(""), 8));
            println!();
        }
    }

    if !report.uncovered.is_empty() {
        println!("{}", "-".repeat(70));
        println!("Advertised but uncovered — add five cases, or record a reason:");
        for u in &report.uncovered {
            println!("  {u}");
        }
        println!();
    }

    if !report.unseeded.is_empty() {
        println!("{}", "-".repeat(70));
        println!(
            "Patterns with no observable example ({}) — not a gap in the matrix \n\
             so much as a finding about the pattern set:",
            report.unseeded.len()
        );
        println!();
        // Group by diagnosis: the interesting number is how many share one.
        let mut by_reason: Vec<(&str, Vec<&str>)> = Vec::new();
        for (sub, why) in &report.unseeded {
            match by_reason.iter_mut().find(|(w, _)| w == why) {
                Some((_, v)) => v.push(sub),
                None => by_reason.push((why, vec![sub])),
            }
        }
        by_reason.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        for (why, subs) in by_reason {
            println!("  {} pattern(s):", subs.len());
            println!("      {}", wrap(why, 6));
            let shown: Vec<&str> = subs.iter().take(10).copied().collect();
            println!(
                "      {}{}",
                shown.join(", "),
                if subs.len() > shown.len() {
                    format!(", and {} more", subs.len() - shown.len())
                } else {
                    String::new()
                }
            );
            println!();
        }
    }

    if !report.gaps.is_empty() {
        println!("{}", "-".repeat(70));
        println!("Known gaps ({}):", report.gaps.len());
        for (capability, why) in &report.gaps {
            println!("  {capability}");
            println!("    {}", first_line(why));
        }
        println!();
    }
}

/// Re-wrap a source-continued note to the terminal, indenting continuations.
fn wrap(s: &str, indent: usize) -> String {
    let words: Vec<&str> = s.split_whitespace().collect();
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut col = indent;
    for w in words {
        if col + w.len() + 1 > 78 && col > indent {
            out.push('\n');
            out.push_str(&pad);
            col = indent;
        } else if !out.is_empty() {
            out.push(' ');
            col += 1;
        }
        out.push_str(w);
        col += w.len();
    }
    out
}

fn print_help() {
    println!(
        "siphon-conformance — run the conformance matrix

USAGE:
    siphon-conformance [OPTIONS]

OPTIONS:
    -c, --capability <NAME>   run only this capability (e.g. docx, zip, png)
        --json                machine-readable output
        --list                show the cases without running them
    -h, --help                this message

Every capability is asked the same five questions:

    clean        well-formed, nothing sensitive: does it read, and stay quiet?
    single       one planted value in the obvious place: is it found?
    structural   one planted value where the format lets you hide it
    damaged      truncated or corrupt: does the reader SAY so, rather than
                 report a faithful clean read?
    evasive      a format-specific bypass: is it still found?

Exit status is 0 only when every case passed and nothing Siphon advertises
is unaccounted for."
    );
}
