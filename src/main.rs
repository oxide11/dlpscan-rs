//! dlpscan CLI — High-performance DLP scanner.
//!
//! Usage:
//!   dlpscan scan <file>         Scan a file
//!   dlpscan scan-dir <dir>      Scan a directory
//!   dlpscan scan-text <text>    Scan inline text
//!   dlpscan guard <text>        Run InputGuard on text

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use dlpscan::guard::{Action, InputGuard, Mode, Preset};
use dlpscan::pipeline::{self, Pipeline};
use dlpscan::scanner;

#[derive(Parser)]
#[command(name = "dlpscan", version = "2.0.0")]
#[command(about = "High-performance DLP scanner — detect, redact, and protect sensitive data")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Only show matches with confidence >= threshold
    #[arg(long, default_value = "0.0", global = true)]
    min_confidence: f64,

    /// Require context keywords for matches
    #[arg(long, global = true)]
    require_context: bool,

    /// Only scan these categories (comma-separated)
    #[arg(long, global = true)]
    categories: Option<String>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for sensitive data
    Scan {
        /// File path to scan
        file: PathBuf,
    },
    /// Scan a directory for sensitive data
    ScanDir {
        /// Directory path
        dir: PathBuf,

        /// Recurse into subdirectories
        #[arg(short, long, default_value = "true")]
        recursive: bool,
    },
    /// Scan text from argument or stdin
    ScanText {
        /// Text to scan (reads from stdin if omitted)
        text: Option<String>,
    },
    /// Run InputGuard on text
    Guard {
        /// Text to guard
        text: Option<String>,

        /// Guard action
        #[arg(long, default_value = "flag")]
        action: GuardAction,

        /// Guard mode
        #[arg(long, default_value = "denylist")]
        mode: GuardMode,

        /// Presets (comma-separated)
        #[arg(long)]
        presets: Option<String>,

        /// Redaction character
        #[arg(long, default_value = "X")]
        redact_char: char,
    },
    /// List available categories
    Categories,
    /// List available presets
    Presets,
}

#[derive(Clone, ValueEnum)]
enum GuardAction {
    Reject,
    Redact,
    Flag,
    Tokenize,
    Obfuscate,
}

#[derive(Clone, ValueEnum)]
enum GuardMode {
    Denylist,
    Allowlist,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let categories: Option<HashSet<String>> = cli.categories.map(|c| {
        c.split(',')
            .map(|s| s.trim().to_string())
            .collect()
    });

    match cli.command {
        Commands::Scan { file } => {
            let start = Instant::now();
            let pipeline = Pipeline::new()
                .with_min_confidence(cli.min_confidence)
                .with_require_context(cli.require_context);

            let result = pipeline.process_file(&file);
            let elapsed = start.elapsed();

            if let Some(ref err) = result.error {
                eprintln!("Error: {err}");
                process::exit(1);
            }

            match cli.format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        pipeline::results_to_json(&[result], true).unwrap_or_default()
                    );
                }
                OutputFormat::Csv => {
                    print!("{}", pipeline::results_to_csv(&[result]));
                }
                _ => {
                    println!("File: {}", result.file_path);
                    println!("Format: {}", result.format_detected);
                    println!("Matches: {}", result.match_count());
                    println!("Duration: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
                    println!();
                    for m in &result.matches {
                        println!(
                            "  [{:.0}%] {} / {} — \"{}\" at {}..{}{}",
                            m.confidence * 100.0,
                            m.category,
                            m.sub_category,
                            m.redacted_text(),
                            m.span.0,
                            m.span.1,
                            if m.has_context { " [context]" } else { "" }
                        );
                    }
                }
            }
        }

        Commands::ScanDir { dir, recursive } => {
            let start = Instant::now();
            let mut pipeline = Pipeline::new()
                .with_min_confidence(cli.min_confidence)
                .with_require_context(cli.require_context);

            if let Some(cats) = categories {
                pipeline = pipeline.with_categories(cats);
            }

            let results = pipeline.process_directory(&dir, recursive);
            let elapsed = start.elapsed();

            let total_matches: usize = results.iter().map(|r| r.match_count()).sum();
            let total_files = results.len();
            let errors: usize = results.iter().filter(|r| r.error.is_some()).count();

            match cli.format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        pipeline::results_to_json(&results, true).unwrap_or_default()
                    );
                }
                OutputFormat::Csv => {
                    print!("{}", pipeline::results_to_csv(&results));
                }
                _ => {
                    for r in &results {
                        if r.match_count() > 0 {
                            println!("{}: {} matches", r.file_path, r.match_count());
                            for m in &r.matches {
                                println!(
                                    "  [{:.0}%] {} / {} — \"{}\"{}",
                                    m.confidence * 100.0,
                                    m.category,
                                    m.sub_category,
                                    m.redacted_text(),
                                    if m.has_context { " [context]" } else { "" }
                                );
                            }
                        }
                    }
                    println!();
                    println!(
                        "Scanned {total_files} files, found {total_matches} matches in {:.2}s ({errors} errors)",
                        elapsed.as_secs_f64()
                    );
                }
            }
        }

        Commands::ScanText { text } => {
            let text = text.unwrap_or_else(|| {
                let mut buf = String::new();
                let max_stdin = 10 * 1024 * 1024; // 10 MB
                match io::stdin().take(max_stdin as u64).read_to_string(&mut buf) {
                    Ok(_) => buf,
                    Err(e) => {
                        eprintln!("Error reading stdin: {e}");
                        process::exit(1);
                    }
                }
            });

            let config = scanner::ScanConfig {
                categories,
                require_context: cli.require_context,
                min_confidence: cli.min_confidence,
                ..Default::default()
            };

            match scanner::scan_text_with_config(&text, &config) {
                Ok(matches) => {
                    match cli.format {
                        OutputFormat::Json => {
                            let json_matches: Vec<_> =
                                matches.iter().map(|m| m.to_dict(false)).collect();
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json_matches).unwrap_or_default()
                            );
                        }
                        _ => {
                            for m in &matches {
                                println!(
                                    "[{:.0}%] {} / {} — \"{}\" at {}..{}{}",
                                    m.confidence * 100.0,
                                    m.category,
                                    m.sub_category,
                                    m.redacted_text(),
                                    m.span.0,
                                    m.span.1,
                                    if m.has_context { " [context]" } else { "" }
                                );
                            }
                            println!("\n{} matches found.", matches.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Guard {
            text,
            action,
            mode,
            presets,
            redact_char,
        } => {
            let text = text.unwrap_or_else(|| {
                let mut buf = String::new();
                let max_stdin = 10 * 1024 * 1024; // 10 MB
                match io::stdin().take(max_stdin as u64).read_to_string(&mut buf) {
                    Ok(_) => buf,
                    Err(e) => {
                        eprintln!("Error reading stdin: {e}");
                        process::exit(1);
                    }
                }
            });

            let action = match action {
                GuardAction::Reject => Action::Reject,
                GuardAction::Redact => Action::Redact,
                GuardAction::Flag => Action::Flag,
                GuardAction::Tokenize => Action::Tokenize,
                GuardAction::Obfuscate => Action::Obfuscate,
            };

            let mode = match mode {
                GuardMode::Denylist => Mode::Denylist,
                GuardMode::Allowlist => Mode::Allowlist,
            };

            let presets: Vec<Preset> = presets
                .map(|p| {
                    p.split(',')
                        .filter_map(|s| match s.trim().to_lowercase().as_str() {
                            "pci_dss" | "pci-dss" => Some(Preset::PciDss),
                            "ssn_sin" | "ssn-sin" => Some(Preset::SsnSin),
                            "pii" => Some(Preset::Pii),
                            "pii_strict" | "pii-strict" => Some(Preset::PiiStrict),
                            "credentials" => Some(Preset::Credentials),
                            "financial" => Some(Preset::Financial),
                            "healthcare" => Some(Preset::Healthcare),
                            "contact_info" | "contact-info" => Some(Preset::ContactInfo),
                            _ => {
                                eprintln!("Unknown preset: {s}");
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let guard = InputGuard::new()
                .with_presets(presets)
                .with_action(action)
                .with_mode(mode)
                .with_min_confidence(cli.min_confidence)
                .with_require_context(cli.require_context)
                .with_redaction_char(redact_char);

            match guard.scan(&text) {
                Ok(result) => {
                    match cli.format {
                        OutputFormat::Json => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&result).unwrap_or_default()
                            );
                        }
                        _ => {
                            println!("Clean: {}", result.is_clean);
                            println!("Findings: {}", result.finding_count());
                            if let Some(ref redacted) = result.redacted_text {
                                println!("Redacted: {redacted}");
                            }
                            for m in &result.findings {
                                println!(
                                    "  [{:.0}%] {} / {} — \"{}\"",
                                    m.confidence * 100.0,
                                    m.category,
                                    m.sub_category,
                                    m.redacted_text()
                                );
                            }
                        }
                    }
                }
                Err(dlpscan::DlpError::SensitiveDataDetected {
                    finding_count,
                    categories,
                }) => {
                    eprintln!(
                        "REJECTED: {finding_count} sensitive data findings in: {}",
                        categories.join(", ")
                    );
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Categories => {
            let cats = dlpscan::patterns::categories();
            for cat in cats {
                println!("  {cat}");
            }
        }

        Commands::Presets => {
            println!("Available presets:");
            println!("  pci-dss       Credit card & banking data");
            println!("  ssn-sin       Social security numbers");
            println!("  pii           Personal identifiable information");
            println!("  pii-strict    PII + regional identifiers");
            println!("  credentials   API keys, tokens, secrets");
            println!("  financial     All financial data");
            println!("  healthcare    Medical/insurance data");
            println!("  contact-info  Email, phone, addresses");
        }
    }
}
