//! Polygon Siphon CLI — High-performance DLP scanner.
//!
//! Usage:
//!   siphon scan <file>         Scan a file
//!   siphon scan-dir <dir>      Scan a directory
//!   siphon scan-text <text>    Scan inline text
//!   siphon guard <text>        Run InputGuard on text

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use siphon::guard::{Action, InputGuard, Mode, Preset};
use siphon::pipeline::{self, Pipeline};
use siphon::scanner;

#[derive(Parser)]
#[command(name = "siphon", version = "2.1.0")]
#[command(
    about = "Polygon Siphon — high-performance DLP scanner to detect, redact, and protect sensitive data"
)]
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
    /// Interactive setup wizard — create or update .siphonrc config
    Init,
    /// Show or modify configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Test a pattern against sample text
    TestPattern {
        /// Regex pattern to test
        pattern: Option<String>,

        /// Sample text to test against (reads from stdin if omitted)
        #[arg(long)]
        text: Option<String>,
    },
    /// Show scanner info: version, patterns, features, config
    Info,
    /// Exact Data Match — register and scan for known sensitive values
    Edm {
        #[command(subcommand)]
        action: EdmAction,
    },
    /// Document Similarity — register and query for similar documents
    Lsh {
        #[command(subcommand)]
        action: LshAction,
    },
    /// Interactive TUI menu (requires tui feature)
    #[cfg(feature = "tui")]
    Tui,
    /// Live statistics dashboard (requires tui feature)
    #[cfg(feature = "tui")]
    Top,
    /// Forensic metadata extraction and author attribution
    #[cfg(feature = "forensics")]
    Forensics {
        /// Files to analyse. Give 1 file for a metadata dump; give
        /// 2+ files to also print pairwise attribution scores.
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Emit JSON instead of the default human-friendly summary.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Clone)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Key (e.g., min_confidence, require_context, blocked_extensions)
        key: String,
        /// Value
        value: String,
    },
    /// Reset configuration to defaults
    Reset,
    /// Show blocked file extensions
    Blocked,
    /// Add a blocked extension
    Block {
        /// Extension to block (e.g., "p8")
        ext: String,
    },
    /// Remove a blocked extension
    Unblock {
        /// Extension to unblock
        ext: String,
    },
}

#[derive(Subcommand, Clone)]
enum EdmAction {
    /// Register sensitive values for exact matching
    Register {
        /// Category name (e.g., "ssn", "account_numbers")
        category: String,
        /// Values to register (or --file to load from file)
        values: Vec<String>,
        /// Load values from file (one per line)
        #[arg(long)]
        file: Option<PathBuf>,
        /// EDM state file path
        #[arg(long, default_value = ".siphon-edm.json")]
        state: String,
    },
    /// Scan text or file against registered EDM values
    Scan {
        /// Text to scan (reads from stdin if omitted)
        text: Option<String>,
        /// EDM state file path
        #[arg(long, default_value = ".siphon-edm.json")]
        state: String,
    },
    /// List registered categories and hash counts
    List {
        /// EDM state file path
        #[arg(long, default_value = ".siphon-edm.json")]
        state: String,
    },
    /// Export EDM state to a backup file (validates and re-serializes)
    Export {
        /// Destination file path for the exported backup
        output: PathBuf,
        /// EDM state file path to export from
        #[arg(long, default_value = ".dlpscan-edm.json")]
        state: String,
    },
    /// Import EDM state from a backup file (validates before writing)
    Import {
        /// Source backup file to import from
        input: PathBuf,
        /// EDM state file path to write to
        #[arg(long, default_value = ".dlpscan-edm.json")]
        state: String,
        /// Overwrite existing state file if present
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Clone)]
enum LshAction {
    /// Register a document for similarity matching
    Register {
        /// Unique document identifier
        doc_id: String,
        /// File to register
        file: PathBuf,
        /// Sensitivity level (e.g., "confidential", "sensitive")
        #[arg(long, default_value = "sensitive")]
        sensitivity: String,
        /// LSH state file path
        #[arg(long, default_value = ".siphon-lsh.json")]
        state: String,
    },
    /// Query for documents similar to input
    Query {
        /// File to check for similarity
        file: PathBuf,
        /// Similarity threshold (0.0-1.0)
        #[arg(long, default_value = "0.8")]
        threshold: f64,
        /// LSH state file path
        #[arg(long, default_value = ".siphon-lsh.json")]
        state: String,
    },
    /// List registered documents
    List {
        /// LSH state file path
        #[arg(long, default_value = ".siphon-lsh.json")]
        state: String,
    },
    /// Export LSH vault to a backup file (validates and re-serializes)
    Export {
        /// Destination file path for the exported backup
        output: PathBuf,
        /// LSH state file path to export from
        #[arg(long, default_value = ".dlpscan-lsh.json")]
        state: String,
    },
    /// Import LSH vault from a backup file (validates before writing)
    Import {
        /// Source backup file to import from
        input: PathBuf,
        /// LSH state file path to write to
        #[arg(long, default_value = ".dlpscan-lsh.json")]
        state: String,
        /// Overwrite existing state file if present
        #[arg(long)]
        force: bool,
    },
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

    let categories: Option<HashSet<String>> = cli
        .categories
        .map(|c| c.split(',').map(|s| s.trim().to_string()).collect());

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
                Ok(matches) => match cli.format {
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
                },
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
                Ok(result) => match cli.format {
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
                },
                Err(siphon::DlpError::SensitiveDataDetected {
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
            let cats = siphon::patterns::categories();
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

        // ---------------------------------------------------------------
        // siphon init — Interactive setup wizard
        // ---------------------------------------------------------------
        Commands::Init => {
            run_init_wizard();
        }

        // ---------------------------------------------------------------
        // siphon config — Show/set configuration
        // ---------------------------------------------------------------
        Commands::Config { action } => {
            let config_path = find_or_default_config();
            match action {
                Some(ConfigAction::Show) | None => {
                    show_config(&config_path);
                }
                Some(ConfigAction::Set { key, value }) => {
                    set_config_value(&config_path, &key, &value);
                }
                Some(ConfigAction::Reset) => {
                    reset_config(&config_path);
                }
                Some(ConfigAction::Blocked) => {
                    let config = load_config(&config_path);
                    println!("Blocked extensions ({}):", config.blocked_extensions.len());
                    for ext in &config.blocked_extensions {
                        println!("  .{ext}");
                    }
                    println!("\nBlock unreadable: {}", config.block_unreadable);
                }
                Some(ConfigAction::Block { ext }) => {
                    let mut config = load_config(&config_path);
                    let ext = ext.trim_start_matches('.').to_lowercase();
                    if !config.blocked_extensions.contains(&ext) {
                        config.blocked_extensions.push(ext.clone());
                        save_config(&config_path, &config);
                        println!("Blocked .{ext}");
                    } else {
                        println!(".{ext} is already blocked");
                    }
                }
                Some(ConfigAction::Unblock { ext }) => {
                    let mut config = load_config(&config_path);
                    let ext = ext.trim_start_matches('.').to_lowercase();
                    let before = config.blocked_extensions.len();
                    config.blocked_extensions.retain(|e| e != &ext);
                    if config.blocked_extensions.len() < before {
                        save_config(&config_path, &config);
                        println!("Unblocked .{ext}");
                    } else {
                        println!(".{ext} was not blocked");
                    }
                }
            }
        }

        // ---------------------------------------------------------------
        // siphon test-pattern — Test a regex pattern against text
        // ---------------------------------------------------------------
        Commands::TestPattern { pattern, text } => {
            run_test_pattern(pattern, text);
        }

        // ---------------------------------------------------------------
        // siphon edm — Exact Data Match
        // ---------------------------------------------------------------
        Commands::Edm { action } => match action {
            EdmAction::Register {
                category,
                values,
                file,
                state,
            } => {
                let mut edm = if std::path::Path::new(&state).exists() {
                    siphon::edm::ExactDataMatcher::load(&state)
                        .unwrap_or_else(|_| siphon::edm::ExactDataMatcher::new(None, None))
                } else {
                    siphon::edm::ExactDataMatcher::new(None, None)
                };

                let mut all_values = values;
                if let Some(file_path) = file {
                    match std::fs::read_to_string(&file_path) {
                        Ok(content) => {
                            all_values.extend(
                                content
                                    .lines()
                                    .map(|l| l.trim().to_string())
                                    .filter(|l| !l.is_empty() && !l.starts_with('#')),
                            );
                        }
                        Err(e) => {
                            eprintln!("Error reading file: {e}");
                            process::exit(1);
                        }
                    }
                }

                let refs: Vec<&str> = all_values.iter().map(|s| s.as_str()).collect();
                let count = edm.register_values(&category, &refs);
                edm.save(&state).unwrap_or_else(|e| {
                    eprintln!("Error saving EDM state: {e}");
                    process::exit(1);
                });
                println!(
                    "Registered {} values in category '{}' ({} total hashes)",
                    all_values.len(),
                    category,
                    count
                );
                println!("State saved to {state}");
            }
            EdmAction::Scan { text, state } => {
                if !std::path::Path::new(&state).exists() {
                    eprintln!("No EDM state file found at {state}");
                    eprintln!("Run `siphon edm register` first");
                    process::exit(1);
                }
                let edm = siphon::edm::ExactDataMatcher::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading EDM state: {e}");
                    process::exit(1);
                });

                let text = text.unwrap_or_else(|| {
                    let mut buf = String::new();
                    io::stdin().read_to_string(&mut buf).unwrap_or_default();
                    buf
                });

                let matches = edm.scan(&text, None);
                if matches.is_empty() {
                    println!("No EDM matches found.");
                } else {
                    println!("{} EDM matches found:", matches.len());
                    for m in &matches {
                        println!(
                            "  [{}] \"{}\" at {}..{}",
                            m.category, m.matched_text, m.span.0, m.span.1
                        );
                    }
                }
            }
            EdmAction::List { state } => {
                if !std::path::Path::new(&state).exists() {
                    println!("No EDM state file found. Run `siphon edm register` first.");
                    return;
                }
                let edm = siphon::edm::ExactDataMatcher::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading EDM state: {e}");
                    process::exit(1);
                });
                let cats = edm.categories();
                println!("EDM categories ({}):", cats.len());
                for cat in cats {
                    println!("  {cat}");
                }
                println!("Total hashes: {}", edm.total_hashes());
            }
            EdmAction::Export { output, state } => {
                if !std::path::Path::new(&state).exists() {
                    eprintln!("No EDM state file found at {state}");
                    eprintln!("Run `dlpscan edm register` first");
                    process::exit(1);
                }
                let edm = siphon::edm::ExactDataMatcher::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading EDM state: {e}");
                    process::exit(1);
                });
                let out_str = output.to_string_lossy().to_string();
                edm.save(&out_str).unwrap_or_else(|e| {
                    eprintln!("Error writing EDM backup: {e}");
                    process::exit(1);
                });
                println!(
                    "Exported EDM state ({} categories, {} hashes) to {}",
                    edm.categories().len(),
                    edm.total_hashes(),
                    out_str
                );
            }
            EdmAction::Import {
                input,
                state,
                force,
            } => {
                if !input.exists() {
                    eprintln!("Source backup not found: {}", input.display());
                    process::exit(1);
                }
                if std::path::Path::new(&state).exists() && !force {
                    eprintln!("Destination state file already exists: {state}");
                    eprintln!("Use --force to overwrite");
                    process::exit(1);
                }
                let in_str = input.to_string_lossy().to_string();
                let edm = siphon::edm::ExactDataMatcher::load(&in_str).unwrap_or_else(|e| {
                    eprintln!("Error loading EDM backup: {e}");
                    process::exit(1);
                });
                edm.save(&state).unwrap_or_else(|e| {
                    eprintln!("Error writing EDM state: {e}");
                    process::exit(1);
                });
                println!(
                    "Imported EDM state ({} categories, {} hashes) into {}",
                    edm.categories().len(),
                    edm.total_hashes(),
                    state
                );
            }
        },

        // ---------------------------------------------------------------
        // siphon lsh — Document Similarity
        // ---------------------------------------------------------------
        Commands::Lsh { action } => match action {
            LshAction::Register {
                doc_id,
                file,
                sensitivity,
                state,
            } => {
                let vault = if std::path::Path::new(&state).exists() {
                    siphon::lsh::DocumentVault::load(&state)
                        .unwrap_or_else(|_| siphon::lsh::DocumentVault::default_vault())
                } else {
                    siphon::lsh::DocumentVault::default_vault()
                };

                let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                    eprintln!("Error reading file: {e}");
                    process::exit(1);
                });

                vault.register(&doc_id, &text, &sensitivity, None);
                vault.save(&state).unwrap_or_else(|e| {
                    eprintln!("Error saving LSH state: {e}");
                    process::exit(1);
                });
                println!(
                    "Registered document '{}' ({} bytes, sensitivity: {})",
                    doc_id,
                    text.len(),
                    sensitivity
                );
                println!(
                    "Vault: {} documents, saved to {state}",
                    vault.document_count()
                );
            }
            LshAction::Query {
                file,
                threshold,
                state,
            } => {
                if !std::path::Path::new(&state).exists() {
                    eprintln!("No LSH state file found at {state}");
                    eprintln!("Run `siphon lsh register` first");
                    process::exit(1);
                }
                let vault = siphon::lsh::DocumentVault::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading LSH state: {e}");
                    process::exit(1);
                });

                let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                    eprintln!("Error reading file: {e}");
                    process::exit(1);
                });

                let matches = vault.query(&text, Some(threshold));
                if matches.is_empty() {
                    println!(
                        "No similar documents found (threshold: {:.0}%).",
                        threshold * 100.0
                    );
                } else {
                    println!("{} similar documents found:", matches.len());
                    for m in &matches {
                        println!(
                            "  [{:.0}%] {} (sensitivity: {})",
                            m.similarity * 100.0,
                            m.doc_id,
                            m.sensitivity
                        );
                    }
                }
            }
            LshAction::List { state } => {
                if !std::path::Path::new(&state).exists() {
                    println!("No LSH state file found. Run `siphon lsh register` first.");
                    return;
                }
                let vault = siphon::lsh::DocumentVault::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading LSH state: {e}");
                    process::exit(1);
                });
                println!("LSH vault: {} documents registered", vault.document_count());
            }
            LshAction::Export { output, state } => {
                if !std::path::Path::new(&state).exists() {
                    eprintln!("No LSH state file found at {state}");
                    eprintln!("Run `dlpscan lsh register` first");
                    process::exit(1);
                }
                let vault = siphon::lsh::DocumentVault::load(&state).unwrap_or_else(|e| {
                    eprintln!("Error loading LSH state: {e}");
                    process::exit(1);
                });
                let out_str = output.to_string_lossy().to_string();
                vault.save(&out_str).unwrap_or_else(|e| {
                    eprintln!("Error writing LSH backup: {e}");
                    process::exit(1);
                });
                println!(
                    "Exported LSH vault ({} documents) to {}",
                    vault.document_count(),
                    out_str
                );
            }
            LshAction::Import {
                input,
                state,
                force,
            } => {
                if !input.exists() {
                    eprintln!("Source backup not found: {}", input.display());
                    process::exit(1);
                }
                if std::path::Path::new(&state).exists() && !force {
                    eprintln!("Destination state file already exists: {state}");
                    eprintln!("Use --force to overwrite");
                    process::exit(1);
                }
                let in_str = input.to_string_lossy().to_string();
                let vault = siphon::lsh::DocumentVault::load(&in_str).unwrap_or_else(|e| {
                    eprintln!("Error loading LSH backup: {e}");
                    process::exit(1);
                });
                vault.save(&state).unwrap_or_else(|e| {
                    eprintln!("Error writing LSH state: {e}");
                    process::exit(1);
                });
                println!(
                    "Imported LSH vault ({} documents) into {}",
                    vault.document_count(),
                    state
                );
            }
        },

        // ---------------------------------------------------------------
        // siphon tui — Interactive TUI menu
        // ---------------------------------------------------------------
        #[cfg(feature = "tui")]
        Commands::Tui => {
            if let Err(e) = siphon::tui::app::run_menu() {
                eprintln!("TUI error: {e}");
                process::exit(1);
            }
        }

        // ---------------------------------------------------------------
        // siphon top — Live statistics dashboard
        // ---------------------------------------------------------------
        #[cfg(feature = "tui")]
        Commands::Top => {
            if let Err(e) = siphon::tui::app::run_live_stats() {
                eprintln!("TUI error: {e}");
                process::exit(1);
            }
        }

        // ---------------------------------------------------------------
        // siphon forensics — Metadata extraction + attribution
        // ---------------------------------------------------------------
        #[cfg(feature = "forensics")]
        Commands::Forensics { files, json } => {
            if let Err(e) = run_forensics(&files, json) {
                eprintln!("forensics: {e}");
                process::exit(1);
            }
        }

        // ---------------------------------------------------------------
        // siphon info — Show scanner info
        // ---------------------------------------------------------------
        Commands::Info => {
            println!();
            println!("  Polygon Siphon v{}", env!("CARGO_PKG_VERSION"));
            println!("  High-Performance DLP Scanner");
            println!();
            println!(
                "Patterns:    {} across {} categories",
                siphon::patterns::PATTERNS.len(),
                siphon::patterns::categories().len()
            );
            println!("Features:    {}", built_features().join(", "));
            println!();
            let config_path = find_or_default_config();
            if std::path::Path::new(&config_path).exists() {
                println!("Config:      {config_path}");
                let config = load_config(&config_path);
                println!("  min_confidence:    {:.2}", config.min_confidence);
                println!("  require_context:   {}", config.require_context);
                println!("  block_unreadable:  {}", config.block_unreadable);
                println!(
                    "  blocked_extensions: {} types",
                    config.blocked_extensions.len()
                );
            } else {
                println!("Config:      (none — run `siphon init` to create)");
            }
            println!();
            let exts = siphon::extractors::supported_extensions();
            println!("Supported formats: {} file types", exts.len());
        }
    }
}

// ===========================================================================
// Interactive setup wizard
// ===========================================================================

fn run_init_wizard() {
    println!("siphon setup wizard");
    println!("====================");
    println!();

    // 1. Choose config location
    let config_path = prompt("Config file path", ".siphonrc");

    if std::path::Path::new(&config_path).exists() {
        let overwrite = prompt("Config already exists. Overwrite? (y/n)", "n");
        if overwrite.to_lowercase() != "y" {
            println!("Aborted.");
            return;
        }
    }

    // 2. Minimum confidence
    let min_conf = prompt("Minimum confidence threshold (0.0-1.0)", "0.5");
    let min_confidence: f64 = min_conf.parse().unwrap_or(0.5);

    // 3. Require context
    let req_ctx = prompt("Require context keywords for all matches? (y/n)", "n");
    let require_context = req_ctx.to_lowercase() == "y";

    // 4. Block unreadable
    let block_unread = prompt(
        "Block unreadable files (executables, encrypted, media)? (y/n)",
        "n",
    );
    let block_unreadable = block_unread.to_lowercase() == "y";

    // 5. Presets
    println!();
    println!("Available presets:");
    println!("  1. pci-dss       Credit card & banking data");
    println!("  2. pii           Personal identifiable information");
    println!("  3. credentials   API keys, tokens, secrets");
    println!("  4. healthcare    Medical/insurance data");
    println!("  5. financial     All financial data");
    println!("  6. contact-info  Email, phone, addresses");
    println!("  7. all           All of the above");
    let preset_choice = prompt("Select presets (comma-separated numbers, e.g., 1,2,3)", "7");
    let categories = parse_preset_choices(&preset_choice);

    // 6. Output format
    let format = prompt("Default output format (text/json/csv)", "text");

    // Build config
    let config = siphon::config::Config {
        min_confidence,
        require_context,
        deduplicate: true,
        max_matches: 50_000,
        format,
        categories: if categories.is_empty() {
            None
        } else {
            Some(categories)
        },
        allowlist: vec![],
        ignore_patterns: vec![],
        ignore_paths: vec![],
        context_backend: "regex".to_string(),
        blocked_extensions: siphon::extractors::DEFAULT_BLOCKED_EXTENSIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        block_unreadable,
        entropy_scan: "off".to_string(),
    };

    save_config(&config_path, &config);

    println!();
    println!("Configuration saved to {config_path}");
    println!();
    println!("Next steps:");
    println!("  siphon scan <file>              Scan a file");
    println!("  siphon scan-dir <directory>     Scan a directory");
    println!("  siphon config show              View configuration");
    println!("  siphon config set <key> <value> Modify a setting");
    println!("  siphon test-pattern             Test a regex pattern");
    println!("  siphon info                     Show scanner info");
}

/// Maximum length of a single interactive-prompt response. Interactive
/// CLI flows don't need more than a few thousand characters for any
/// setting, and capping guards against an operator accidentally piping
/// a multi-megabyte file (or an attacker feeding stdin a long blob)
/// into a setup wizard expecting a word.
const PROMPT_MAX_LEN: usize = 4096;

fn prompt(label: &str, default: &str) -> String {
    use std::io::{self, BufRead, Write};
    print!("{label} [{default}]: ");
    // A broken stdout (e.g. the operator backgrounded the process) is
    // not a reason to crash — swallow the flush error and keep going.
    let _ = io::stdout().flush();

    // Bound the read so a malicious or accidental long line cannot
    // grow `input` without limit. `.take()` gives us a one-shot upper
    // bound on the number of bytes pulled from stdin for this prompt.
    let stdin = io::stdin();
    let mut limited = stdin.lock().take(PROMPT_MAX_LEN as u64);
    let mut input = String::new();
    if limited.read_line(&mut input).is_err() {
        // Broken pipe / EOF / encoding error: fall back to the default
        // rather than panicking and killing an interactive session.
        return default.to_string();
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_preset_choices(input: &str) -> Vec<String> {
    let mut categories = Vec::new();
    for part in input.split(',') {
        match part.trim() {
            "1" => categories.push("pci-dss".into()),
            "2" => categories.push("pii".into()),
            "3" => categories.push("credentials".into()),
            "4" => categories.push("healthcare".into()),
            "5" => categories.push("financial".into()),
            "6" => categories.push("contact-info".into()),
            "7" | "all" => return vec![], // None = all categories
            _ => {}
        }
    }
    categories
}

// ===========================================================================
// Config management
// ===========================================================================

fn find_or_default_config() -> String {
    siphon::config::find_config_path()
}

fn load_config(path: &str) -> siphon::config::Config {
    siphon::config::load_config_json(path)
}

fn save_config(path: &str, config: &siphon::config::Config) {
    if let Err(e) = siphon::config::save_config_json(path, config) {
        eprintln!("Error writing config: {e}");
        process::exit(1);
    }
}

fn show_config(path: &str) {
    let config = load_config(path);
    println!("Config: {path}");
    println!(
        "{}",
        serde_json::to_string_pretty(&config).unwrap_or_default()
    );
}

fn set_config_value(path: &str, key: &str, value: &str) {
    let mut config = load_config(path);
    match key {
        "min_confidence" => {
            config.min_confidence = value.parse().unwrap_or_else(|_| {
                eprintln!("Invalid float: {value}");
                process::exit(1);
            });
        }
        "require_context" => {
            config.require_context = value == "true" || value == "1";
        }
        "deduplicate" => {
            config.deduplicate = value == "true" || value == "1";
        }
        "max_matches" => {
            config.max_matches = value.parse().unwrap_or(50_000);
        }
        "format" => {
            config.format = value.to_string();
        }
        "block_unreadable" => {
            config.block_unreadable = value == "true" || value == "1";
        }
        "context_backend" => {
            config.context_backend = value.to_string();
        }
        _ => {
            eprintln!("Unknown config key: {key}");
            eprintln!("Valid keys: min_confidence, require_context, deduplicate, max_matches, format, block_unreadable, context_backend");
            process::exit(1);
        }
    }
    save_config(path, &config);
    println!("Set {key} = {value}");
}

fn reset_config(path: &str) {
    let config = siphon::config::Config::default();
    save_config(path, &config);
    println!("Config reset to defaults: {path}");
}

// ===========================================================================
// Test pattern
// ===========================================================================

fn run_test_pattern(pattern: Option<String>, text: Option<String>) {
    let pattern = pattern.unwrap_or_else(|| prompt("Regex pattern", r"\b\d{3}-\d{2}-\d{4}\b"));

    // Validate regex
    let re = match regex::Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Invalid regex: {e}");
            process::exit(1);
        }
    };

    let text =
        text.unwrap_or_else(|| prompt("Sample text", "SSN: 425-71-3482, card: 4532015112830366"));

    println!();
    println!("Pattern: {pattern}");
    println!("Text:    {text}");
    println!();

    let matches: Vec<_> = re.find_iter(&text).collect();
    if matches.is_empty() {
        println!("No matches found.");
    } else {
        println!("Matches ({}):", matches.len());
        for m in &matches {
            println!("  [{}-{}] \"{}\"", m.start(), m.end(), m.as_str());
        }
    }

    // Also run through the full scanner for comparison
    println!();
    println!("--- Full scanner results ---");
    match scanner::scan_text(&text) {
        Ok(results) => {
            if results.is_empty() {
                println!("No DLP findings.");
            } else {
                for m in &results {
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
        Err(e) => eprintln!("Scanner error: {e}"),
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn built_features() -> Vec<&'static str> {
    let mut features = vec!["core"];
    #[cfg(feature = "metrics")]
    features.push("metrics");
    #[cfg(feature = "pdf")]
    features.push("pdf");
    #[cfg(feature = "office")]
    features.push("office");
    #[cfg(feature = "archives")]
    features.push("archives");
    #[cfg(feature = "data-formats")]
    features.push("data-formats");
    #[cfg(feature = "msg")]
    features.push("msg");
    #[cfg(feature = "barcode")]
    features.push("barcode");
    #[cfg(feature = "async-support")]
    features.push("async-support");
    #[cfg(feature = "tls")]
    features.push("tls");
    #[cfg(feature = "forensics")]
    features.push("forensics");
    features
}

// ---------------------------------------------------------------------------
// Forensics subcommand
// ---------------------------------------------------------------------------
#[cfg(feature = "forensics")]
fn run_forensics(files: &[PathBuf], json: bool) -> Result<(), Box<dyn std::error::Error>> {
    use siphon_core::forensics::{compare, extract_metadata, FileMetadata};

    // Collect metadata for each input — skip any that fail so one
    // unreadable file doesn't sink the whole batch.
    let mut records: Vec<(PathBuf, FileMetadata)> = Vec::with_capacity(files.len());
    for path in files {
        match extract_metadata(path) {
            Ok(meta) => records.push((path.clone(), meta)),
            Err(e) => eprintln!("{}: {}", path.display(), e),
        }
    }
    if records.is_empty() {
        return Err("no files parsed successfully".into());
    }

    // Pairwise comparisons — O(n²/2) over `records`. Fine for the
    // CLI's batch-of-a-dozen use case; if a caller wants a 10k
    // matrix they should script against the library API directly.
    let mut pairs = Vec::new();
    for i in 0..records.len() {
        for j in (i + 1)..records.len() {
            let (a, b) = (&records[i].1, &records[j].1);
            let score = compare(a, b);
            pairs.push((records[i].0.clone(), records[j].0.clone(), score));
        }
    }

    if json {
        let payload = serde_json::json!({
            "records": records.iter().map(|(_, m)| m).collect::<Vec<_>>(),
            "pairs": pairs.iter().map(|(a, b, s)| serde_json::json!({
                "a": a.display().to_string(),
                "b": b.display().to_string(),
                "score": s,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    // Human-readable layout: metadata per file, then a score matrix.
    for (path, meta) in &records {
        println!("── {} ──", path.display());
        print_meta_line("kind", &format!("{:?}", meta.kind));
        print_meta_line("sha256", &meta.content_hash);
        print_meta_line("size", &format!("{} bytes", meta.size_bytes));
        if let Some(v) = &meta.creator {
            print_meta_line("creator", v);
        }
        if let Some(v) = &meta.last_modified_by {
            print_meta_line("last modified by", v);
        }
        if let Some(v) = &meta.application {
            print_meta_line("application", v);
        }
        if let Some(v) = &meta.company {
            print_meta_line("company", v);
        }
        if let Some(v) = &meta.title {
            print_meta_line("title", v);
        }
        if let Some(v) = &meta.created_at {
            print_meta_line("created", v);
        }
        if let Some(v) = &meta.modified_at {
            print_meta_line("modified", v);
        }
        if !meta.rsids.is_empty() {
            print_meta_line(
                "rsids",
                &format!(
                    "{} sessions (root: {})",
                    meta.rsids.len(),
                    meta.rsids.first().cloned().unwrap_or_default()
                ),
            );
        }
        if let Some((id0, id1)) = &meta.pdf_doc_id {
            print_meta_line("pdf /ID", &format!("{id0} / {id1}"));
        }
        println!();
    }

    if !pairs.is_empty() {
        println!("── attribution ──");
        for (a, b, score) in &pairs {
            println!("{:>5.2}  {}  ↔  {}", score.total, a.display(), b.display());
            for sig in &score.signals {
                println!("        +{:.2}  {}", sig.weight, sig.detail);
            }
        }
    }

    Ok(())
}

#[cfg(feature = "forensics")]
fn print_meta_line(label: &str, value: &str) {
    println!("  {:<18} {}", label, value);
}
