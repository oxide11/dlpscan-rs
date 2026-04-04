# dlpscan-rs

High-performance DLP scanner written in Rust. Detects, redacts, and protects
sensitive data with exceptional throughput.

**560 patterns** across **126 categories** — full parity with the Python version.
**15,000+ lines** of Rust across 37 modules. **127 tests** passing.

## Performance

| Scenario (1MB) | Python | Rust | Speedup |
|---|---:|---:|---:|
| Clean text | 2.5 MB/s | 83.2 MB/s | **33x** |
| Mixed content | 1.0 MB/s | 30.2 MB/s | **30x** |
| Dense sensitive data | 0.5 MB/s | 31.9 MB/s | **64x** |

See [BENCHMARKS.md](BENCHMARKS.md) for full results including optimization
journey, latency tables, and baseline-vs-full comparison.

## Installation

```bash
# Build from source
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo run --release --bin benchmark
```

### Feature flags

| Feature | Default | Description |
|---|---|---|
| `metrics` | Yes | Prometheus metrics via `prometheus` crate |
| `pdf` | No | PDF text extraction via `pdf-extract` |
| `office` | No | DOCX/XLSX/ODS/ODT/PPTX extraction via `calamine` + `quick-xml` |
| `archives` | No | RAR and 7z archive extraction via `unrar` + `sevenz-rust` |
| `data-formats` | No | Parquet, SQLite extraction via `parquet` + `arrow` + `rusqlite` |
| `msg` | No | Outlook MSG extraction via `cfb` |
| `async-support` | No | Async HTTP server and webhooks via `tokio` + `reqwest` |
| `python` | No | Python bindings via `pyo3` |
| `full` | No | All optional features |

```bash
cargo build --release --features full
```

## Quick Start

### InputGuard (application integration)

```rust
use dlpscan::{InputGuard, Preset, Action, Mode};

// Block PCI-DSS data and PII — flag on detection
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii])
    .with_action(Action::Flag);

let result = guard.scan("My card is 4532015112830366")?;
println!("Clean: {}", result.is_clean);       // false
println!("Findings: {}", result.finding_count()); // 1

// Redact sensitive data
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss])
    .with_action(Action::Redact);

let result = guard.scan("card: 4532015112830366")?;
println!("{}", result.redacted_text.unwrap()); // "card: XXXXXXXXXXXXXXXX"

// Obfuscate with realistic fake data
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss])
    .with_action(Action::Obfuscate);

let result = guard.scan("card: 4532015112830366")?;
println!("{}", result.redacted_text.unwrap()); // "card: 4758286118069724"
```

### Presets

| Preset | What it covers |
|---|---|
| `Preset::PciDss` | Credit card numbers, PANs, track data, card expiry |
| `Preset::Pii` | Personal identifiers, geolocation, device IDs |
| `Preset::Credentials` | API keys, tokens, secrets, database connection strings |
| `Preset::Healthcare` | Medical identifiers, insurance codes |
| `Preset::ContactInfo` | Email, phone, IP, MAC addresses |

### Actions

| Action | Behavior |
|---|---|
| `Action::Reject` | Returns error when sensitive data is found |
| `Action::Redact` | Replaces sensitive data with redaction characters |
| `Action::Flag` | Returns findings without modifying text |
| `Action::Tokenize` | Replaces with reversible tokens |
| `Action::Obfuscate` | Replaces with realistic fake data (Luhn-valid CCs, etc.) |

### Baseline-only mode

For high-throughput pipelines, restrict scanning to only the 108 highest-confidence
patterns (SSNs, credit cards, national IDs, secrets, crypto addresses):

```rust
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii, Preset::Credentials])
    .with_baseline_only(true);
```

### Low-level scanner API

```rust
use dlpscan::scanner::{scan_text, scan_text_with_config, ScanConfig};

// Scan with defaults
let matches = scan_text("SSN: 123-45-6789")?;

// Scan with custom config
let config = ScanConfig {
    categories: Some(["Credit Card Numbers".to_string()].into()),
    min_confidence: 0.5,
    require_context: true,
    baseline_only: false,
    ..Default::default()
};
let matches = scan_text_with_config("Card: 4532015112830366", &config)?;
```

## Modules

### Core scanning

| Module | Description |
|---|---|
| `scanner` | Core engine — parallel regex matching with Rayon, AC prefilter |
| `patterns` | 560 compiled regex patterns across 126 categories |
| `context` | Aho-Corasick keyword proximity matching (560+ keywords) |
| `normalize` | Unicode normalization (zero-width, homoglyphs, whitespace) |
| `scoring` | Confidence scoring and overlapping match deduplication |
| `validation` | Luhn check, input validation |
| `models` | `Match`, `PatternDef`, specificity scores |

### Guard and protection

| Module | Description |
|---|---|
| `guard` | `InputGuard` — high-level scan/redact/tokenize/obfuscate API |
| `guard::obfuscate` | Realistic fake data generators (CC, email, SSN, IBAN, etc.) |
| `guard::tokenize` | Reversible token vault with RBAC |
| `guard::presets` | Preset category bundles |
| `allowlist` | Suppress known false positives by text or pattern |
| `profiles` | Named masking profiles (PCI_PRODUCTION, HIPAA_STRICT, etc.) |
| `plugins` | Custom validator and post-processor registry |

### Data processing

| Module | Description |
|---|---|
| `pipeline` | Concurrent file processing pipeline |
| `batch` | CSV, JSON/JSONL parallel batch scanning |
| `streaming` | Streaming scanner with chunk buffering |
| `extractors` | Text extraction from 20+ formats (DOCX, XLSX, PDF, EML, MBOX, ICS, WARC, ZIP, RAR, 7z, Parquet, SQLite, etc.) |
| `cache` | Thread-safe LRU scan cache with TTL eviction |
| `config` | Config file loading (pyproject.toml, .dlpscanrc) |

### Advanced detection

| Module | Description |
|---|---|
| `edm` | Exact Data Match — HMAC-SHA256 known-value detection |
| `lsh` | Locality-Sensitive Hashing — fuzzy document similarity |
| `entropy` | Shannon entropy analysis, recursive archive extraction |

### Enterprise

| Module | Description |
|---|---|
| `policy` | TOML-based policy engine with rule matching |
| `compliance` | PCI-DSS/HIPAA/SOC2/GDPR compliance reports (JSON/text/HTML) |
| `audit` | Audit event logging with pluggable handlers |
| `metrics` | Scan metrics collection with callbacks |
| `siem` | SIEM adapters (Splunk HEC, Elasticsearch, Syslog, Datadog) |
| `webhooks` | Webhook notifications with retry and exponential backoff |
| `api` | HTTP API server with rate limiting and auth |

## Architecture

```
Input text
  │
  ├── normalize (ASCII fast-path, or NFKC + homoglyph + zero-width)
  │
  ├── Aho-Corasick keyword pre-scan (single O(n) pass)
  │   └── Builds ContextHitIndex: (category, sub_category) → positions
  │
  ├── Pattern prefilter
  │   ├── 108 always-run patterns (specificity ≥ 0.85 or critical)
  │   └── 452 context-gated patterns (only run if keywords present)
  │
  ├── Parallel regex matching (Rayon par_iter over active patterns)
  │   ├── Luhn validation (credit cards)
  │   ├── Context proximity check (AC hit index lookup)
  │   └── Confidence scoring (base + context boost)
  │
  ├── Deduplication (overlapping span resolution)
  │
  └── Action: Flag | Redact | Obfuscate | Tokenize | Reject
```

## CLI

```bash
# Scan a file
dlpscan file.txt

# Scan with JSON output
dlpscan -f json file.txt

# Scan a directory
dlpscan ./src/

# Pipe input
echo "SSN: 123-45-6789" | dlpscan
```

## Development

```bash
# Run tests
cargo test

# Run benchmarks
cargo run --release --bin benchmark

# Build with all features
cargo build --release --features full

# Check formatting and lints
cargo fmt --check
cargo clippy
```

## License

MIT
