# dlpscan-rs

High-performance DLP scanner written in Rust. Detects, redacts, and protects
sensitive data with exceptional throughput.

**560 patterns** across **126 categories** — full parity with the Python version.
**19,000+ lines** of Rust across 38 modules. **360 tests** passing.

## Performance

| Scenario (1MB) | Full (560 patterns) | Baseline (108 patterns) |
|---|---:|---:|
| Clean text | 66.8 MB/s | 66.4 MB/s |
| Mixed content | 20.4 MB/s | 20.8 MB/s |
| Dense sensitive data | 20.9 MB/s | 21.5 MB/s |
| Keyword-heavy text | 34.4 MB/s | 38.9 MB/s |

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for full results including optimization
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
| `barcode` | No | QR code and barcode decoding via `rxing` + `image` |
| `bin-data` | No | BIN database (374k card prefixes) for issuer/country enrichment |
| `tui` | No | Interactive TUI menu and live dashboard |
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

### QR code and barcode scanning

With the `barcode` feature, image files are automatically decoded for
embedded barcodes and QR codes. Any decoded text is scanned for sensitive
data patterns -- catching credit cards, SSNs, API keys, or other data
hidden in 2D codes.

```bash
cargo build --release --features barcode
```

**Supported formats:**

| Type | Formats |
|---|---|
| 2D codes | QR Code, Data Matrix, Aztec, PDF417 |
| 1D codes | UPC-A, UPC-E, EAN-8, EAN-13, Code 39, Code 128, ITF, Codabar |
| Image types | PNG, JPG, JPEG, GIF, BMP, TIFF, WebP |

**Usage:**

```rust
use dlpscan::extractors::extract_text;

// Automatically decodes barcodes from images when barcode feature is enabled
let result = extract_text("boarding-pass.png")?;
// result.text contains decoded barcode content, scanned for patterns
// result.metadata["barcode_count"] = "3"
// result.metadata["formats"] = "QR Code, PDF417"
```

```bash
# CLI: scan an image for barcodes containing sensitive data
dlpscan boarding-pass.png

# Scan a directory of scanned documents
dlpscan --features barcode ./scanned-forms/
```

**Safety limits:** 20 MB max image size, 100 barcodes per image,
4 KB max decoded text per barcode.

### File type controls

Configure which file types the pipeline blocks or skips:

```toml
# .dlpscanrc or pyproject.toml [tool.dlpscan]
blocked_extensions = ["der", "p12", "pfx", "p7m", "p8", "ppk", "jks"]
block_unreadable = true  # also blocks .exe, .dll, .gpg, .kdbx, etc.
```

Crypto certificates are blocked by default. See the [Security](#file-type-controls-1)
section for details on symlink resolution and double-extension protection.

### BIN lookup (credit card enrichment)

With the `bin-data` feature, credit card findings are enriched with
issuing bank metadata from a database of 374,788 Bank Identification
Numbers:

```bash
cargo build --release --features bin-data
```

```json
{
  "category": "Credit Card Numbers",
  "sub_category": "Visa",
  "confidence": 0.95,
  "metadata": {
    "bin_brand": "Visa",
    "bin_card_type": "Credit",
    "bin_country": "US"
  }
}
```

Known BINs receive a +0.05 confidence boost. The lookup runs only on
numbers that already passed regex + Luhn validation (O(log n) binary
search, effectively free).

### Entropy-based secret detection

Detect high-entropy secrets that don't match any regex pattern (random API
keys, custom tokens, encoded credentials):

```toml
# .dlpscanrc
entropy_scan = "gated"        # only near keywords like "secret", "key", "token"
# entropy_scan = "assignment" # only in KEY=VALUE patterns
# entropy_scan = "all"        # flag all high-entropy tokens
```

The pipeline also reports file-level entropy for detecting encrypted or
compressed content:

```json
{
  "file_path": "data.bin",
  "file_entropy": 7.92,
  "entropy_classification": "likely_encrypted"
}
```

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

## Patterns and Keywords

dlpscan detects sensitive data using a two-layer system:

1. **560 regex patterns** match data formats (credit cards, SSNs, IBANs, API keys, etc.)
2. **5,000+ context keywords** (English, French, Spanish, German, Italian, Portuguese) confirm detections via Aho-Corasick proximity matching

Each pattern has a **specificity score** (0.0-1.0) indicating base confidence.
When a context keyword appears within the configured distance of a match,
confidence is boosted by +0.20. Some low-specificity patterns are **context-required** --
they are suppressed entirely without a nearby keyword.

Keywords include translations in 6 languages for multilingual document
scanning: English, French/French-Canadian, Spanish, German, Italian,
and Portuguese (e.g., `credit card` / `carte de crédit` / `tarjeta de
crédito` / `Kreditkarte` / `carta di credito` / `cartão de crédito`).

| Category | Patterns | Examples |
|---|---:|---|
| Credit Card Numbers | 7 | Visa, MasterCard, Amex, Discover, JCB, Diners Club, UnionPay |
| National IDs (50+ regions) | 250+ | SSN, SIN, Aadhaar, NIN, DNI, CPF, CURP, and more |
| Secrets & Credentials | 20+ | JWT, AWS keys, GitHub tokens, Slack tokens, Stripe keys |
| Banking & Financial | 30+ | IBAN, SWIFT/BIC, ABA routing, wire transfers, securities |
| Healthcare | 10+ | DEA numbers, ICD-10 codes, NDC codes, insurance IDs |
| Contact Information | 5 | Email, phone (E.164/US/UK), IPv4/IPv6, MAC address |
| Cryptocurrency | 7 | Bitcoin, Ethereum, Litecoin, Monero, Ripple, Bitcoin Cash |
| Classification Labels | 40+ | Top Secret, Confidential, HIPAA, GDPR, Attorney-Client |
| Device & Biometric | 7 | IMEI, ICCID, IDFA, biometric hashes |
| Geolocation & Postal | 8 | GPS coordinates, geohash, ZIP+4, UK postcode |

Full reference:
- **[docs/PATTERNS.md](docs/PATTERNS.md)** -- All 560 patterns with regex, specificity scores, and context-required flags
- **[docs/KEYWORDS.md](docs/KEYWORDS.md)** -- All 3,100+ context keywords (English + French) with proximity distances

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
| `extractors` | Text extraction from 20+ formats (DOCX, XLSX, PDF, EML, MBOX, ICS, WARC, ZIP, RAR, 7z, CAB, DAT, Parquet, SQLite, QR/barcode, etc.) |
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
| `policy` | TOML-based policy engine with priority-based rule matching |
| `compliance` | PCI-DSS/HIPAA/SOC2/GDPR compliance reports (JSON/text/HTML) |
| `audit` | Audit event logging with HMAC signing and pluggable handlers |
| `metrics` | Scan metrics collection with callbacks |
| `siem` | SIEM adapters (Splunk HEC, Elasticsearch, Syslog, Datadog) with retry |
| `webhooks` | Webhook notifications with retry and exponential backoff |
| `api` | HTTP API server with per-key rate limiting, RBAC, and key rotation |

## Architecture

```
Input text
  │
  ├── Filename context (pipeline: prepend filename words as keywords)
  │
  ├── normalize (ASCII fast-path, or NFKC + homoglyph + zero-width)
  │
  ├── Aho-Corasick keyword pre-scan (single O(n) pass)
  │   └── Builds ContextHitIndex: (category, sub_category) → positions
  │
  ├── Pattern prefilter
  │   ├── 107 always-run patterns (specificity ≥ 0.85 or critical)
  │   └── 453 context-gated patterns (only run if keywords present)
  │
  ├── Parallel regex matching (Rayon par_iter over active patterns)
  │   ├── Structural validation (Luhn, SWIFT, CUSIP, SEDOL, TFN, SSN)
  │   ├── Context proximity check (AC hit index lookup)
  │   └── Confidence scoring (base + context boost)
  │
  ├── Deduplication (overlapping span resolution)
  │
  ├── Entropy scan (optional: gated, assignment, or all mode)
  │
  ├── EDM scan (optional: exact match against registered values)
  │
  ├── LSH query (optional: document similarity check)
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

## Security

dlpscan is hardened for enterprise deployment in regulated environments
(PCI-DSS, HIPAA, SOC 2, GDPR).

### API security

- **API key hashed at rest** -- SHA-256 hash stored in memory, never plaintext
- **Constant-time key verification** -- prevents timing side-channel attacks
- **Per-API-key rate limiting** -- falls back to per-IP when no key provided
- **RBAC enforcement** -- server-side role resolution from authenticated keys;
  Admin, Analyst, Operator, Viewer roles with least-privilege defaults
- **Runtime key rotation** -- `POST /v1/admin/rotate-key` (Admin-only)
  with minimum complexity enforcement
- **Content-Length pre-check** -- rejects oversized bodies before reading
- **Authenticated metrics** -- `/metrics` requires auth when API key is set

### Audit

- **HMAC-SHA256 event signing** -- tamper-evident audit trail with
  `sign(key)` / `verify(key)` on every event
- **Structured fields** -- `source_ip`, `request_id`, `outcome` for
  correlation and forensics
- **Rotating file handler** -- size-based rotation with configurable
  `max_bytes` and `max_files`; symlink attack protection; `0o600` permissions
- **Rate limit rejections audited** -- every throttled request logged

### Network

- **SSRF protection** -- blocks private IPs, IPv6-mapped IPv4
  (`::ffff:127.0.0.1`), DNS round-robin bypass (validates ALL resolved
  addresses), CRLF header injection
- **HTTPS enforced for SIEM** -- HTTP-based adapters (Splunk, Elasticsearch,
  Webhook) require HTTPS by default
- **SIEM retry with backoff** -- 3 retries at 200/400/800ms for transient
  failures

### Detection hardening

- **Unicode evasion defense** -- Cyrillic, Greek, fullwidth homoglyphs;
  zero-width character stripping; leet-speak decoding; NFKC normalization
- **Byte-preserving redaction** -- replacement preserves exact span byte
  length, preventing offset corruption in multi-byte text
- **Constant-time EDM matching** -- Exact Data Match uses XOR comparison
  across all registered hashes (no timing leak)
- **Structural validators** -- SWIFT/BIC (ISO 3166 country code + 400-word
  false-positive filter), CUSIP/SEDOL (check digit), Australia TFN (weighted
  checksum), SSN (area code rules), Luhn (min 12 digits, same-digit rejection)
- **BIN database** -- 374k card prefixes validate issuing bank, card type,
  and country; enriches findings with metadata (feature: `bin-data`)
- **Context gating** -- low-specificity patterns (Account Balance, Ticker
  Symbol, CUSIP, SEDOL, Teller ID) require nearby keywords to fire
- **Corrupted file recovery** -- corrupted ZIP/DOCX falls back to raw byte
  scanning; binary files with unknown extensions get printable string extraction
- **Entropy analysis** -- detects high-entropy secrets that evade regex
  patterns (random API keys, custom tokens) with three gating modes:
  context-gated, assignment-gated, or ungated
- **File-level entropy** -- pipeline classifies files as normal, compressed,
  or encrypted based on Shannon entropy (7.9+ bits/byte = likely encrypted)
- **Token vault TTL** -- vaults expire after 1 hour with panic-safe background
  eviction; detokenize rejects expired vaults
- **Tenant-isolated caching** -- `key_with_namespace()` prevents cross-tenant
  cache poisoning
- **EDM safety limits** -- warns when hash count exceeds 50k to prevent
  O(N*M) performance degradation in constant-time scan

### File type controls

- **Blocked extensions** -- cryptographic material (`.der`, `.p12`, `.pfx`,
  `.p7m`, `.p8`, `.ppk`, `.jks`, `.gpg`, `.pgp`) blocked by default
- **Block unreadable** -- opt-in blocking of executables, compiled objects,
  encrypted containers, and media files
- **Double-extension bypass prevention** -- `secret.der.txt` correctly blocked
  by checking ALL dot-separated segments
- **Symlink resolution** -- paths canonicalized before extension check to
  prevent `safe.txt` -> `secret.der` bypass

See [docs/enterprise/security.md](docs/enterprise/security.md) for full details.

## Documentation

| Document | Description |
|---|---|
| [docs/getting-started/concepts.md](docs/getting-started/concepts.md) | Core concepts: specificity, context keywords, validators, actions |
| [docs/getting-started/quickstart.md](docs/getting-started/quickstart.md) | Quick start guide with CLI and Rust API examples |
| [docs/getting-started/configuration.md](docs/getting-started/configuration.md) | Full configuration reference (config file, env vars, CLI, policies) |
| [docs/getting-started/installation.md](docs/getting-started/installation.md) | Build from source, Docker, feature flags |
| [docs/PATTERNS.md](docs/PATTERNS.md) | All 560 patterns with regex, specificity, and context flags |
| [docs/KEYWORDS.md](docs/KEYWORDS.md) | All 5,000+ context keywords (6 languages) with proximity distances |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Performance analysis and optimization journey |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [docs/api-reference.md](docs/api-reference.md) | Comprehensive API documentation |
| [docs/evasion_techniques.md](docs/evasion_techniques.md) | Known evasion attacks |
| [docs/evasion_defenses.md](docs/evasion_defenses.md) | Countermeasures implemented |
| [docs/baselines/](docs/baselines/) | Control baselines (PCI, PII, PHI, secrets, financial, confidential) |
| [docs/deployment/](docs/deployment/) | Docker, CI/CD, pre-commit hooks |
| [docs/enterprise/](docs/enterprise/) | API server, audit, compliance, SIEM, RBAC, security hardening |

## License

MIT
