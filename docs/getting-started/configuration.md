# Configuration

dlpscan can be configured via config files, environment variables, CLI
flags, or the interactive setup wizard.

---

## Quick Setup

The fastest way to create a config file:

```bash
dlpscan init
```

This launches an interactive wizard that guides you through:
- Minimum confidence threshold
- Context keyword requirements
- File type blocking
- Preset selection
- Output format

The wizard saves a `.dlpscanrc` JSON file in the current directory.

---

## Config File Reference

dlpscan looks for configuration in this order:
1. `.dlpscanrc` (JSON)
2. `dlpscan.json` (JSON)
3. `pyproject.toml` under `[tool.dlpscan]` (TOML)

### JSON Schema (editor validation)

A JSON Schema is available at [`docs/dlpscanrc.schema.json`](../dlpscanrc.schema.json).
Modern editors (VS Code, Neovim, IntelliJ) will auto-complete and
validate fields when you add a schema reference:

```json
{
  "$schema": "https://raw.githubusercontent.com/oxide11/dlpscan-rs/main/docs/dlpscanrc.schema.json",
  "min_confidence": 0.5,
  "entropy_scan": "gated"
}
```

For VS Code, you can also add a global association in `settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": [".dlpscanrc", "dlpscan.json"],
      "url": "https://raw.githubusercontent.com/oxide11/dlpscan-rs/main/docs/dlpscanrc.schema.json"
    }
  ]
}
```

### Full `.dlpscanrc` example

```json
{
  "min_confidence": 0.5,
  "require_context": false,
  "deduplicate": true,
  "max_matches": 50000,
  "format": "text",
  "categories": null,
  "allowlist": [],
  "ignore_patterns": [],
  "ignore_paths": [],
  "context_backend": "regex",
  "blocked_extensions": [
    "der", "p12", "pfx", "p7b", "p7c", "p7m", "p7s",
    "p8", "ppk", "jks", "keystore", "bks",
    "smime", "gpg", "pgp", "asc", "sst", "stl", "spc", "pvk"
  ],
  "block_unreadable": false,
  "entropy_scan": "off"
}
```

### Field reference

| Field | Type | Default | Description |
|---|---|---|---|
| `min_confidence` | float | `0.0` | Ignore findings with confidence below this threshold (0.0-1.0). See [Concepts: Specificity](concepts.md#specificity) |
| `require_context` | bool | `false` | Only report findings that have a context keyword nearby |
| `deduplicate` | bool | `true` | Remove overlapping findings, keeping the highest-confidence one |
| `max_matches` | int | `50000` | Maximum findings per scan (prevents memory exhaustion) |
| `format` | string | `"text"` | Default output format: `text`, `json`, `csv`, `sarif` |
| `categories` | list/null | `null` | Scan only these categories (null = all). See `dlpscan categories` |
| `allowlist` | list | `[]` | Exact text values to suppress (e.g., test credit card numbers) |
| `ignore_patterns` | list | `[]` | Regex patterns for text to ignore |
| `ignore_paths` | list | `[]` | File path globs to skip in directory scans |
| `context_backend` | string | `"regex"` | Context matching engine (usually leave as default) |
| `blocked_extensions` | list | *(crypto certs)* | File extensions to block in pipeline scans |
| `block_unreadable` | bool | `false` | Also block executables, encrypted containers, and media files |
| `entropy_scan` | string | `"off"` | Entropy-based secret detection: `"off"`, `"gated"`, `"assignment"`, or `"all"`. See [Concepts: Entropy](concepts.md#entropy-analysis) |

---

## Managing Configuration via CLI

### View current config

```bash
dlpscan config show
```

### Set individual values

```bash
dlpscan config set min_confidence 0.5
dlpscan config set require_context true
dlpscan config set block_unreadable true
dlpscan config set format json
dlpscan config set max_matches 10000
```

### Reset to defaults

```bash
dlpscan config reset
```

### Manage blocked file extensions

```bash
dlpscan config blocked          # List blocked extensions
dlpscan config block enc        # Block .enc files
dlpscan config unblock asc      # Unblock .asc files
```

---

## Environment Variables

Environment variables override config file values. This is useful for
Docker/Kubernetes deployments where config files aren't practical.

### Scanning

| Variable | Default | Description |
|---|---|---|
| `DLPSCAN_MIN_CONFIDENCE` | `0.0` | Minimum confidence threshold |
| `DLPSCAN_REQUIRE_CONTEXT` | `false` | Require context keywords |
| `DLPSCAN_FORMAT` | `text` | Output format |
| `DLPSCAN_CATEGORIES` | *(all)* | Comma-separated category names |
| `DLPSCAN_MAX_MATCHES` | `50000` | Max findings per scan |
| `DLPSCAN_DEDUPLICATE` | `true` | Remove overlapping matches |

### API Server

| Variable | Default | Description |
|---|---|---|
| `DLPSCAN_API_HOST` | `127.0.0.1` | Bind address |
| `DLPSCAN_API_PORT` | `8000` | Listen port |
| `DLPSCAN_API_KEY` | *(none)* | API key for authentication (hashed at rest) |
| `DLPSCAN_API_RATE_LIMIT` | `100` | Max requests per minute per client/key |
| `DLPSCAN_API_KEY_ROLES` | *(none)* | Key-to-role mapping (e.g., `key1:admin,key2:analyst`) |

### SIEM

| Variable | Description |
|---|---|
| `DLPSCAN_SIEM_TYPE` | `splunk`, `elasticsearch`, `syslog`, `webhook`, `datadog` |
| `DLPSCAN_SIEM_URL` | Endpoint URL (must be HTTPS in production) |
| `DLPSCAN_SIEM_TOKEN` | Authentication token |
| `DLPSCAN_SIEM_API_KEY` | API key (Elasticsearch, Datadog) |
| `DLPSCAN_SIEM_INDEX` | Index name (Elasticsearch) |
| `DLPSCAN_SIEM_HOST` | Host (Syslog) |
| `DLPSCAN_SIEM_PORT` | Port (Syslog) |
| `DLPSCAN_SIEM_FACILITY` | Facility (Syslog, default: local0) |
| `DLPSCAN_SIEM_PROTOCOL` | `udp` or `tcp` (Syslog) |
| `DLPSCAN_SIEM_SITE` | Site (Datadog, default: datadoghq.com) |

### TLS

| Variable | Description |
|---|---|
| `DLPSCAN_TLS_CERT` | Path to TLS certificate PEM file |
| `DLPSCAN_TLS_KEY` | Path to TLS private key PEM file |

---

## Precedence

Configuration is resolved in this order (highest priority first):

1. **CLI flags** (`--min-confidence`, `--require-context`, `--format`)
2. **Environment variables** (`DLPSCAN_MIN_CONFIDENCE`, etc.)
3. **Config file** (`.dlpscanrc`, `dlpscan.json`, or `pyproject.toml`)
4. **Built-in defaults**

---

## Policy Files (TOML)

For complex rule-based configurations, use TOML policy files. These
support per-category rule overrides with priority-based evaluation.

```toml
# policies/pci-production.toml
name = "pci-production"
version = "2"
description = "PCI-DSS production scanning policy"

[scan]
presets = ["pci_dss"]
action = "reject"
min_confidence = 0.7
require_context = true
redaction_char = "X"

[[rules]]
name = "block-credit-cards"
match_categories = ["Credit Card Numbers"]
action = "reject"
min_confidence = 0.8
priority = 10

[[rules]]
name = "redact-banking"
match_categories = ["Banking and Financial"]
action = "redact"
min_confidence = 0.6
priority = 5

[audit]
enabled = true
file = "/var/log/dlp-audit.jsonl"
```

Rules are evaluated in **priority order** (highest first). Among rules
with the same priority, definition order is preserved.

Load and use policies:

```rust
use dlpscan::policy::{load_policy, PolicyEngine};

let policy = load_policy("policies/pci-production.toml")?;
let engine = PolicyEngine::new(policy);
let result = engine.scan("Card: 4532015112830366")?;
```

---

## Feature Flags

dlpscan's capabilities depend on which features are compiled:

| Feature | Default | Description |
|---|---|---|
| `metrics` | Yes | Prometheus metrics via `/metrics` endpoint |
| `pdf` | No | PDF text extraction |
| `office` | No | DOCX/XLSX/PPTX extraction |
| `archives` | No | RAR and 7z archive extraction |
| `data-formats` | No | Parquet, SQLite extraction |
| `msg` | No | Outlook MSG extraction |
| `barcode` | No | QR code and barcode decoding from images |
| `bin-data` | No | BIN database (374k card prefixes) for issuer/country enrichment |
| `tui` | No | Interactive TUI menu and live dashboard |
| `async-support` | No | HTTP API server with async runtime |
| `tls` | No | HTTPS support for API server |
| `python` | No | Python bindings |
| `full` | No | All features |

```bash
# Build with specific features
cargo build --release --features "barcode,tui"

# Build with everything
cargo build --release --features full
```

---

## Recommended Configurations

### Development / Discovery

Find everything, tune later:

```json
{
  "min_confidence": 0.0,
  "require_context": false,
  "block_unreadable": false,
  "entropy_scan": "all"
}
```

### Production (Low False Positives)

Balanced detection with minimal noise:

```json
{
  "min_confidence": 0.5,
  "require_context": false,
  "deduplicate": true,
  "block_unreadable": true,
  "entropy_scan": "gated"
}
```

### High Security (Critical Only)

Maximum precision, only high-confidence findings:

```json
{
  "min_confidence": 0.8,
  "require_context": true,
  "block_unreadable": true,
  "entropy_scan": "assignment"
}
```

### PCI-DSS Compliance

Payment card focused:

```json
{
  "min_confidence": 0.6,
  "require_context": true,
  "categories": ["Credit Card Numbers", "Primary Account Numbers",
                  "Card Track Data", "Card Expiration Dates",
                  "Banking and Financial"]
}
```
