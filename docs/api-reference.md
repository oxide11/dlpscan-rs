# API Reference

## Core Scanning

| Function | Description |
|----------|-------------|
| `dlpscan::scan_text(text)` | Scan text for sensitive data, returns `Result<Vec<Match>>` |
| `dlpscan::scanner::scan_text_with_config(text, config)` | Scan with custom configuration |
| `dlpscan::is_luhn_valid(number)` | Validate credit card checksum |

## InputGuard

Builder-style API for configuring scan behavior:

```rust
use dlpscan::{InputGuard, Action, Preset};

let guard = InputGuard::new()
    .with_action(Action::Redact)
    .with_presets(vec![Preset::PciDss]);

let result = guard.scan("Card: 4111111111111111");
```

| Method | Description |
|--------|-------------|
| `InputGuard::new()` | Create with defaults |
| `.with_action(Action)` | Set the action (Redact, Reject, Tokenize, Obfuscate) |
| `.with_presets(Vec<Preset>)` | Set compliance presets |
| `.scan(text)` | Scan and apply action |
| `.check(text)` | Boolean clean check |
| `.sanitize(text)` | Always redact |
| `.tokenize(text)` | Reversible token replacement |
| `.obfuscate(text)` | Irreversible fake data |
| `.detokenize(text)` | Reverse tokenization |

## StreamScanner

Scan large or streaming inputs with configurable buffer and overlap:

```rust
use dlpscan::StreamScanner;

let scanner = StreamScanner::new(8192, 256); // buffer_size, overlap
```

## Pipeline

File scanning pipeline:

```rust
use dlpscan::Pipeline;

let pipeline = Pipeline::new();
```

## ComplianceReporter

Generate compliance reports:

```rust
use dlpscan::ComplianceReporter;

let reporter = ComplianceReporter::new("PCI-DSS Audit Report");
```

## BatchScanner

Batch scanning for CSV, JSON, and JSONL files:

```rust
use dlpscan::batch::BatchScanner;
use dlpscan::InputGuard;

let guard = InputGuard::new();
let scanner = BatchScanner::new(guard);
```

| Method | Description |
|--------|-------------|
| `BatchScanner::new(guard)` | Create with an `InputGuard` |
| `.scan_texts(items)` | Scan `&[(&str, &str)]` (source_id, text) pairs |
| `.scan_csv(path, columns, delimiter)` | Scan CSV file columns |
| `.scan_json(path, fields)` | Scan JSON file fields |
| `.scan_jsonl(path, fields)` | Scan JSONL file fields |
| `BatchScanner::summarize(results, duration)` | Generate summary report |

## TokenVault

Reversible tokenization with HMAC-SHA256:

```rust
use dlpscan::guard::TokenVault;

let vault = TokenVault::new("TOK_", "my-secret");
```

## RBAC

Role-based access control with server-side role resolution:

```rust
use dlpscan::rbac::{Role, Permission, role_has_permission, resolve_role};

// Server-side role resolution from API key mapping
let key_roles = std::collections::HashMap::from([
    ("admin-key".to_string(), Role::Admin),
]);
let role = resolve_role(request, Some("admin-key"), &key_roles);
assert!(role_has_permission(role, Permission::ManagePatterns));
```

| Item | Description |
|------|-------------|
| `Role` | Enum: `Admin`, `Analyst`, `Operator`, `Viewer` |
| `Permission` | Enum: `Scan`, `BatchScan`, `ManagePatterns`, `Detokenize`, `ExportVault`, `ViewStatus` |
| `role_has_permission(role, perm)` | Check if a role has a permission |
| `resolve_role(request, key, key_roles)` | Derive role from authenticated API key (recommended) |

## HTTP Utilities

Shared HTTP, SSRF, and timestamp utilities:

```rust
use dlpscan::http_util::{is_safe_url, is_private_ip, sanitize_url, iso8601_now};

assert!(is_safe_url("https://api.example.com/webhook"));
assert!(!is_safe_url("http://127.0.0.1/internal"));
```

| Item | Description |
|------|-------------|
| `parse_url(url)` | Parse URL into `ParsedUrl` struct |
| `is_safe_url(url)` | SSRF pre-resolution check |
| `is_private_ip(ip)` | Check if IP is in a private/reserved range |
| `safe_http_post(url, body, headers, timeout)` | HTTP POST with DNS rebinding + SSRF protection |
| `sanitize_url(url)` | Strip credentials from URL for logging |
| `iso8601_now()` | Current time as ISO 8601 UTC string |
| `epoch_to_iso8601(secs)` | Convert Unix epoch to ISO 8601 |

## Enterprise Modules

| Module | Key Items |
|--------|-----------|
| `dlpscan::batch` | `BatchScanner` |
| `dlpscan::siem` | `SplunkHECAdapter`, `ElasticsearchAdapter`, `SyslogAdapter`, `WebhookSIEMAdapter`, `DatadogAdapter` |
| `dlpscan::compliance` | `ComplianceReporter` |
| `dlpscan::metrics` | Prometheus metrics (auto-recorded by API) |
| `dlpscan::rbac` | `Role`, `Permission`, `role_has_permission`, `resolve_role` |
| `dlpscan::http_util` | `ParsedUrl`, `is_safe_url`, `is_private_ip`, `safe_http_post`, `sanitize_url` |
| `dlpscan::guard` | `TokenVault` |
