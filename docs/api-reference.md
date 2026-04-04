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

Role-based access control:

```rust
use dlpscan::rbac::{Role, Permission, role_has_permission, extract_role};

let role = extract_role(Some("analyst"));
assert!(role_has_permission(&role, &Permission::Scan));
```

| Item | Description |
|------|-------------|
| `Role` | Enum: `Admin`, `Analyst`, `Operator`, `Viewer` |
| `Permission` | Enum: `Scan`, `BatchScan`, `ManagePatterns`, `Detokenize`, `ExportVault`, `ViewStatus` |
| `role_has_permission(role, perm)` | Check if a role has a permission |
| `extract_role(header_value)` | Parse role from `X-Role` header value |

## Enterprise Modules

| Module | Key Items |
|--------|-----------|
| `dlpscan::batch` | `BatchScanner` |
| `dlpscan::siem` | `SplunkHECAdapter`, `ElasticsearchAdapter`, `SyslogAdapter`, `WebhookSIEMAdapter`, `DatadogAdapter` |
| `dlpscan::compliance` | `ComplianceReporter` |
| `dlpscan::metrics` | Prometheus metrics (auto-recorded by API) |
| `dlpscan::rbac` | `Role`, `Permission`, `role_has_permission`, `extract_role` |
| `dlpscan::guard` | `TokenVault` |
