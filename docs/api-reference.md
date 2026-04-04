# API Reference

## Core Scanning

| Function | Description |
|----------|-------------|
| `enhanced_scan_text(text, ...)` | Scan text for sensitive data |
| `scan_file(path, ...)` | Scan a file |
| `scan_directory(path, ...)` | Scan a directory |
| `scan_stream(stream, ...)` | Scan a stream |
| `redact_sensitive_info(text, char)` | Redact matched text |
| `is_luhn_valid(number)` | Validate credit card checksum |
| `register_patterns(category, patterns)` | Register custom patterns |
| `unregister_patterns(category)` | Remove custom patterns |

## InputGuard

| Method | Description |
|--------|-------------|
| `scan(text)` | Scan and apply action |
| `check(text)` | Boolean clean check |
| `sanitize(text)` | Always redact |
| `tokenize(text)` | Reversible token replacement |
| `obfuscate(text)` | Irreversible fake data |
| `detokenize(text)` | Reverse tokenization |
| `protect(param=)` | Decorator for function args |

## Enterprise Modules

| Module | Key Classes/Functions |
|--------|----------------------|
| `dlpscan.audit` | `AuditLogger`, `AuditEvent`, `audit_event`, `event_from_scan` |
| `dlpscan.rate_limit` | `RateLimiter`, `rate_limited`, `RateLimitExceeded` |
| `dlpscan.siem` | `SplunkHECAdapter`, `ElasticsearchAdapter`, `SyslogAdapter`, `DatadogAdapter` |
| `dlpscan.compliance` | `ComplianceReporter`, `ComplianceReport` |
| `dlpscan.observability` | `MetricsRegistry`, `PrometheusExporter`, `record_scan` |
| `dlpscan.batch` | `BatchScanner`, `BatchResult`, `BatchReport` |
| `dlpscan.profiles` | `MaskingProfile`, `get_profile`, `ProfileRegistry` |
| `dlpscan.policy` | `PolicyEngine`, `load_policy`, `Policy` |
| `dlpscan.api` | `create_app()`, FastAPI REST server |
| `dlpscan.guard.rbac` | `RBACPolicy`, `SecureTokenVault`, `Role`, `Permission` |
| `dlpscan.guard.vault_backends` | `FileBackend`, `EncryptedVault`, `RedisBackend` |
| `dlpscan.env_config` | `configure_from_env`, `apply_env_to_guard_kwargs` |
