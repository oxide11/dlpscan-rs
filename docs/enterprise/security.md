# Security Hardening

dlpscan includes built-in security controls to protect against common
attack vectors. This page documents the measures in place and how to
configure them.

## API Security

### Authentication

The REST API supports API key authentication via the `X-API-Key` header.
Set the `DLPSCAN_API_KEY` environment variable to enable it:

```bash
export DLPSCAN_API_KEY="your-secret-key-here"
```

Key validation uses constant-time comparison (`hmac.compare_digest`) to
prevent timing side-channel attacks.

!!! warning
    When `DLPSCAN_API_KEY` is not set, authentication is **disabled**.
    Always set this variable in production.

### Request Size Limits

All API text fields enforce a maximum length of **1 MB** (1,000,000
characters) to prevent memory exhaustion from oversized payloads. The
rate limiter also enforces a per-request payload byte limit (default
10 MB).

### Error Sanitization

API error responses never expose internal exception details. All
unhandled errors return a generic `"Internal scan error"` message while
full details are logged server-side.

### Metrics Endpoint

The Prometheus metrics exporter binds to `127.0.0.1` (localhost only) by
default. It does not require authentication, so it should not be exposed
to untrusted networks.

## Cryptography

### Key Derivation (PBKDF2)

Vault encryption keys are derived using **PBKDF2-HMAC-SHA256** with:

- **600,000 iterations** (OWASP 2024 recommendation)
- **Random 16-byte salt** generated via `os.urandom()`

When using `EncryptedVault` or `FileBackend` with `encryption_key`, the
derived key is never stored — only the ciphertext and per-record nonces.

### Token Generation

`TokenVault` uses HMAC-SHA256 with a cryptographically random secret
(via `secrets.token_bytes()`) to generate deterministic tokens. This
prevents token precomputation even when no explicit secret is provided.

### AES-256-GCM Encryption

Vault encryption uses AES-256-GCM with unique 12-byte nonces per record,
providing both confidentiality and integrity.

## File System Security

### Restrictive File Permissions

Vault files and audit log files are created with `0o600` permissions
(owner read/write only) using `os.open()` with explicit mode flags.

### Symlink Protection

File-based backends (`FileBackend`, `FileAuditHandler`) resolve paths
and reject symbolic links to prevent symlink race attacks where an
attacker substitutes a symlink to read or overwrite sensitive files.

## Input Validation

### SQL Injection Prevention

`BatchScanner.scan_database()` only accepts `SELECT` queries. Any
query that does not start with `SELECT` is rejected before execution.
Results are fetched in bounded batches of 1,000 rows.

### OCR Config Allowlist

Tesseract configuration flags are validated against a strict allowlist
(`--oem`, `--psm`, `--dpi` only). Flags like `--tessdata-dir` that
accept file paths are blocked to prevent path traversal.

### HTML ReDoS Protection

HTML tag stripping in email extraction uses bounded regex patterns
(max 1,000 characters per match) to prevent catastrophic backtracking.

### JSON Recursion Limit

The streaming JSON string extractor enforces a maximum recursion depth
of 64 levels to prevent stack overflow from deeply nested payloads.

## Rate Limiting

The built-in rate limiter uses an O(1) time-window algorithm backed by
`collections.deque` for efficient timestamp management.

```python
from dlpscan.rate_limit import RateLimiter

limiter = RateLimiter(
    max_requests=100,       # per window
    window_seconds=60,      # 1 minute
    max_payload_bytes=10 * 1024 * 1024,  # 10 MB
)
```

## Deployment Recommendations

1. **Always set `DLPSCAN_API_KEY`** in production API deployments.
2. **Use `FileBackend` with `encryption_key`** — plaintext storage is
   the default when no key is provided.
3. **Run behind a reverse proxy** (nginx, Caddy) with TLS termination.
4. **Restrict metrics access** — if exposing Prometheus metrics, use
   network policies or a sidecar proxy with authentication.
5. **Set file umask** — ensure the process umask doesn't weaken the
   `0o600` file permissions.
6. **Monitor audit logs** — use `FileAuditHandler` or SIEM integration
   for compliance-grade audit trails.
