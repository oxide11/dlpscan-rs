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

Key validation uses SHA-256 constant-time comparison to prevent timing
side-channel attacks.

!!! warning
    When `DLPSCAN_API_KEY` is not set, authentication is **disabled**.
    Always set this variable in production.

### RBAC

Access control is enforced via the `X-Role` header. See [RBAC](rbac.md)
for the full role/permission matrix.

### Request Size Limits

All API text fields enforce a maximum length of **1 MB** (1,000,000
characters) to prevent memory exhaustion from oversized payloads.

### Error Sanitization

API error responses never expose internal exception details. All
unhandled errors return a generic `"Internal scan error"` message while
full details are logged server-side.

### TLS Support

Enable TLS by setting the certificate and key paths:

```bash
export DLPSCAN_TLS_CERT=/path/to/cert.pem
export DLPSCAN_TLS_KEY=/path/to/key.pem
```

### Metrics Endpoint

The Prometheus metrics endpoint (`GET /metrics`) does not require
authentication by default. It should not be exposed to untrusted
networks without additional access controls.

## Token Vault

### HMAC-SHA256 Tokens

`TokenVault` uses HMAC-SHA256 with a cryptographically random secret to
generate deterministic tokens. This prevents token precomputation even
when no explicit secret is provided.

### Memory Safety

Token vault secrets are protected with `zeroize` and are securely erased
from memory on `Drop`, preventing secrets from lingering in freed memory.

```rust
use dlpscan::guard::TokenVault;

let vault = TokenVault::new("TOK_", "my-secret-key");
// Secret is zeroized when `vault` is dropped
```

## File System Security

### Restrictive File Permissions

Vault files and audit log files are created with `0o600` permissions
(owner read/write only) on Unix systems.

### Symlink Protection

File-based operations resolve paths and reject symbolic links to prevent
symlink race attacks where an attacker substitutes a symlink to read or
overwrite sensitive files.

### SSRF Protection

URL inputs are validated to prevent server-side request forgery. Private
and loopback addresses are rejected when processing external URLs.

## Input Validation

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

The built-in rate limiter uses a per-client sliding-window algorithm.
Configure via environment variable:

```bash
export DLPSCAN_API_RATE_LIMIT=100  # requests per minute per client
```

See [Rate Limiting](rate-limiting.md) for details.

## Deployment Recommendations

1. **Always set `DLPSCAN_API_KEY`** in production API deployments.
2. **Enable TLS** via `DLPSCAN_TLS_CERT` and `DLPSCAN_TLS_KEY`, or run
   behind a reverse proxy (nginx, Caddy) with TLS termination.
3. **Restrict metrics access** -- if exposing Prometheus metrics, use
   network policies or a sidecar proxy with authentication.
4. **Set file umask** -- ensure the process umask doesn't weaken the
   `0o600` file permissions.
5. **Monitor audit logs** -- use SIEM integration for compliance-grade
   audit trails.
