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

**Key storage:** The API key is immediately hashed with SHA-256 on startup.
Only the hash is kept in memory -- the plaintext key is never stored.

**Constant-time verification:** Key comparison uses a bitwise XOR
accumulator over SHA-256 digests, preventing timing side-channel attacks.

!!! warning
    When `DLPSCAN_API_KEY` is not set, authentication is **disabled**.
    Always set this variable in production.

### Runtime Key Rotation

API keys can be rotated at runtime without restarting the server:

```bash
curl -X POST http://localhost:8000/v1/admin/rotate-key \
  -H "X-API-Key: current-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"new_key": "new-secret-key-at-least-16-chars"}'
```

Requirements:
- Caller must have **Admin** role
- New key must be at least 16 non-whitespace characters
- Purely alphanumeric keys must be at least 24 characters
- Every rotation is logged to the audit trail (key identity is hashed, never logged in plaintext)

Programmatic rotation is also available:

```rust
use dlpscan::api::{rotate_api_key, set_api_key_role, revoke_api_key_role};

rotate_api_key(&app_state, "new-secret-key");
set_api_key_role(&app_state, "analyst-key", Role::Analyst);
revoke_api_key_role(&app_state, "old-key");
```

### RBAC

Access control is enforced via server-side API key-to-role mapping using
`DLPSCAN_API_KEY_ROLES`. See [RBAC](rbac.md) for the full
role/permission matrix. Roles are derived from the authenticated key,
not from client-supplied headers (preventing privilege escalation).

Permission enforcement by endpoint:

| Endpoint | Permission Required |
|---|---|
| `POST /v1/scan` | Scan |
| `POST /v1/batch/scan` | BatchScan |
| `POST /v1/tokenize` | Scan |
| `POST /v1/detokenize` | Detokenize |
| `POST /v1/obfuscate` | Scan |
| `POST /v1/patterns` | ManagePatterns |
| `GET /v1/patterns` | ManagePatterns |
| `GET /metrics` | ViewStatus |
| `POST /v1/admin/rotate-key` | AdminAction |
| `GET /health` | None (minimal response without auth) |

### HTTP Security Headers

All API responses include defense-in-depth security headers:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `Content-Security-Policy` | `default-src 'none'` | Blocks resource loading |
| `Cache-Control` | `no-store` | Prevents caching of sensitive scan results |
| `X-XSS-Protection` | `0` | Disables legacy XSS filter (CSP preferred) |

### Request Timeouts

- **Socket read timeout**: 10 seconds (prevents slowloris attacks)
- **Handler timeout**: 60 seconds (prevents runaway scans from holding connections)
- Requests exceeding the timeout receive no response (connection dropped)

### HTTP Request Smuggling Protection

The server rejects requests that could enable HTTP desync attacks:

- **Transfer-Encoding**: Rejected with 400 (chunked encoding not supported)
- **Duplicate Content-Length**: Rejected with 400 (prevents CL.CL attacks)

### Request Size Limits

The API read buffer matches the declared maximum body size (10 MB).
Content-Length is validated before processing.

### Error Sanitization

API error responses never expose internal details. All errors return
generic messages while full details are logged server-side.

### TLS Support

Enable TLS by setting the certificate and key paths:

```bash
export DLPSCAN_TLS_CERT=/path/to/cert.pem
export DLPSCAN_TLS_KEY=/path/to/key.pem
```

Requires the `tls` feature flag. Falls back to HTTP when not configured.

### Metrics Endpoint

The Prometheus metrics endpoint (`GET /metrics`) requires authentication
when `DLPSCAN_API_KEY` is set (ViewStatus permission). When no API key
is configured, metrics are accessible without authentication.

### Request Pre-validation

Incoming requests are validated before the body is fully read:

- **Content-Length pre-check** -- if the `Content-Length` header exceeds
  10 MB, the request is rejected immediately (HTTP 413) without
  allocating memory for the body
- **Post-read size check** -- the body is also validated after reading
  to protect against chunked transfers without Content-Length

## Token Vault

### HMAC-SHA256 Tokens

`TokenVault` uses HMAC-SHA256 with a cryptographically random secret to
generate deterministic tokens. Max 100,000 entries per vault to prevent
memory exhaustion.

### Memory Safety

Token vault secrets and sensitive values are protected with the `zeroize`
crate, which provides compiler-barrier-guaranteed memory zeroing on `Drop`.
Both the HMAC secret key and all plaintext values in the forward/reverse
maps are zeroized before deallocation.

### Vault Limits

- **MAX_VAULT_ENTRIES**: 100,000 per vault (overflow returns hash-only token)
- **MAX_VAULTS**: 1,000 concurrent vaults
- **VAULT_TTL**: 1 hour (expired vaults evicted on each request)

## Network Security

### SSRF Protection

All outbound HTTP connections (webhooks, SIEM adapters) are protected by
a unified SSRF validation layer (`http_util::is_private_ip`):

| Blocked Range | Description |
|---|---|
| `127.0.0.0/8` | Loopback |
| `10.0.0.0/8` | Private (RFC 1918) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.168.0.0/16` | Private (RFC 1918) |
| `169.254.0.0/16` | Link-local |
| `100.64.0.0/10` | CGNAT (RFC 6598) |
| `198.18.0.0/15` | Benchmarking (RFC 2544) |
| `192.0.0.0/24` | IETF protocol assignments |
| `::1` | IPv6 loopback |
| `fc00::/7` | IPv6 ULA |
| `fe80::/10` | IPv6 link-local |
| `::ffff:x.x.x.x` | IPv4-mapped IPv6 (extracted and validated as IPv4) |
| `::x.x.x.x` | IPv4-compatible IPv6 (extracted and validated as IPv4) |

### DNS Rebinding Protection

Outbound HTTP connections resolve the hostname and validate **all**
resolved IP addresses before connecting. If any resolved address is
private or reserved, the entire connection is rejected. This prevents:

- **DNS round-robin bypass** -- where a safe IP is returned first
  followed by a private IP in the same DNS response
- **TOCTOU attacks** -- where DNS resolves to a public IP at
  registration but a private IP when the connection is made

### CRLF Header Injection Prevention

All HTTP header values in outbound requests are sanitized to strip `\r`
and `\n` characters, preventing header injection attacks.

## File System Security

### Restrictive File Permissions

Vault files and audit log files are created with `0o600` permissions
(owner read/write only) on Unix systems.

### Symlink Protection

The audit file handler rejects symbolic link paths before writing,
preventing symlink race attacks.

## Rate Limiting

The built-in rate limiter uses a sliding-window algorithm with per-client
tracking. When an API key is provided, rate limits are tracked per key
hash. When no key is provided, limits are tracked per source IP.

```bash
export DLPSCAN_API_RATE_LIMIT=100  # requests per minute per client
```

Rate limit rejections are automatically logged to the audit trail with
the source IP, request path, and reason.

See [Rate Limiting](rate-limiting.md) for details.

## Supply Chain Security

### cargo-deny

The project includes a `deny.toml` configuration for `cargo-deny`:

- **Advisories**: Known vulnerabilities are denied
- **Licenses**: Only OSI-approved licenses allowed (MIT, Apache-2.0, BSD, ISC)
- **Sources**: Unknown registries and git sources are denied

### .gitignore

The `.gitignore` is hardened to prevent accidental commits of secrets:
`.env`, `*.pem`, `*.key`, `*.crt`, `*.log`, `*.sqlite`, `secrets/`, `certs/`.

## Detection Hardening

### Unicode Evasion Defense

The normalization pipeline defends against Unicode-based evasion:

- **Homoglyph substitution** -- Cyrillic (А→A, е→e, Ё→E, У→Y, в→b),
  Greek (ε→e, σ→s, τ→t, ω→w), fullwidth digits/letters mapped to ASCII
- **Zero-width character stripping** -- U+200B-200F, U+202A-202E,
  U+2060-2064, U+FEFF, variation selectors
- **Leet-speak decoding** -- @→a, 3→e, 0→o, 1→l, 5→s, 7→t, etc.
- **HTML entity decoding** -- numeric and named entities
- **NFKC normalization** -- compatibility decomposition

### Byte-Preserving Redaction

The redaction engine preserves exact byte span length when replacing
sensitive data. This prevents offset corruption when processing multiple
findings in multi-byte UTF-8 text.

### Constant-Time EDM Matching

The Exact Data Match module uses bitwise XOR comparison that iterates
all registered hashes regardless of match status, preventing timing
side-channel attacks that could reveal which values are registered.

### Luhn Validation

Credit card Luhn checks enforce:
- Minimum 12 digits (rejects short sequences)
- Rejects all-same-digit sequences (e.g., `0000000000000000`)

## Deployment Recommendations

1. **Always set `DLPSCAN_API_KEY`** and **`DLPSCAN_API_KEY_ROLES`** in production.
2. **Enable TLS** via `DLPSCAN_TLS_CERT` and `DLPSCAN_TLS_KEY`, or run
   behind a reverse proxy with TLS termination.
3. **Set file umask** -- ensure the process umask doesn't weaken `0o600`.
4. **Use `RotatingFileAuditHandler`** -- configure size-based rotation
   with `max_bytes` and `max_files` to prevent disk exhaustion.
5. **Sign audit events** -- pass an HMAC key to `event.sign(key)` for
   tamper-evident audit trails.
6. **Monitor audit logs** -- use SIEM integration for compliance-grade trails.
7. **Run `cargo deny check`** in CI to catch dependency vulnerabilities.
8. **Rotate API keys periodically** -- use the `/v1/admin/rotate-key` endpoint.
9. **Use disk encryption** -- pair with OS-level encryption (LUKS, dm-crypt)
   for audit logs at rest.
