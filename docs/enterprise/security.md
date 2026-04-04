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

Access control is enforced via server-side API key-to-role mapping using
`DLPSCAN_API_KEY_ROLES`. See [RBAC](rbac.md) for the full
role/permission matrix. Roles are derived from the authenticated key,
not from client-supplied headers (preventing privilege escalation).

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

The Prometheus metrics endpoint (`GET /metrics`) does not require
authentication by default. It should not be exposed to untrusted
networks without additional access controls.

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

### DNS Rebinding Protection

Outbound HTTP connections resolve the hostname and validate the resolved
IP **at connection time** (not just at registration). This prevents
TOCTOU attacks where DNS resolves to a public IP at registration but a
private IP when the connection is made.

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

The built-in rate limiter uses a per-client sliding-window algorithm.
Configure via environment variable:

```bash
export DLPSCAN_API_RATE_LIMIT=100  # requests per minute per client
```

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

## Deployment Recommendations

1. **Always set `DLPSCAN_API_KEY`** and **`DLPSCAN_API_KEY_ROLES`** in production.
2. **Enable TLS** via `DLPSCAN_TLS_CERT` and `DLPSCAN_TLS_KEY`, or run
   behind a reverse proxy with TLS termination.
3. **Restrict metrics access** — use network policies or auth proxy.
4. **Set file umask** — ensure the process umask doesn't weaken `0o600`.
5. **Monitor audit logs** — use SIEM integration for compliance-grade trails.
6. **Run `cargo deny check`** in CI to catch dependency vulnerabilities.
