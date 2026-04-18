# Zero-Trust Security Model

<p align="center">
  <img src="../assets/logo.png" alt="Polygon Siphon" width="200">
</p>

Every Polygon Siphon pod treats every other pod — and every external
caller — as untrusted. There is no implicit trust based on network
location, pod identity, or service mesh membership.

## Principles

1. **Authenticate every request.** No unauthenticated access to any
   endpoint except health checks.
2. **Encrypt every transport.** TLS for all pod-to-pod and
   client-to-pod communication.
3. **Mutual authentication.** Pods verify each other via mTLS client
   certificates or pre-shared API keys.
4. **Least privilege.** Each pod exposes only the endpoints it needs.
   No shared admin backdoors.
5. **Defense in depth.** Rate limiting, request size limits, timeouts,
   and security headers are enforced even behind a service mesh.

## Authentication

### API key authentication

Every Siphon pod that exposes an HTTP endpoint requires a `Bearer`
token in the `Authorization` header:

```http
POST /scan HTTP/1.1
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Key handling:**
- API key is set via `SIPHON_API_KEY` environment variable at pod
  startup
- The key is immediately SHA-256 hashed; only the hash is retained
  in memory. The plaintext key is never stored
- Verification uses **constant-time comparison** (bitwise OR
  accumulation) to prevent timing side-channel attacks
- If `SIPHON_API_KEY` is not set, the pod logs a warning and runs in
  **dev mode** — this is only for local development

### Mutual TLS (mTLS)

For pod-to-pod communication (e.g., ingestion pod → detector pod),
mTLS provides two-way authentication:

```
Siphon-API ──────────────────── Siphon-ML
   │                                │
   ├── presents client cert         ├── presents server cert
   ├── verifies server cert         ├── verifies client cert
   └── encrypted channel            └── encrypted channel
```

**Configuration:**
- `SIPHON_TLS_CERT` — server certificate path (PEM)
- `SIPHON_TLS_KEY` — server private key path (PEM)
- `SIPHON_TLS_CA` — CA certificate for verifying peer certs (PEM)
- `SIPHON_TLS_CLIENT_CERT` — client certificate for outbound mTLS

When deploying in Kubernetes with a service mesh (Istio, Linkerd),
the mesh provides mTLS automatically. The pod-level TLS is a
**defense-in-depth layer** — even if the mesh is misconfigured, the
pod rejects unauthenticated connections.

## Transport encryption

### TLS configuration

Every pod supports TLS via rustls:

```bash
# Enable TLS
export SIPHON_TLS_CERT=/etc/siphon/tls/server.crt
export SIPHON_TLS_KEY=/etc/siphon/tls/server.key
siphon-api
```

When TLS is enabled:
- HSTS header is set (`max-age=31536000; includeSubDomains`)
- Plaintext HTTP is not available on the same port
- TLS 1.2 minimum (configurable)

When TLS is disabled:
- The pod logs a warning if bound to anything other than `127.0.0.1`
  or `::1`
- Intended for local dev or behind a TLS-terminating proxy

### Certificate rotation

Certificates can be rotated without downtime:
1. Replace the cert/key files on disk
2. Send SIGHUP to the pod (or restart)
3. New connections use the new cert; existing connections drain

## Rate limiting

Per-IP sliding-window rate limiter protects against brute force
and resource exhaustion:

- **Default:** 120 requests/minute/IP (configurable via
  `SIPHON_RATE_LIMIT`)
- **Sliding window:** 60-second window, per source IP
- **Periodic cleanup:** stale entries evicted every 5 minutes
- **Hard cap:** rate limiter map capped at 100k entries to prevent
  memory exhaustion from IP rotation attacks
- **Response:** `429 Too Many Requests` with `Retry-After: 60` header

## Request hardening

Every Siphon pod applies these protections:

| Control | Implementation |
|---------|---------------|
| **Body size limit** | 11 MB at HTTP layer (before handler) |
| **Payload validation** | Empty/oversized text rejected with 400/413 |
| **Security headers** | X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP: default-src 'none', Cache-Control: no-store |
| **CORS** | Denied by default; explicit allowlist via `SIPHON_CORS_ORIGINS` |
| **Error responses** | Generic messages; full errors logged server-side only |
| **Request ID** | UUID v4 per request for tracing; included in response |
| **Structured logging** | JSON logs with request_id, text_len, findings_count, duration_ms |
| **Default bind** | `127.0.0.1` (loopback); must explicitly set `SIPHON_BIND=0.0.0.0` |

## Pod-to-pod trust model

```
┌──────────────────────────────────────────────────┐
│                                                   │
│  Every arrow requires:                           │
│    1. TLS encryption (or service mesh mTLS)      │
│    2. API key or client certificate              │
│    3. Rate limiting at receiver                   │
│                                                   │
│  ┌────────┐    mTLS + API key    ┌────────────┐  │
│  │Siphon- │◄────────────────────►│ Siphon-ML  │  │
│  │  API   │                      └────────────┘  │
│  │        │    mTLS + API key    ┌────────────┐  │
│  │        │◄────────────────────►│ Siphon-    │  │
│  └────────┘                      │ Vision     │  │
│       ▲                          └────────────┘  │
│       │ TLS + API key                            │
│       │                                          │
│  ┌────┴───┐    mTLS + API key    ┌────────────┐  │
│  │Siphon- │◄────────────────────►│ Siphon-C2  │  │
│  │  C2    │                      │ (mgmt API) │  │
│  └────────┘                      └────────────┘  │
│                                                   │
└──────────────────────────────────────────────────┘
```

**No pod trusts any other pod implicitly.** Even Siphon-C2 (the
management plane) must authenticate to data-plane pods. This ensures:

- A compromised ML pod cannot exfiltrate data from the API pod
- A compromised C2 cannot bypass data-plane rate limits
- Lateral movement requires compromising credentials, not just
  network access

## Environment variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SIPHON_API_KEY` | (none) | API key for Bearer auth. Required in production. |
| `SIPHON_TLS_CERT` | (none) | Server TLS certificate (PEM) |
| `SIPHON_TLS_KEY` | (none) | Server TLS private key (PEM) |
| `SIPHON_TLS_CA` | (none) | CA cert for mTLS client verification (PEM) |
| `SIPHON_TLS_CLIENT_CERT` | (none) | Client cert for outbound mTLS (PEM) |
| `SIPHON_CORS_ORIGINS` | (none) | Comma-separated allowed CORS origins |
| `SIPHON_RATE_LIMIT` | 120 | Max requests per minute per IP |
| `SIPHON_REQUEST_TIMEOUT_SECS` | 30 | Request processing timeout |
| `SIPHON_BIND` | 127.0.0.1 | Listen address |
| `SIPHON_PORT` | 8080 | Listen port |
