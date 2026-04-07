# REST API

dlpscan includes a built-in REST API server for language-agnostic integration.

## Quick Start

```bash
# Set optional configuration
export DLPSCAN_API_HOST=127.0.0.1
export DLPSCAN_API_PORT=8000

# Run the server
dlpscan serve
# Server starts at http://127.0.0.1:8000
```

## Authentication

Set the `DLPSCAN_API_KEY` environment variable to enable API key authentication:

```bash
export DLPSCAN_API_KEY=your-secret-key
```

All requests must include the `X-API-Key` header:

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "Card: 4111111111111111", "action": "redact"}'
```

RBAC is controlled via server-side key-to-role mapping (not client headers).
See [RBAC](rbac.md) for the full permission matrix.

```bash
# Map API keys to roles (comma-separated key:role pairs)
export DLPSCAN_API_KEY_ROLES="admin-key-here:admin,analyst-key:analyst"
```

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `DLPSCAN_API_HOST` | `127.0.0.1` | Bind address |
| `DLPSCAN_API_PORT` | `8000` | Listen port |
| `DLPSCAN_API_KEY` | *(none)* | API key for authentication (hashed at rest) |
| `DLPSCAN_API_RATE_LIMIT` | `100` | Max requests per minute per client/key |
| `DLPSCAN_API_KEY_ROLES` | *(none)* | Key-to-role mapping (e.g., `key1:admin,key2:analyst`) |

## Endpoints

### `GET /health`

Health check endpoint. Returns minimal response without authentication,
or full details (uptime, pattern count, connections) when authenticated.

```json
// Unauthenticated
{"status": "ok"}

// Authenticated
{"status": "ok", "version": "2.0.0", "uptime_secs": 3600, "pattern_count": 560, "is_ready": true}
```

### `GET /health/live`

Liveness probe (for Kubernetes).

### `GET /health/ready`

Readiness probe (for Kubernetes).

### `GET /metrics`

Prometheus text format metrics. See [Observability](observability.md).

### `POST /v1/scan`

Scan text for sensitive data.

**Request (`ScanRequest`):**
```json
{
  "text": "My card is 4111-1111-1111-1111",
  "presets": ["pci_dss"],
  "categories": [],
  "action": "redact",
  "min_confidence": 0.5,
  "require_context": false
}
```

**Response:**
```json
{
  "is_clean": false,
  "finding_count": 1,
  "categories_found": ["Credit Card Numbers"],
  "redacted_text": "My card is XXXX-XXXX-XXXX-XXXX",
  "findings": [...]
}
```

### `POST /v1/batch/scan`

Scan multiple texts in a single request.

**Request (`BatchScanRequest`):**
```json
{
  "items": [
    {"text": "Card: 4111111111111111", "action": "redact"},
    {"text": "SSN: 123-45-6789", "action": "redact"}
  ]
}
```

Each item in `items` is a `ScanRequest`.

### `POST /v1/tokenize`

Tokenize sensitive data (reversible).

**Request (`TokenizeRequest`):**
```json
{
  "text": "My card is 4111-1111-1111-1111",
  "presets": ["pci_dss"],
  "categories": [],
  "min_confidence": 0.5
}
```

**Response** includes a `vault_id` for later detokenization.

### `POST /v1/detokenize`

Reverse tokenization using a `vault_id`. Vaults expire after 1 hour;
expired vaults return an error.

**Request (`DetokenizeRequest`):**
```json
{
  "text": "My card is TOK_abc123",
  "vault_id": "vault-uuid-here"
}
```

### `POST /v1/obfuscate`

Replace sensitive data with realistic fakes. Uses `ScanRequest` with `action` set to `"obfuscate"`.

### `POST /v1/patterns`

Register a custom detection pattern. Maximum 100 custom patterns;
pattern regex length limited to 2048 characters.

**Request (`PatternCreateRequest`):**
```json
{
  "name": "internal-id",
  "pattern": "PROJ-\\d{6}",
  "category": "Internal IDs",
  "confidence": 0.9
}
```

Requires **ManagePatterns** permission (Admin role).

### `GET /v1/patterns`

List all registered custom patterns. Requires **ManagePatterns** permission.

### `POST /v1/admin/rotate-key`

Rotate the API key at runtime. Requires **Admin** role.

**Request:**
```json
{
  "new_key": "new-secret-key-at-least-16-chars"
}
```

The old key is immediately invalidated. The rotation event is logged
to the audit trail.

## Rate Limiting

Rate limits are tracked per API key (when provided) or per source IP.
Configure via `DLPSCAN_API_RATE_LIMIT` (default: 100 requests/minute).

Returns `429 Too Many Requests` when exceeded. Every rejection is
logged to the audit trail with source IP and request path.

## Docker Deployment

```dockerfile
FROM rust:1.78 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --features api

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/dlpscan /usr/local/bin/
EXPOSE 8000
CMD ["dlpscan", "serve"]
```
