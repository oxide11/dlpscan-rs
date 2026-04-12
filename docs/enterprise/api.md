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
  "findings": [
    {
      "text": "411**********111",
      "category": "Credit Card Numbers",
      "sub_category": "Visa",
      "confidence": 0.95,
      "has_context": true,
      "span": [11, 30],
      "metadata": {
        "bin_brand": "Visa",
        "bin_card_type": "Credit",
        "bin_country": "US",
        "bin_issuer": "JPMORGAN CHASE BANK, N.A."
      }
    }
  ]
}
```

Findings for Credit Card Numbers include enriched BIN metadata when the
`bin-data` feature is compiled in. See [BIN Enrichment](#bin-enrichment)
below for details.

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

### `POST /v1/edm/register`

Register sensitive values for exact data matching. Requires **Admin** role.

**Request:**
```json
{
  "category": "ssn",
  "values": ["123-45-6789", "987-65-4321"]
}
```

**Response:**
```json
{"category": "ssn", "registered": 2, "total_hashes": 2}
```

### `GET /v1/edm/categories`

List registered EDM categories and hash counts. Requires **ViewStatus**.

### `POST /v1/lsh/register`

Register a document for similarity matching. Requires **Admin** role.

**Request:**
```json
{
  "doc_id": "earnings-q4",
  "text": "Quarterly earnings report...",
  "sensitivity": "confidential"
}
```

### `POST /v1/lsh/query`

Query for similar documents. Requires **Scan** permission.

**Request:**
```json
{
  "text": "This quarterly report contains...",
  "threshold": 0.8
}
```

**Response:**
```json
{
  "matches": [
    {"doc_id": "earnings-q4", "similarity": 0.92, "sensitivity": "confidential"}
  ]
}
```

### `GET /v1/lsh/documents`

List registered document count. Requires **ViewStatus**.

## BIN Enrichment

When dlpscan is compiled with the `bin-data` feature, credit card findings
are automatically enriched with metadata from a database of 374,788 Bank
Identification Numbers (the first 6 digits of a card identify the issuing
bank).

### Enriched metadata fields

| Field | Description | Example |
|---|---|---|
| `bin_brand` | Card network brand | `"Visa"`, `"MasterCard"`, `"American Express"` |
| `bin_card_type` | Card classification | `"Credit"`, `"Debit"`, `"Charge Card"` |
| `bin_country` | ISO 3166-1 alpha-2 country code | `"US"`, `"GB"`, `"DE"`, `"JP"` |
| `bin_issuer` | Name of the issuing bank | `"JPMORGAN CHASE BANK, N.A."` |

Known BINs receive a +0.05 confidence boost. Unknown BINs are still
accepted (they may be newly issued prefixes not yet in the database).

### Use cases for compliance

- **Country-of-issuance tracking** — determine which regulations apply
  (GDPR for EU, PCI-DSS, regional banking rules)
- **Sanctions screening** — flag cards from high-risk jurisdictions
- **Fraud indicators** — mismatched country between customer location
  and card issuer
- **Issuer risk assessment** — identify cards from distressed financial
  institutions
- **Audit enrichment** — compliance reports include the issuing bank
  name directly, no manual lookup needed

### Enabling BIN enrichment

```bash
cargo build --release --features bin-data
# or use the "full" feature bundle:
cargo build --release --features full
```

The `bin-data` feature embeds the 4.1 MB BIN database into the binary
at compile time. Without the feature, the `metadata` field on Credit
Card findings is simply empty (no runtime errors).

## EDM and LSH State

Load pre-registered EDM/LSH state at server startup via environment
variables:

```bash
export DLPSCAN_EDM_STATE=.dlpscan-edm.json
export DLPSCAN_LSH_STATE=.dlpscan-lsh.json
```

State files use 0o600 permissions on Unix and reject symlinks on write.

### Backup and Restore

Both EDM and LSH state files can be exported to a portable backup and
imported on another host. Export/import validate the file format (magic,
schema) before writing, so a corrupt or unrelated JSON file will be
rejected rather than silently overwriting state.

```bash
# Export the current state to a shareable backup file
dlpscan edm export edm-backup-2026-04.json --state .dlpscan-edm.json
dlpscan lsh export lsh-backup-2026-04.json --state .dlpscan-lsh.json

# Import a backup on another host (refuses to overwrite an existing
# state file unless --force is passed)
dlpscan edm import edm-backup-2026-04.json --state .dlpscan-edm.json --force
dlpscan lsh import lsh-backup-2026-04.json --state .dlpscan-lsh.json --force
```

Exported files preserve the HMAC salt (for EDM) and MinHash signatures
(for LSH) so matching behavior is identical on the destination host.
Backups respect the same 100 MB state file size limit enforced at load
time.

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
