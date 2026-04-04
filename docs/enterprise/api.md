# REST API

dlpscan includes a FastAPI-based REST API server for language-agnostic integration.

## Quick Start

```bash
pip install dlpscan[api]
python -m dlpscan.api
# Server starts at http://localhost:8000
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

## Endpoints

### `GET /health`

Health check endpoint.

```json
{"status": "ok", "version": "1.4.0"}
```

### `POST /v1/scan`

Scan text for sensitive data.

**Request:**
```json
{
  "text": "My card is 4111-1111-1111-1111",
  "presets": ["pci_dss"],
  "action": "redact",
  "min_confidence": 0.5
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

### `POST /v1/tokenize`

Tokenize sensitive data (reversible).

**Response** includes a `vault_id` for later detokenization.

### `POST /v1/detokenize`

Reverse tokenization using a `vault_id`.

### `POST /v1/obfuscate`

Replace sensitive data with realistic fakes.

### `POST /v1/batch/scan`

Scan multiple texts in a single request.

## Rate Limiting

Configure via `DLPSCAN_API_RATE_LIMIT` (default: 100 requests/minute).

Returns `429 Too Many Requests` when exceeded.

## Docker Deployment

```dockerfile
FROM python:3.12-slim
RUN pip install dlpscan[api]
EXPOSE 8000
CMD ["python", "-m", "dlpscan.api"]
```
