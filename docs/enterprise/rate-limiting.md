# Rate Limiting

Per-client sliding-window rate limiter built into the API server.

## Overview

The rate limiter is implemented directly in the API layer (`src/api.rs`)
using a `HashMap<String, Vec<Instant>>` to track request timestamps per
client. It uses a sliding-window algorithm: timestamps older than the
window are pruned on each check.

## Configuration

Set the `DLPSCAN_API_RATE_LIMIT` environment variable to configure the
maximum number of requests per minute per client (default: 100):

```bash
export DLPSCAN_API_RATE_LIMIT=100  # 100 requests per minute per client
```

## Behavior

When a client exceeds the rate limit, the API returns:

- HTTP status `429 Too Many Requests`
- The `dlpscan_rate_limit_rejections_total` Prometheus metric is incremented

The client is identified by IP address (or the `X-Forwarded-For` header
when behind a reverse proxy).

## Example

```bash
# Normal request
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "test data"}'

# After exceeding the limit
# HTTP/1.1 429 Too Many Requests
# {"error": "Rate limit exceeded"}
```

## Monitoring

Track rate limit rejections via the Prometheus metrics endpoint:

```bash
curl http://localhost:8000/metrics | grep rate_limit
# dlpscan_rate_limit_rejections_total 5
```
