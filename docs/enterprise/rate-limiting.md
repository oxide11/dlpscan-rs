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

## Distributed Rate Limiting (Redis)

When dlpscan is deployed as multiple replicas behind a load balancer,
each instance tracks its own per-client counters in memory, so a client
round-robining across N replicas effectively gets `N × DLPSCAN_API_RATE_LIMIT`
requests per minute. To enforce a single, global limit across the
entire fleet, enable the optional Redis-backed limiter.

### Enabling

Build with the `redis-rate-limit` feature (included in `full`):

```bash
cargo build --release --features "async-support redis-rate-limit"
# or
cargo build --release --features full
```

Set the Redis URL via environment variable:

```bash
export DLPSCAN_RATE_LIMIT_REDIS_URL=redis://10.0.0.5:6379
# Or with auth:
export DLPSCAN_RATE_LIMIT_REDIS_URL=redis://user:password@10.0.0.5:6379/0
```

When set, the API consults Redis on every request before falling back
to the in-memory limiter.

### Algorithm

Fixed-window counter on a key of the form
`dlpscan:rl:<window-bucket>:<client-id>`:

1. `INCR` the counter atomically.
2. If the counter is now `1`, set `EXPIRE` to `1.5 × window` so the
   key self-cleans after the window passes.
3. If the counter exceeds `DLPSCAN_API_RATE_LIMIT`, the request is
   rejected with `429`.

The `1.5 ×` TTL absorbs minor clock skew between dlpscan replicas
and the Redis server.

### Failure handling

Any Redis error (connection failure, timeout, reply parsing) is
**logged at WARN** and the request falls through to the in-memory
limiter. A Redis outage cannot take the API offline — at worst the
limiter degrades to per-instance enforcement until Redis recovers.
The startup log includes a confirmation when distributed limiting
is active:

```
INFO dlpscan::api: Distributed rate limiting enabled (redis, 100/60s per client)
```

### Audit trail

Distributed rate limit rejections include `"backend": "redis"` in
the audit metadata, so you can distinguish them from local rejections
when reviewing the audit log.

### Sizing

A single Redis instance comfortably handles 100k+ ops/sec, far above
typical DLP API workloads. For HA, point dlpscan at a Redis Sentinel
or Redis Cluster endpoint via the connection URL — the underlying
`redis` crate supports both.
