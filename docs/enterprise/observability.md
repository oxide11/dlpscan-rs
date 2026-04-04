# Observability

Prometheus metrics for monitoring DLP operations.

## Built-in Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `dlpscan_requests_total` | Counter | Total HTTP requests (labels: `method`, `path`, `status`) |
| `dlpscan_request_duration_seconds` | Histogram | HTTP request latency |
| `dlpscan_scan_matches_total` | Counter | Total pattern matches across all scans |
| `dlpscan_active_connections` | Gauge | Currently active connections |
| `dlpscan_scans_total` | Counter | Total scans performed |
| `dlpscan_scan_duration_seconds` | Histogram | Scan processing latency |
| `dlpscan_scan_errors_total` | Counter | Scan errors |
| `dlpscan_rate_limit_rejections_total` | Counter | Rate limit rejections |

## Metrics Endpoint

Metrics are exposed in Prometheus text format at `GET /metrics` on the
API server:

```bash
curl http://localhost:8000/metrics
```

Example output:

```text
# HELP dlpscan_requests_total Total HTTP requests
# TYPE dlpscan_requests_total counter
dlpscan_requests_total{method="POST",path="/v1/scan",status="200"} 42

# HELP dlpscan_scans_total Total scans performed
# TYPE dlpscan_scans_total counter
dlpscan_scans_total 42

# HELP dlpscan_scan_duration_seconds Scan processing latency
# TYPE dlpscan_scan_duration_seconds histogram
dlpscan_scan_duration_seconds_bucket{le="0.01"} 30
dlpscan_scan_duration_seconds_bucket{le="0.1"} 40
dlpscan_scan_duration_seconds_bucket{le="+Inf"} 42
dlpscan_scan_duration_seconds_sum 1.234
dlpscan_scan_duration_seconds_count 42
```

## Using Metrics in Rust

The metrics are managed by the `dlpscan::metrics` module. They are
recorded automatically by the API server middleware.

```rust
use dlpscan::metrics;

// Metrics are auto-incremented by the API layer.
// Access the global registry for custom integrations:
let output = metrics::export_metrics();
println!("{}", output);
```

## Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: dlpscan
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:8000"]
    metrics_path: /metrics
```

## Grafana Dashboard

Useful PromQL queries:

```promql
# Request rate
rate(dlpscan_requests_total[5m])

# Scan latency p99
histogram_quantile(0.99, rate(dlpscan_scan_duration_seconds_bucket[5m]))

# Error rate
rate(dlpscan_scan_errors_total[5m])

# Active connections
dlpscan_active_connections
```
