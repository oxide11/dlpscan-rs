# Observability

Prometheus and OpenTelemetry metrics for monitoring DLP operations.

## Built-in Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `dlpscan_scans_total` | Counter | Total scans performed |
| `dlpscan_findings_total` | Counter | Findings detected (by category) |
| `dlpscan_scan_duration_seconds` | Histogram | Scan latency |
| `dlpscan_scan_errors_total` | Counter | Scan errors |
| `dlpscan_active_vaults` | Gauge | Active token vaults |
| `dlpscan_tokens_created_total` | Counter | Tokens created |
| `dlpscan_rate_limit_rejections_total` | Counter | Rate limit rejections |

## Prometheus Exporter

```python
from dlpscan.observability import PrometheusExporter

exporter = PrometheusExporter()
exporter.start(port=9090)
# Metrics available at http://localhost:9090/metrics
```

## Recording Scan Metrics

```python
from dlpscan.observability import record_scan
import time

start = time.monotonic()
result = guard.scan(text)
duration = time.monotonic() - start

record_scan(result, duration)
```

## Prometheus Text Format

```python
from dlpscan.observability import MetricsRegistry

registry = MetricsRegistry()
print(registry.to_prometheus())
```

## OpenTelemetry

```python
from dlpscan.observability import setup_opentelemetry
setup_opentelemetry(service_name="dlpscan")
```

Requires the `opentelemetry-api` and `opentelemetry-sdk` packages.
