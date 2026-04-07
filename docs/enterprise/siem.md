# SIEM Integration

Ship scan events to security information and event management platforms.

## Adapters

| Adapter | Platform |
|---------|----------|
| `SplunkHECAdapter` | Splunk HTTP Event Collector |
| `ElasticsearchAdapter` | Elasticsearch / OpenSearch |
| `SyslogAdapter` | Syslog (RFC 5424) |
| `WebhookSIEMAdapter` | Generic webhook (POST JSON) |
| `DatadogAdapter` | Datadog Logs API |

## Usage

```rust
use dlpscan::siem::SplunkHECAdapter;

let adapter = SplunkHECAdapter::new(
    "https://splunk.example.com:8088",
    "my-hec-token",
);
adapter.send(&serde_json::json!({
    "action": "redact",
    "categories": ["Credit Card Numbers"],
}));
```

## Environment Variables

All adapters can be configured via environment variables. Set
`DLPSCAN_SIEM_TYPE` to select the adapter, then set the corresponding
variables.

### Splunk

```bash
export DLPSCAN_SIEM_TYPE=splunk
export DLPSCAN_SIEM_URL=https://splunk:8088
export DLPSCAN_SIEM_TOKEN=my-hec-token
export DLPSCAN_SIEM_SOURCE=dlpscan       # optional
```

### Elasticsearch

```bash
export DLPSCAN_SIEM_TYPE=elasticsearch
export DLPSCAN_SIEM_URL=https://es:9200
export DLPSCAN_SIEM_INDEX=dlpscan-events
export DLPSCAN_SIEM_API_KEY=my-api-key
```

### Syslog

```bash
export DLPSCAN_SIEM_TYPE=syslog
export DLPSCAN_SIEM_HOST=syslog.example.com
export DLPSCAN_SIEM_PORT=514
export DLPSCAN_SIEM_FACILITY=local0    # optional
export DLPSCAN_SIEM_PROTOCOL=udp       # udp or tcp
```

### Datadog

```bash
export DLPSCAN_SIEM_TYPE=datadog
export DLPSCAN_SIEM_API_KEY=dd-api-key
export DLPSCAN_SIEM_SITE=datadoghq.com  # optional
```

### Webhook

```bash
export DLPSCAN_SIEM_TYPE=webhook
export DLPSCAN_SIEM_URL=https://hooks.example.com/dlp
```

## Creating an Adapter from Environment

```rust
use dlpscan::siem::create_siem_from_env;

let adapter = create_siem_from_env()
    .expect("DLPSCAN_SIEM_TYPE must be set");
adapter.send(&event);
```

All adapters are thread-safe and enrich events with timestamp, host, and source.

## HTTPS Enforcement

HTTP-based adapters (Splunk, Elasticsearch, Webhook) require HTTPS URLs
by default. This prevents audit events and tokens from being transmitted
in plaintext.

To permit HTTP in development/testing environments:

```bash
export DLPSCAN_SIEM_ALLOW_HTTP=1
```

!!! warning
    Never set `DLPSCAN_SIEM_ALLOW_HTTP=1` in production.

## Retry with Exponential Backoff

Use `send_with_retry()` for automatic retry on transient failures:

```rust
use dlpscan::siem::{send_with_retry, SplunkHECAdapter};

let adapter = SplunkHECAdapter::new("https://splunk:8088", "token");
send_with_retry(&adapter, &event)?;
```

Retry behavior:
- **3 retries** with exponential backoff (200ms, 400ms, 800ms)
- Each retry attempt is logged via `tracing::warn`
- Final failure logged via `tracing::error`
- Returns the last error after all retries are exhausted

## Syslog Security

The Syslog adapter sanitizes the hostname field to prevent header
injection attacks. Control characters and spaces are stripped from
the hostname before constructing the RFC 5424 message.
