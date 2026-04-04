# SIEM Integration

Ship scan events to security information and event management platforms.

## Adapters

| Adapter | Platform |
|---------|----------|
| `SplunkHECAdapter` | Splunk HTTP Event Collector |
| `ElasticsearchAdapter` | Elasticsearch / OpenSearch |
| `SyslogAdapter` | Syslog (RFC 5424) |
| `WebhookAdapter` | Generic webhook (POST JSON) |
| `DatadogAdapter` | Datadog Logs API |

## Usage

```python
from dlpscan.siem import SplunkHECAdapter

adapter = SplunkHECAdapter(
    url="https://splunk.example.com:8088",
    token="my-hec-token",
)
adapter.send({"action": "redact", "categories": ["Credit Card Numbers"]})
```

## From Environment Variables

```bash
export DLPSCAN_SIEM_TYPE=splunk
export DLPSCAN_SIEM_URL=https://splunk:8088
export DLPSCAN_SIEM_TOKEN=my-token
```

```python
from dlpscan.siem import create_siem_from_env
adapter = create_siem_from_env()
```

## All adapters are thread-safe and enrich events with timestamp, host, and source.
