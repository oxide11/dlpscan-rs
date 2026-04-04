# Environment Variables

Configure dlpscan entirely via `DLPSCAN_*` environment variables.

## Supported Variables

| Variable | Type | Description |
|----------|------|-------------|
| `DLPSCAN_ACTION` | string | Default action (reject/redact/flag/tokenize/obfuscate) |
| `DLPSCAN_PRESETS` | comma-list | Preset names |
| `DLPSCAN_CATEGORIES` | comma-list | Category names |
| `DLPSCAN_MODE` | string | denylist or allowlist |
| `DLPSCAN_MIN_CONFIDENCE` | float | Minimum confidence threshold |
| `DLPSCAN_REQUIRE_CONTEXT` | bool | Require context keywords |
| `DLPSCAN_REDACTION_CHAR` | string | Redaction character |
| `DLPSCAN_AUDIT_FILE` | path | Audit log file path |
| `DLPSCAN_RATE_LIMIT` | int | Max requests per window |
| `DLPSCAN_RATE_WINDOW` | int | Rate limit window (seconds) |
| `DLPSCAN_LOG_LEVEL` | string | Logging level |
| `DLPSCAN_API_KEY` | string | API server authentication key |
| `DLPSCAN_API_RATE_LIMIT` | int | API rate limit (req/min) |

## One-Call Setup

```python
from dlpscan.env_config import configure_from_env
configure_from_env()
```

## Guard Construction

```python
from dlpscan.env_config import apply_env_to_guard_kwargs
from dlpscan import InputGuard

guard = InputGuard(**apply_env_to_guard_kwargs())
```
