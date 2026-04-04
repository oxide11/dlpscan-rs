# Configuration

## Config File

dlpscan looks for configuration in `pyproject.toml` or `.dlpscanrc`:

```toml
# pyproject.toml
[tool.dlpscan]
min_confidence = 0.5
require_context = true
deduplicate = true
max_matches = 50000
format = "text"
allowlist = ["test@example.com", "4111111111111111"]
ignore_patterns = ["TEST-\\d+"]
ignore_paths = ["tests/", "fixtures/"]
```

## Environment Variables

Configure dlpscan entirely via environment variables:

```bash
# Scanning
export DLPSCAN_ACTION=redact
export DLPSCAN_PRESETS=pci_dss,ssn_sin
export DLPSCAN_MIN_CONFIDENCE=0.5
export DLPSCAN_REQUIRE_CONTEXT=true
export DLPSCAN_MODE=denylist

# Audit
export DLPSCAN_AUDIT_FILE=/var/log/dlp-audit.jsonl

# Rate limiting
export DLPSCAN_RATE_LIMIT=100
export DLPSCAN_RATE_WINDOW=60

# SIEM
export DLPSCAN_SIEM_TYPE=splunk
export DLPSCAN_SIEM_URL=https://splunk:8088
export DLPSCAN_SIEM_TOKEN=my-hec-token

# API server
export DLPSCAN_API_KEY=your-secret-key
export DLPSCAN_API_RATE_LIMIT=100
```

Apply in code:

```python
from dlpscan.env_config import configure_from_env

configure_from_env()  # One-call setup
```

Or get kwargs for InputGuard:

```python
from dlpscan.env_config import apply_env_to_guard_kwargs
from dlpscan import InputGuard

guard = InputGuard(**apply_env_to_guard_kwargs())
```

## YAML Policies

For complex configurations, use policy files:

```yaml
# policies/pci-production.yml
version: "1"
name: "pci-production"
description: "PCI-DSS production scanning policy"

scan:
  presets: [pci_dss]
  action: reject
  min_confidence: 0.7
  require_context: true

rules:
  - name: block-credit-cards
    match:
      categories: ["Credit Card Numbers"]
    action: reject
    min_confidence: 0.8

audit:
  enabled: true
  file: /var/log/dlp-audit.jsonl
```

See [Policy Engine](../guide/policy.md) for full documentation.
