# Configuration

## Config File

dlpscan looks for configuration in `dlpscan.yaml` or `dlpscan.yml`
(requires the `yaml-config` feature):

```yaml
# dlpscan.yaml
min_confidence: 0.5
require_context: true
deduplicate: true
max_matches: 50000
format: text
allowlist:
  - "test@example.com"
  - "4111111111111111"
ignore_patterns:
  - "TEST-\\d+"
ignore_paths:
  - "tests/"
  - "fixtures/"
```

## Environment Variables

Configure dlpscan entirely via environment variables:

```bash
# Scanning
export DLPSCAN_MIN_CONFIDENCE=0.5
export DLPSCAN_REQUIRE_CONTEXT=true
export DLPSCAN_FORMAT=text
export DLPSCAN_CATEGORIES=credit_cards,ssn
export DLPSCAN_MAX_MATCHES=50000
export DLPSCAN_DEDUPLICATE=true

# SIEM
export DLPSCAN_SIEM_TYPE=splunk
export DLPSCAN_SIEM_URL=https://splunk:8088
export DLPSCAN_SIEM_TOKEN=my-hec-token

# API server
export DLPSCAN_API_KEY=your-secret-key
export DLPSCAN_API_HOST=127.0.0.1
export DLPSCAN_API_PORT=8000
export DLPSCAN_API_RATE_LIMIT=100
export DLPSCAN_API_KEY_ROLES="key1:admin,key2:analyst,key3:viewer"

# TLS (optional)
export DLPSCAN_TLS_CERT=/path/to/cert.pem
export DLPSCAN_TLS_KEY=/path/to/key.pem
```

Environment variables override values from the config file.

## Precedence

Configuration is resolved in this order (highest priority first):

1. CLI flags
2. Environment variables
3. `dlpscan.yaml` / `dlpscan.yml` config file
4. Built-in defaults

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
