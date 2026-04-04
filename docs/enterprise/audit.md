# Audit Logging

Structured audit trail for every DLP operation.

## Setup

```python
from dlpscan.audit import (
    AuditLogger, FileAuditHandler, StderrAuditHandler,
    set_audit_logger, event_from_scan,
)

# File-based audit log (JSON-lines)
logger = AuditLogger(handlers=[
    FileAuditHandler("/var/log/dlp-audit.jsonl"),
    StderrAuditHandler(),  # Also log to stderr
])
set_audit_logger(logger)
```

## Recording Events

```python
from dlpscan import InputGuard, Preset, Action
from dlpscan.audit import event_from_scan, audit_event

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
result = guard.scan("Card: 4111111111111111")

event = event_from_scan(result, action="redact", source="api")
audit_event(event)
```

## Audit Event Fields

| Field | Description |
|-------|-------------|
| `event_type` | SCAN, TOKENIZE, DETOKENIZE, OBFUSCATE, REDACT, REJECT, FLAG |
| `timestamp` | ISO 8601 UTC |
| `user` | From env `USER` or explicit |
| `action` | The action taken |
| `categories_found` | Categories detected |
| `finding_count` | Number of findings |
| `is_clean` | Whether data was clean |
| `source` | Origin of the data |
| `duration_ms` | Operation time |

## Handlers

| Handler | Description |
|---------|-------------|
| `StderrAuditHandler` | JSON to stderr via logging |
| `FileAuditHandler(path)` | Append JSON-lines to file |
| `CallbackAuditHandler(fn)` | Custom callback function |
| `NullAuditHandler` | Discard (testing) |
