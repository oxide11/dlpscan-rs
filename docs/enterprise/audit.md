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
| `source_ip` | Source IP address of the request (API) |
| `request_id` | Unique request identifier for correlation |
| `outcome` | Result: `success`, `rejected`, `findings_detected`, `error` |
| `signature` | HMAC-SHA256 hex signature (when signing is enabled) |

## HMAC Event Signing

Audit events support HMAC-SHA256 signing for tamper detection:

```rust
use dlpscan::audit::AuditEvent;

let key = b"your-signing-key";

// Sign an event
let event = AuditEvent::new("SCAN")?
    .with_action("scan")
    .with_outcome("success")
    .sign(key)?;

// Verify later
assert!(event.verify(key));
```

The signature covers all fields except `signature` itself. Events that
fail JSON serialization cannot be signed (returns `Err` rather than
signing over empty data).

## Handlers

| Handler | Description |
|---------|-------------|
| `StderrAuditHandler` | JSON to stderr via logging |
| `FileAuditHandler(path)` | Append JSON-lines to file (0o600 permissions, symlink protection) |
| `RotatingFileAuditHandler` | Size-based log rotation with configurable `max_bytes` and `max_files` |
| `CallbackAuditHandler(fn)` | Custom callback function |
| `NullAuditHandler` | Discard (testing) |

## Rotating File Handler

```rust
use dlpscan::audit::{RotatingFileAuditHandler, AuditLogger, set_audit_logger};

let handler = RotatingFileAuditHandler::new(
    "/var/log/dlp-audit.jsonl",
    50 * 1024 * 1024,  // 50 MB per file
    10,                 // keep 10 rotated files
);

let logger = AuditLogger::new()
    .with_handler(Box::new(handler));
set_audit_logger(logger);
```

Rotation behavior:
- When the active log exceeds `max_bytes`, it is renamed to `.1`
- Existing rotated files shift up (`.1` -> `.2`, etc.)
- The oldest file beyond `max_files` is deleted
- Rotation failures are logged via `tracing::warn` (never silently dropped)
