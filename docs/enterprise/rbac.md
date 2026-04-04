# RBAC

Role-based access control for API operations.

## Roles & Permissions

| Role | Scan | BatchScan | ManagePatterns | Detokenize | ExportVault | ViewStatus |
|------|:----:|:---------:|:--------------:|:----------:|:-----------:|:----------:|
| Admin | Yes | Yes | Yes | Yes | Yes | Yes |
| Analyst | Yes | Yes | No | Yes | No | Yes |
| Operator | Yes | Yes | No | No | No | Yes |
| Viewer | No | No | No | No | No | Yes |

## How It Works

Roles are resolved **server-side** from the authenticated API key using the
`DLPSCAN_API_KEY_ROLES` environment variable. This prevents clients from
escalating privileges by spoofing headers.

### Server-Side Role Mapping (Recommended)

Set `DLPSCAN_API_KEY_ROLES` to a comma-separated list of `key:role` pairs:

```bash
export DLPSCAN_API_KEY="admin-key-abc123"
export DLPSCAN_API_KEY_ROLES="admin-key-abc123:admin,analyst-key-def456:analyst,readonly-key-ghi789:viewer"
```

The server uses `resolve_role()` to derive the role from the authenticated key:

```rust
use dlpscan::rbac::{Role, Permission, role_has_permission, resolve_role};

// Server resolves role from the authenticated API key
let key_roles = std::collections::HashMap::from([
    ("admin-key".to_string(), Role::Admin),
    ("analyst-key".to_string(), Role::Analyst),
]);

let role = resolve_role(raw_request, Some("admin-key"), &key_roles);
assert_eq!(role, Role::Admin);

// Check permissions
assert!(role_has_permission(Role::Admin, Permission::ManagePatterns));
assert!(!role_has_permission(Role::Viewer, Permission::Scan));
```

### Default Behavior

- **With key mapping**: Role is derived from the matching key. Unknown keys default to `Viewer`.
- **Without key mapping**: Authenticated users default to `Viewer`. Unauthenticated access (no API key configured) defaults to `Operator`.

## API Usage

```bash
# Admin key can manage patterns
curl -X POST http://localhost:8000/v1/patterns \
  -H "X-API-Key: admin-key-abc123" \
  -H "Content-Type: application/json" \
  -d '{"name": "internal-id", "pattern": "PROJ-\\d+", "category": "Internal", "confidence": 0.9}'

# Analyst key can scan and detokenize
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: analyst-key-def456" \
  -H "Content-Type: application/json" \
  -d '{"text": "Card: 4111111111111111", "action": "redact"}'

# Read-only key can only check status
curl http://localhost:8000/health \
  -H "X-API-Key: readonly-key-ghi789"
```

Requests that require a permission the role does not have receive a
`403 Forbidden` response.

## Endpoint Permissions

| Endpoint | Required Permission |
|---|---|
| `POST /v1/scan` | Scan |
| `POST /v1/batch/scan` | BatchScan |
| `POST /v1/tokenize` | Scan |
| `POST /v1/detokenize` | Detokenize |
| `POST /v1/obfuscate` | Scan |
| `POST /v1/patterns` | ManagePatterns |
| `GET /health*`, `GET /metrics` | None (exempt) |
