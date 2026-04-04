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

Roles are extracted from the `X-Role` HTTP header on each request. The
`dlpscan::rbac` module defines the `Role` and `Permission` enums and
provides helper functions.

```rust
use dlpscan::rbac::{Role, Permission, role_has_permission, extract_role};

// Check if a role has a specific permission
assert!(role_has_permission(&Role::Admin, &Permission::ManagePatterns));
assert!(role_has_permission(&Role::Analyst, &Permission::Scan));
assert!(!role_has_permission(&Role::Viewer, &Permission::Scan));

// Extract a role from an HTTP header value
let role = extract_role(Some("analyst"));
assert_eq!(role, Role::Analyst);

// Unknown or missing header defaults to Viewer
let role = extract_role(None);
assert_eq!(role, Role::Viewer);
```

## API Usage

Include the `X-Role` header in your requests:

```bash
# Admin can manage patterns
curl -X POST http://localhost:8000/v1/patterns \
  -H "X-API-Key: your-key" \
  -H "X-Role: admin" \
  -H "Content-Type: application/json" \
  -d '{"name": "internal-id", "pattern": "PROJ-\\d+", "category": "Internal", "confidence": 0.9}'

# Analyst can scan and detokenize
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: your-key" \
  -H "X-Role: analyst" \
  -H "Content-Type: application/json" \
  -d '{"text": "Card: 4111111111111111", "action": "redact"}'

# Viewer can only check status
curl http://localhost:8000/health \
  -H "X-API-Key: your-key" \
  -H "X-Role: viewer"
```

Requests that require a permission the role does not have will receive a
`403 Forbidden` response.
