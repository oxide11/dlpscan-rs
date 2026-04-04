# RBAC

Role-based access control for detokenization operations.

## Roles & Permissions

| Role | DETOKENIZE | EXPORT_VAULT | IMPORT_VAULT | CLEAR_VAULT |
|------|:---:|:---:|:---:|:---:|
| ADMIN | Yes | Yes | Yes | Yes |
| ANALYST | Yes | Yes | No | No |
| OPERATOR | Yes | No | No | No |
| VIEWER | No | No | No | No |

## Usage

```python
from dlpscan import TokenVault, Role, RBACPolicy, SecureTokenVault

vault = TokenVault()
policy = RBACPolicy(
    default_role=Role.VIEWER,
    role_overrides={"admin": Role.ADMIN, "analyst": Role.ANALYST},
)
secure = SecureTokenVault(vault=vault, policy=policy)

# Tokenize (no permission check)
token = secure.tokenize("4111111111111111", "Credit Card Numbers")

# Detokenize (requires DETOKENIZE permission)
original = secure.detokenize(token, user_id="admin")     # Works
# secure.detokenize(token, user_id="viewer")  # Raises PermissionDeniedError

# Dynamic role assignment
policy.set_role("new_user", Role.OPERATOR)
```
