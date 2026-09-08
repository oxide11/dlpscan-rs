//! Role-Based Access Control (RBAC) for the DLP scanner API.
//!
//! Roles: Admin, Analyst, Operator, Viewer (matching docs/enterprise/rbac.md).
//! Each role has a set of permitted operations.

use serde::{Deserialize, Serialize};

/// API roles ordered by privilege level (Admin highest).
///
/// `Ord` is derived and the variants are declared most-privileged first, so
/// `min()` across a set of groups picks the *highest* privilege. That is the
/// behaviour we want when a user belongs to several groups, and deriving it
/// means adding a role cannot silently break the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Analyst,
    /// Incident responder — investigates findings rather than operating the
    /// scanner. Can see and unmask sensitive values in the course of an
    /// investigation, but cannot change what the scanner detects or enforces.
    /// See `docs/wireframes/IR-vs-C2.md` for the operate/investigate split.
    Responder,
    Operator,
    Viewer,
}

impl Role {
    /// Map an identity-provider group name to a role.
    ///
    /// The names match the groups Authelia is configured with
    /// (`deploy/authelia/configuration.yml`). Unknown groups map to `None`
    /// rather than a default, so a typo in the IdP drops privilege instead of
    /// silently granting some.
    pub fn from_group(group: &str) -> Option<Self> {
        match group.trim().to_ascii_lowercase().as_str() {
            "admins" | "admin" => Some(Self::Admin),
            "analysts" | "analyst" => Some(Self::Analyst),
            "responders" | "responder" | "ir" => Some(Self::Responder),
            "operators" | "operator" => Some(Self::Operator),
            "viewers" | "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Highest-privilege role among a comma-separated group list.
    ///
    /// Returns `None` when the list carries no group we recognise — the caller
    /// must then decide, and every caller here fails closed.
    pub fn from_groups(groups: &str) -> Option<Self> {
        groups.split(',').filter_map(Self::from_group).min()
    }

    /// Short lowercase name, as it appears in audit rows and `GET /v1/me`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Responder => "responder",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    /// Every permission this role holds. Drives `GET /v1/me`, so the console
    /// can render only the affordances that will actually work.
    pub fn permissions(self) -> Vec<Permission> {
        Permission::ALL
            .iter()
            .copied()
            .filter(|p| role_has_permission(self, *p))
            .collect()
    }
}

/// API permissions for gating endpoint access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// POST /v1/scan
    Scan,
    /// POST /v1/batch/scan
    BatchScan,
    /// POST /v1/patterns
    ManagePatterns,
    /// Tokenize/detokenize operations
    Detokenize,
    /// Export vault mappings
    ExportVault,
    /// View health and metrics
    ViewStatus,
    /// Admin-only operations (key rotation, configuration changes)
    AdminAction,
    /// Read the matched value of a PII finding in the clear.
    ///
    /// Separate from `UnmaskPci` on purpose. Cardholder data carries its own
    /// regulatory basis under PCI-DSS and a narrower need-to-know than personal
    /// data generally, so a role can hold one without the other. Collapsing
    /// them into a single "unmask" permission is how the narrower control
    /// quietly becomes the wider one.
    UnmaskPii,
    /// Read the matched value of a PCI-DSS finding (PAN, track data) in the
    /// clear. Every use is audited server-side.
    UnmaskPci,
}

impl Permission {
    /// Every permission, so `Role::permissions()` cannot silently miss one.
    /// A new variant that is not added here is a compile-time nudge rather
    /// than a permission that never appears in `GET /v1/me`.
    pub const ALL: [Permission; 9] = [
        Permission::Scan,
        Permission::BatchScan,
        Permission::ManagePatterns,
        Permission::Detokenize,
        Permission::ExportVault,
        Permission::ViewStatus,
        Permission::AdminAction,
        Permission::UnmaskPii,
        Permission::UnmaskPci,
    ];

    /// Stable wire name, used in `GET /v1/me` and audit metadata.
    pub fn label(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::BatchScan => "batch_scan",
            Self::ManagePatterns => "manage_patterns",
            Self::Detokenize => "detokenize",
            Self::ExportVault => "export_vault",
            Self::ViewStatus => "view_status",
            Self::AdminAction => "admin_action",
            Self::UnmaskPii => "unmask_pii",
            Self::UnmaskPci => "unmask_pci",
        }
    }
}

/// Check whether a role has a given permission.
///
/// Permission matrix:
///
/// | Role | Permissions |
/// |---|---|
/// | Admin | all |
/// | Analyst | Scan, BatchScan, Detokenize, ViewStatus, UnmaskPii |
/// | Responder | Scan, ViewStatus, UnmaskPii, UnmaskPci |
/// | Operator | Scan, BatchScan, ViewStatus |
/// | Viewer | ViewStatus |
///
/// Two notes on the unmask columns, because they are the ones that will be
/// argued about:
///
/// **Analyst holds `UnmaskPii` but not `UnmaskPci`.** Tuning a pattern means
/// looking at what it matched, so an analyst who cannot see values cannot do
/// the job. Cardholder data is the exception: PCI-DSS wants that need-to-know
/// narrow, and pattern tuning can be done against a redacted PAN plus the
/// validator result.
///
/// **Responder holds both, but not `BatchScan` or `ManagePatterns`.** An
/// investigation genuinely needs the value in the clear — that is the whole
/// job — but a responder has no business changing what the scanner detects.
/// Investigate, don't operate.
///
/// Holding an unmask permission is not the same as data arriving unmasked.
/// Responses are redacted by default whatever the role; the permission is what
/// lets an explicit unmask request succeed, and every one of those is audited.
pub fn role_has_permission(role: Role, perm: Permission) -> bool {
    match role {
        Role::Admin => true,
        Role::Analyst => matches!(
            perm,
            Permission::Scan
                | Permission::BatchScan
                | Permission::Detokenize
                | Permission::ViewStatus
                | Permission::UnmaskPii
        ),
        Role::Responder => matches!(
            perm,
            Permission::Scan
                | Permission::ViewStatus
                | Permission::UnmaskPii
                | Permission::UnmaskPci
        ),
        Role::Operator => matches!(
            perm,
            Permission::Scan | Permission::BatchScan | Permission::ViewStatus
        ),
        Role::Viewer => matches!(perm, Permission::ViewStatus),
    }
}

/// Determine the role for a request based on the authenticated API key.
///
/// **Security:** The `X-Role` header is ONLY used as a hint when the server has
/// no key-to-role mapping configured. When `api_key_roles` is provided, the role
/// is derived server-side from the authenticated key — the client header is ignored.
///
/// If no API key auth is configured (open access), defaults to `Operator` (not Admin)
/// to limit damage from unauthenticated access.
pub fn resolve_role(
    _raw_request: &str,
    authenticated_key: Option<&str>,
    api_key_roles: &std::collections::HashMap<String, Role>,
) -> Role {
    // If we have a key-to-role mapping and an authenticated key, use it (server-authoritative)
    if let Some(key) = authenticated_key {
        if let Some(role) = api_key_roles.get(key) {
            return *role;
        }
    }

    // If no API key auth is configured at all, restrict to Operator (not Admin)
    if authenticated_key.is_none() {
        return Role::Operator;
    }

    // Fallback: authenticated but no role mapping — default to Viewer
    Role::Viewer
}

/// Extract the role from an HTTP request's `X-Role` header.
///
/// # Security Warning
///
/// **DEPRECATED:** Use `resolve_role()` instead for production. This function
/// trusts the client-supplied `X-Role` header, which can be trivially spoofed.
/// Restricted to `pub(crate)` so external library consumers cannot bypass
/// the key-derived RBAC path; retained for the in-crate regression tests
/// that still pin its parsing behaviour.
#[deprecated(
    since = "2.1.0",
    note = "Use resolve_role() which derives roles from authenticated API keys"
)]
// Kept for the in-crate parsing regression test. No production callers
// remain; this is dead code outside `cfg(test)`.
#[allow(dead_code)]
pub(crate) fn extract_role(raw_request: &str) -> Role {
    raw_request
        .lines()
        .find(|l| l.to_lowercase().starts_with("x-role:"))
        .and_then(|l| l.split_once(':').map(|x| x.1))
        .map(|v| v.trim().to_lowercase())
        .map(|v| match v.as_str() {
            "admin" => Role::Admin,
            "analyst" => Role::Analyst,
            "operator" => Role::Operator,
            _ => Role::Viewer,
        })
        .unwrap_or(Role::Viewer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_has_all_permissions() {
        assert!(role_has_permission(Role::Admin, Permission::Scan));
        assert!(role_has_permission(Role::Admin, Permission::ManagePatterns));
        assert!(role_has_permission(Role::Admin, Permission::ExportVault));
        assert!(role_has_permission(Role::Admin, Permission::Detokenize));
    }

    #[test]
    fn test_viewer_only_status() {
        assert!(role_has_permission(Role::Viewer, Permission::ViewStatus));
        assert!(!role_has_permission(Role::Viewer, Permission::Scan));
        assert!(!role_has_permission(
            Role::Viewer,
            Permission::ManagePatterns
        ));
    }

    #[test]
    fn test_operator_can_scan() {
        assert!(role_has_permission(Role::Operator, Permission::Scan));
        assert!(role_has_permission(Role::Operator, Permission::BatchScan));
        assert!(!role_has_permission(
            Role::Operator,
            Permission::ManagePatterns
        ));
        assert!(!role_has_permission(Role::Operator, Permission::Detokenize));
    }

    #[test]
    fn test_analyst_can_detokenize() {
        assert!(role_has_permission(Role::Analyst, Permission::Detokenize));
        assert!(role_has_permission(Role::Analyst, Permission::Scan));
        assert!(!role_has_permission(
            Role::Analyst,
            Permission::ManagePatterns
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn test_extract_role_from_header() {
        assert_eq!(
            extract_role("GET / HTTP/1.1\r\nX-Role: admin\r\n"),
            Role::Admin
        );
        assert_eq!(
            extract_role("GET / HTTP/1.1\r\nX-Role: Analyst\r\n"),
            Role::Analyst
        );
        assert_eq!(
            extract_role("GET / HTTP/1.1\r\nX-Role: OPERATOR\r\n"),
            Role::Operator
        );
        assert_eq!(extract_role("GET / HTTP/1.1\r\n"), Role::Viewer);
        assert_eq!(
            extract_role("GET / HTTP/1.1\r\nX-Role: unknown\r\n"),
            Role::Viewer
        );
    }

    #[test]
    fn test_admin_action_permission() {
        // Only Admin can perform AdminAction
        assert!(role_has_permission(Role::Admin, Permission::AdminAction));
        assert!(!role_has_permission(Role::Analyst, Permission::AdminAction));
        assert!(!role_has_permission(
            Role::Operator,
            Permission::AdminAction
        ));
        assert!(!role_has_permission(Role::Viewer, Permission::AdminAction));
    }
}
