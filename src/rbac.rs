//! Role-Based Access Control (RBAC) for the DLP scanner API.
//!
//! Roles: Admin, Analyst, Operator, Viewer (matching docs/enterprise/rbac.md).
//! Each role has a set of permitted operations.

use serde::{Deserialize, Serialize};

/// API roles ordered by privilege level (Admin highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Analyst,
    Operator,
    Viewer,
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
}

/// Check whether a role has a given permission.
///
/// Permission matrix:
///   - Admin:    all permissions
///   - Analyst:  Scan, BatchScan, Detokenize, ViewStatus
///   - Operator: Scan, BatchScan, ViewStatus
///   - Viewer:   ViewStatus only
pub fn role_has_permission(role: Role, perm: Permission) -> bool {
    match role {
        Role::Admin => true,
        Role::Analyst => matches!(
            perm,
            Permission::Scan
                | Permission::BatchScan
                | Permission::Detokenize
                | Permission::ViewStatus
        ),
        Role::Operator => matches!(
            perm,
            Permission::Scan | Permission::BatchScan | Permission::ViewStatus
        ),
        Role::Viewer => matches!(perm, Permission::ViewStatus),
    }
}

/// Extract the role from an HTTP request's `X-Role` header.
/// Returns `Viewer` if the header is missing or unrecognized.
pub fn extract_role(raw_request: &str) -> Role {
    raw_request
        .lines()
        .find(|l| l.to_lowercase().starts_with("x-role:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
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
        assert!(!role_has_permission(Role::Viewer, Permission::ManagePatterns));
    }

    #[test]
    fn test_operator_can_scan() {
        assert!(role_has_permission(Role::Operator, Permission::Scan));
        assert!(role_has_permission(Role::Operator, Permission::BatchScan));
        assert!(!role_has_permission(Role::Operator, Permission::ManagePatterns));
        assert!(!role_has_permission(Role::Operator, Permission::Detokenize));
    }

    #[test]
    fn test_analyst_can_detokenize() {
        assert!(role_has_permission(Role::Analyst, Permission::Detokenize));
        assert!(role_has_permission(Role::Analyst, Permission::Scan));
        assert!(!role_has_permission(Role::Analyst, Permission::ManagePatterns));
    }

    #[test]
    fn test_extract_role_from_header() {
        assert_eq!(extract_role("GET / HTTP/1.1\r\nX-Role: admin\r\n"), Role::Admin);
        assert_eq!(extract_role("GET / HTTP/1.1\r\nX-Role: Analyst\r\n"), Role::Analyst);
        assert_eq!(extract_role("GET / HTTP/1.1\r\nX-Role: OPERATOR\r\n"), Role::Operator);
        assert_eq!(extract_role("GET / HTTP/1.1\r\n"), Role::Viewer);
        assert_eq!(extract_role("GET / HTTP/1.1\r\nX-Role: unknown\r\n"), Role::Viewer);
    }
}
