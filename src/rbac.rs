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
    /// Incident responder — investigates alerts rather than operating the
    /// scanner. Can see and unmask sensitive values in the course of an
    /// investigation, and can rule on them, but cannot change what the scanner
    /// detects or enforces. See `docs/wireframes/IR-vs-C2.md`.
    Responder,
    /// A responder who observes but does not act: reads the queue, may unmask
    /// for an investigation, cannot record a verdict or submit a scan.
    /// For consultants and shadowing analysts.
    ResponderReadOnly,
    /// Compliance auditor. Reads everything **masked, always** — no unmask
    /// permission at all, not even on request.
    ///
    /// This is the point of the role: an auditor verifies that process was
    /// followed, which needs the metadata (what matched, when, who ruled on
    /// it, whether the chain verifies) and never the personal data itself.
    /// Giving them unmask "just in case" would make the narrowest role in the
    /// system a full-disclosure one.
    Auditor,
    Operator,
    /// A detector reporting in: siphon-fs, siphon-icap, siphon-smtp. Holds
    /// `ReportTelemetry` and `ViewStatus` and nothing else — a sensor's key
    /// says what the sensor is, not what it may read. It does not scan
    /// through siphon-api (each embeds the engine) and it never reads alerts.
    Sensor,
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
            "admins" | "admin" | "administrator" | "administrators" => Some(Self::Admin),
            "analysts" | "analyst" => Some(Self::Analyst),
            "responders" | "responder" | "ir" => Some(Self::Responder),
            "responders-readonly" | "responder-readonly" | "ir-readonly" => {
                Some(Self::ResponderReadOnly)
            }
            "auditors" | "auditor" => Some(Self::Auditor),
            "operators" | "operator" => Some(Self::Operator),
            "sensors" | "sensor" => Some(Self::Sensor),
            "viewers" | "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Every role, so a table that must cover all of them cannot silently
    /// miss one — the `api_keys.role` CHECK constraint is asserted against
    /// this, and `GET /v1/roles` renders from it.
    pub const ALL: [Role; 8] = [
        Role::Admin,
        Role::Analyst,
        Role::Responder,
        Role::ResponderReadOnly,
        Role::Auditor,
        Role::Operator,
        Role::Sensor,
        Role::Viewer,
    ];

    /// The strict inverse of [`Role::label`]: the wire name, and only the
    /// wire name. `from_group` accepts IdP spellings (`admins`, `ir`); a
    /// stored role label is not an IdP group and gets no such latitude.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.label() == label)
    }

    /// One line for the console and `GET /v1/roles`.
    pub fn description(self) -> &'static str {
        match self {
            Self::Admin => "Full control. Every permission, unscoped.",
            Self::Analyst => "Tunes detection: scans, reads and rules on alerts, unmasks PII but not cardholder data.",
            Self::Responder => "Investigates: reads, rules on and fully unmasks alerts; submits scans; changes nothing about detection.",
            Self::ResponderReadOnly => "Investigates without acting: reads and unmasks, records no verdict, submits no scan.",
            Self::Auditor => "Verifies process: reads everything masked, always. No unmask permission exists for it to hold.",
            Self::Operator => "Runs scans and reads status. The application-owner key: sees only its own responses.",
            Self::Sensor => "A detector reporting in: heartbeat, mTLS state and counters. Reads nothing.",
            Self::Viewer => "Status only.",
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
            Self::ResponderReadOnly => "responder-readonly",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
            Self::Sensor => "sensor",
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
    /// Read the alert/detection stream at all — the queue, the history, the
    /// export. Values arrive redacted; this is permission to see *that*
    /// something matched, not *what* matched.
    ///
    /// Split out from `AdminAction`, which used to gate these endpoints back
    /// when they returned values in the clear. Masking is server-side now, so
    /// that gate was only keeping responders and auditors out of the surface
    /// built for them.
    ViewAlerts,
    /// Record a true/false-positive verdict on an alert. Separate from
    /// `ViewAlerts` because read-only roles exist precisely to hold one and
    /// not the other.
    ReviewAlerts,
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
    /// `POST /v1/sensors/heartbeat` — a detector reporting its identity,
    /// transport state and counters. Writes one row about itself and reads
    /// nothing, which is why `Sensor` can hold it and nothing else.
    ReportTelemetry,
}

impl Permission {
    /// Every permission, so `Role::permissions()` cannot silently miss one.
    /// A new variant that is not added here is a compile-time nudge rather
    /// than a permission that never appears in `GET /v1/me`.
    pub const ALL: [Permission; 12] = [
        Permission::Scan,
        Permission::BatchScan,
        Permission::ManagePatterns,
        Permission::Detokenize,
        Permission::ExportVault,
        Permission::ViewStatus,
        Permission::AdminAction,
        Permission::ViewAlerts,
        Permission::ReviewAlerts,
        Permission::UnmaskPii,
        Permission::UnmaskPci,
        Permission::ReportTelemetry,
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
            Self::ViewAlerts => "view_alerts",
            Self::ReviewAlerts => "review_alerts",
            Self::UnmaskPii => "unmask_pii",
            Self::UnmaskPci => "unmask_pci",
            Self::ReportTelemetry => "report_telemetry",
        }
    }
}

/// Check whether a role has a given permission.
///
/// | Role | Scan | Batch | Patterns | Admin | ViewAlerts | ReviewAlerts | PII | PCI |
/// |---|---|---|---|---|---|---|---|---|
/// | Admin             | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
/// | Analyst           | ✓ | ✓ | — | — | ✓ | ✓ | ✓ | — |
/// | Responder         | ✓ | — | — | — | ✓ | ✓ | ✓ | ✓ |
/// | ResponderReadOnly | — | — | — | — | ✓ | — | ✓ | ✓ |
/// | Auditor           | — | — | — | — | ✓ | — | — | — |
/// | Operator          | ✓ | ✓ | — | — | — | — | — | — |
/// | Sensor            | — | — | — | — | — | — | — | — |
/// | Viewer            | — | — | — | — | — | — | — | — |
///
/// Every role also holds `ViewStatus`; it is omitted above to keep the table
/// readable. `Sensor` additionally holds `ReportTelemetry`, which no human
/// role needs and which appears in no column because it is the whole of what
/// a sensor may do.
///
/// The columns that will be argued about:
///
/// **Analyst has PII but not PCI.** Tuning a pattern means looking at what it
/// matched, so an analyst who cannot see values cannot do the job. Cardholder
/// data is the exception: PCI-DSS wants that need-to-know narrow, and tuning
/// works from a redacted PAN plus the validator result.
///
/// **Responder has both, and no `ManagePatterns`.** An investigation needs the
/// value in the clear — that is the job — but a responder has no business
/// changing what the scanner detects. Investigate, don't operate.
///
/// **ResponderReadOnly keeps unmask but loses `ReviewAlerts` and `Scan`.**
/// The distinction is acting, not seeing: a consultant or a shadowing analyst
/// should be able to work a case fully and still not move it. Taking unmask
/// away instead would make the role useless for investigation while leaving
/// the ability to *change* the record, which is exactly backwards.
///
/// **Auditor has `ViewAlerts` and nothing else.** No unmask, on request or
/// otherwise. An auditor verifies that process was followed — what matched,
/// when, who ruled on it, whether the chain verifies — and none of that
/// requires the personal data. This is the only role for which redaction is
/// unconditional rather than a default, and that is the entire point of it.
///
/// **`Operator` cannot read alerts at all.** It runs scans; the results belong
/// to whoever investigates them.
///
/// Holding an unmask permission is not the same as data arriving unmasked.
/// Responses are redacted by default whatever the role; the permission is what
/// lets an explicit unmask request succeed, and every one of those is audited.
pub fn role_has_permission(role: Role, perm: Permission) -> bool {
    use Permission as P;
    match role {
        Role::Admin => true,
        Role::Analyst => matches!(
            perm,
            P::Scan
                | P::BatchScan
                | P::Detokenize
                | P::ViewStatus
                | P::ViewAlerts
                | P::ReviewAlerts
                | P::UnmaskPii
        ),
        Role::Responder => matches!(
            perm,
            P::Scan | P::ViewStatus | P::ViewAlerts | P::ReviewAlerts | P::UnmaskPii | P::UnmaskPci
        ),
        Role::ResponderReadOnly => matches!(
            perm,
            P::ViewStatus | P::ViewAlerts | P::UnmaskPii | P::UnmaskPci
        ),
        Role::Auditor => matches!(perm, P::ViewStatus | P::ViewAlerts),
        Role::Operator => matches!(perm, P::Scan | P::BatchScan | P::ViewStatus),
        Role::Sensor => matches!(perm, P::ViewStatus | P::ReportTelemetry),
        Role::Viewer => matches!(perm, P::ViewStatus),
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

    /// The whole point of the Auditor role: it can see that something
    /// matched and never what matched. Not "redacted by default" — no unmask
    /// permission exists for it to hold, so asking cannot help.
    #[test]
    fn auditor_can_never_unmask() {
        assert!(role_has_permission(Role::Auditor, Permission::ViewAlerts));
        assert!(!role_has_permission(Role::Auditor, Permission::UnmaskPii));
        assert!(!role_has_permission(Role::Auditor, Permission::UnmaskPci));
        assert!(!role_has_permission(
            Role::Auditor,
            Permission::ReviewAlerts
        ));
        assert!(!role_has_permission(Role::Auditor, Permission::Scan));
    }

    /// Read-only means cannot *act*, not cannot *see*. A consultant works the
    /// case fully and still cannot move it.
    #[test]
    fn responder_read_only_investigates_but_does_not_act() {
        for p in [
            Permission::ViewAlerts,
            Permission::UnmaskPii,
            Permission::UnmaskPci,
        ] {
            assert!(
                role_has_permission(Role::ResponderReadOnly, p),
                "read-only responder must still be able to investigate: {p:?}"
            );
        }
        assert!(!role_has_permission(
            Role::ResponderReadOnly,
            Permission::ReviewAlerts
        ));
        assert!(!role_has_permission(
            Role::ResponderReadOnly,
            Permission::Scan
        ));
        // The full responder differs by exactly the two acting permissions.
        assert!(role_has_permission(
            Role::Responder,
            Permission::ReviewAlerts
        ));
        assert!(role_has_permission(Role::Responder, Permission::Scan));
    }

    /// Running scans does not entitle you to the results.
    #[test]
    fn operator_cannot_read_alerts() {
        assert!(role_has_permission(Role::Operator, Permission::Scan));
        assert!(!role_has_permission(Role::Operator, Permission::ViewAlerts));
        assert!(!role_has_permission(Role::Viewer, Permission::ViewAlerts));
    }

    #[test]
    fn the_new_groups_map_and_rank() {
        assert_eq!(Role::from_group("auditors"), Some(Role::Auditor));
        assert_eq!(Role::from_group("Administrators"), Some(Role::Admin));
        assert_eq!(
            Role::from_group("ir-readonly"),
            Some(Role::ResponderReadOnly)
        );
        // A responder who is also an auditor is a responder.
        assert_eq!(
            Role::from_groups("auditors,responders"),
            Some(Role::Responder)
        );
        // Read-only outranks auditor: it can do everything auditor can, plus
        // unmask.
        assert_eq!(
            Role::from_groups("auditors,ir-readonly"),
            Some(Role::ResponderReadOnly)
        );
    }

    /// `GET /v1/me` is built from this, so a permission missing from
    /// `Permission::ALL` would be invisible to the console.
    #[test]
    fn every_permission_is_reachable_from_some_role() {
        for p in Permission::ALL {
            assert!(
                role_has_permission(Role::Admin, p),
                "Admin should hold every permission, missing {p:?}"
            );
            assert!(!p.label().is_empty());
        }
        assert_eq!(Role::Admin.permissions().len(), Permission::ALL.len());
        assert_eq!(Role::Viewer.permissions(), vec![Permission::ViewStatus]);
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn all_covers_every_variant() {
        // The match is the guard: adding a variant without listing it in
        // ALL fails to compile here rather than silently vanishing from
        // GET /v1/roles and the api_keys CHECK.
        for r in Role::ALL {
            let _ = match r {
                Role::Admin
                | Role::Analyst
                | Role::Responder
                | Role::ResponderReadOnly
                | Role::Auditor
                | Role::Operator
                | Role::Sensor
                | Role::Viewer => (),
            };
        }
        assert_eq!(Role::ALL.len(), 8);
    }

    #[test]
    fn labels_round_trip_and_are_strict() {
        for r in Role::ALL {
            assert_eq!(Role::from_label(r.label()), Some(r));
        }
        // IdP spellings are for from_group; a stored label gets no latitude.
        assert_eq!(Role::from_label("admins"), None);
        assert_eq!(Role::from_label("Admin"), None);
        assert_eq!(Role::from_label(""), None);
    }

    #[test]
    fn a_sensor_reports_and_does_nothing_else() {
        assert_eq!(
            Role::Sensor.permissions(),
            vec![Permission::ViewStatus, Permission::ReportTelemetry]
        );
        // And no human role reports telemetry — it is a machine's permission.
        for r in [
            Role::Analyst,
            Role::Responder,
            Role::ResponderReadOnly,
            Role::Auditor,
            Role::Operator,
            Role::Viewer,
        ] {
            assert!(
                !role_has_permission(r, Permission::ReportTelemetry),
                "{r:?}"
            );
        }
    }

    #[test]
    fn a_sensor_is_below_operator_and_above_viewer() {
        // min() across groups picks the highest privilege, so the declared
        // order is load-bearing.
        assert!(Role::Operator < Role::Sensor);
        assert!(Role::Sensor < Role::Viewer);
        assert_eq!(Role::from_groups("viewers,sensors"), Some(Role::Sensor));
    }
}
