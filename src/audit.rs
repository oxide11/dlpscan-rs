//! Audit logging facade — re-exports the core audit module from
//! [`siphon_core::audit`] and adds the `event_from_scan` factory which
//! depends on this crate's [`crate::guard::ScanResult`].
//!
//! The split keeps the bulk of the audit machinery (events, signing,
//! chain mode, file/rotating handlers, global logger) in `siphon-core`
//! so the standalone pods (`siphon-api` etc.) can emit signed audit
//! events without taking a dependency on the root `siphon` crate.
//! Only the convenience wrapper that converts a `ScanResult` into an
//! `AuditEvent` lives here.

pub use siphon_core::audit::{
    audit_event, set_audit_logger, with_audit_logger, AuditEvent, AuditHandler, AuditLogger,
    CallbackAuditHandler, FileAuditHandler, NullAuditHandler, RotatingFileAuditHandler,
    StderrAuditHandler, VALID_EVENT_TYPES,
};

/// Create an [`AuditEvent`] from a [`crate::guard::ScanResult`].
pub fn event_from_scan(
    result: &crate::guard::ScanResult,
    action: &str,
    source: Option<&str>,
    duration_ms: Option<f64>,
    user: Option<&str>,
) -> AuditEvent {
    let event_type = match action.to_uppercase().as_str() {
        "REJECT" => "REJECT",
        "REDACT" => "REDACT",
        "FLAG" => "FLAG",
        "TOKENIZE" => "TOKENIZE",
        "OBFUSCATE" => "OBFUSCATE",
        "DETOKENIZE" => "DETOKENIZE",
        _ => "SCAN",
    };

    let mut event = match AuditEvent::new(event_type) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!("Failed to create audit event: {}", err);
            // SCAN is always in VALID_EVENT_TYPES so the fallback cannot fail.
            AuditEvent::new("SCAN").expect("SCAN is a valid event type")
        }
    };

    let outcome = if result.is_clean {
        "success"
    } else if action.eq_ignore_ascii_case("REJECT") {
        "rejected"
    } else {
        "findings_detected"
    };

    event = event
        .with_action(action)
        .with_is_clean(result.is_clean)
        .with_finding_count(result.finding_count())
        .with_categories_found(result.categories_found.iter().cloned().collect::<Vec<_>>())
        .with_outcome(outcome);

    if let Some(src) = source {
        event = event.with_source(src);
    }
    if let Some(ms) = duration_ms {
        event = event.with_duration_ms(ms);
    }
    if let Some(u) = user {
        event = event.with_user(u);
    }

    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn clean_scan_result() -> crate::guard::ScanResult {
        crate::guard::ScanResult {
            text: String::new(),
            is_clean: true,
            findings: vec![],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
            classification_level: None,
        }
    }

    fn dirty_scan_result(category: &str) -> crate::guard::ScanResult {
        let mut cats = HashSet::new();
        cats.insert(category.to_string());
        crate::guard::ScanResult {
            text: "hello".to_string(),
            is_clean: false,
            findings: vec![],
            redacted_text: None,
            categories_found: cats,
            scan_truncated: false,
            classification_level: None,
        }
    }

    #[test]
    fn test_event_from_scan() {
        let scan_result = dirty_scan_result("SSN");
        let event = event_from_scan(
            &scan_result,
            "redact",
            Some("cli"),
            Some(12.3),
            Some("alice"),
        );
        assert_eq!(event.event_type, "REDACT");
        assert_eq!(event.action.as_deref(), Some("redact"));
        assert_eq!(event.source.as_deref(), Some("cli"));
        assert_eq!(event.duration_ms, Some(12.3));
        assert_eq!(event.user.as_deref(), Some("alice"));
        assert!(!event.is_clean);
        assert!(event.categories_found.contains(&"SSN".to_string()));
    }

    #[test]
    fn test_event_from_scan_unknown_action_defaults_to_scan() {
        let scan_result = clean_scan_result();
        let event = event_from_scan(&scan_result, "unknown_action", None, None, None);
        assert_eq!(event.event_type, "SCAN");
    }

    #[test]
    fn test_event_from_scan_outcome() {
        let clean = clean_scan_result();
        let event = event_from_scan(&clean, "flag", None, None, None);
        assert_eq!(event.outcome.as_deref(), Some("success"));

        let dirty = dirty_scan_result("SSN");
        let event = event_from_scan(&dirty, "REJECT", None, None, None);
        assert_eq!(event.outcome.as_deref(), Some("rejected"));

        let event = event_from_scan(&dirty, "flag", None, None, None);
        assert_eq!(event.outcome.as_deref(), Some("findings_detected"));
    }
}
