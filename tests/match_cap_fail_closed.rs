//! A match cap must never produce a transformed result that still contains
//! the values it claims to have removed.
//!
//! The scanner stops collecting a pattern at `MAX_MATCHES_PER_PATTERN`
//! (10,000) and the whole scan at `max_matches`. Both are denial-of-service
//! bounds and both are correct. What was not correct was returning the
//! prefix as though it were the document: `InputGuard` redacted exactly the
//! spans it was handed, left every value past the cap intact, and reported
//! `scan_truncated: false` over the top of it.
//!
//! These tests pin the boundary. The cap is exact, so 10,000 occurrences is
//! a complete scan and 10,001 is not.

use siphon::errors::DlpError;
use siphon::guard::{Action, InputGuard};

/// Passes Luhn, so validation cannot be what drops it.
const CARD: &str = "4532015112830366";
const PER_PATTERN_CAP: usize = 10_000;

fn doc(occurrences: usize) -> String {
    format!("Credit card: {CARD}\n").repeat(occurrences)
}

fn guard(action: Action) -> InputGuard {
    InputGuard::new()
        .with_action(action)
        .with_categories(["Credit Card Numbers".to_string()].into_iter().collect())
}

#[test]
fn under_the_cap_every_value_is_redacted() {
    let input = doc(PER_PATTERN_CAP - 1);
    let r = guard(Action::Redact).scan(&input).expect("complete scan");
    assert!(!r.scan_truncated, "9,999 occurrences is under the cap");
    assert_eq!(r.findings.len(), PER_PATTERN_CAP - 1);
    let redacted = r.redacted_text.expect("redact produces text");
    assert_eq!(
        redacted.matches(CARD).count(),
        0,
        "a complete scan must leave no card in redacted output"
    );
}

#[test]
fn exactly_at_the_cap_is_still_a_complete_scan() {
    let input = doc(PER_PATTERN_CAP);
    let r = guard(Action::Redact).scan(&input).expect("complete scan");
    assert!(!r.scan_truncated, "the cap is a ceiling, not a fence post");
    assert_eq!(r.findings.len(), PER_PATTERN_CAP);
    assert_eq!(
        r.redacted_text
            .expect("redact produces text")
            .matches(CARD)
            .count(),
        0
    );
}

#[test]
fn past_the_cap_redaction_refuses_rather_than_leaking() {
    // The regression. This document previously returned Ok with five intact
    // card numbers in `redacted_text` and `scan_truncated: false`.
    let input = doc(PER_PATTERN_CAP + 1);
    match guard(Action::Redact).scan(&input) {
        Err(DlpError::ScanTruncated { collected, action }) => {
            assert_eq!(collected, PER_PATTERN_CAP);
            assert_eq!(action, "redact");
        }
        Err(other) => panic!("expected ScanTruncated, got {other}"),
        Ok(r) => {
            let leaked = r
                .redacted_text
                .as_deref()
                .map(|t| t.matches(CARD).count())
                .unwrap_or(0);
            panic!("truncated scan returned Ok with {leaked} cards still in the output");
        }
    }
}

#[test]
fn tokenize_and_obfuscate_refuse_on_the_same_boundary() {
    let input = doc(PER_PATTERN_CAP + 1);
    for (action, name) in [
        (Action::Tokenize, "tokenize"),
        (Action::Obfuscate, "obfuscate"),
    ] {
        match guard(action).scan(&input) {
            Err(DlpError::ScanTruncated { action: got, .. }) => assert_eq!(got, name),
            other => panic!("{name} on a truncated scan should refuse, got {other:?}"),
        }
    }
}

#[test]
fn flag_reports_the_truncation_instead_of_refusing() {
    // Flag transforms nothing, so there is nothing to lie about. The caller
    // gets the findings and the fact that there are more.
    let input = doc(PER_PATTERN_CAP + 1);
    let r = guard(Action::Flag)
        .scan(&input)
        .expect("flag does not refuse");
    assert!(
        r.scan_truncated,
        "the caller must be told the scan was capped"
    );
    assert_eq!(r.findings.len(), PER_PATTERN_CAP);
    assert!(r.redacted_text.is_none());
}
