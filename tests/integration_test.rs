//! Integration tests for the DLP scanner.
//!
//! These test the full scanning pipeline end-to-end, including normalization,
//! pattern matching, context checking, and confidence scoring.

use dlpscan::{scan_text, ScanConfig};

// ---------------------------------------------------------------------------
// Core scanner integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_detects_ssn() {
    let matches = scan_text("My SSN is 123-45-6789").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Expected SSN detection, got: {:?}",
        matches.iter().map(|m| &m.sub_category).collect::<Vec<_>>()
    );
}

#[test]
fn test_detects_credit_card_visa() {
    let matches = scan_text("Card: 4532015112830366").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "Visa"),
        "Expected Visa detection"
    );
}

#[test]
fn test_detects_credit_card_mastercard() {
    let matches = scan_text("Payment to 5425233430109903").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "MasterCard"),
        "Expected MasterCard detection"
    );
}

#[test]
fn test_detects_email() {
    let matches = scan_text("Contact us at test@example.com for info.").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "Email Address"),
        "Expected email detection"
    );
}

#[test]
fn test_detects_iban() {
    let matches = scan_text("Transfer to DE89370400440532013000").unwrap();
    assert!(
        matches.iter().any(|m| m.category.contains("Banking")),
        "Expected IBAN detection, got: {:?}",
        matches.iter().map(|m| &m.category).collect::<Vec<_>>()
    );
}

#[test]
fn test_detects_bitcoin_address() {
    let matches = scan_text("Pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
    assert!(
        matches.iter().any(|m| m.category.contains("Crypto")),
        "Expected crypto detection"
    );
}

#[test]
fn test_clean_text_no_matches() {
    let matches = scan_text("The quick brown fox jumps over the lazy dog.").unwrap();
    let high_conf: Vec<_> = matches.iter().filter(|m| m.confidence > 0.8).collect();
    assert!(
        high_conf.len() < 3,
        "Expected few high-confidence matches on clean text, got {}",
        high_conf.len()
    );
}

#[test]
fn test_rejects_empty_input() {
    assert!(scan_text("").is_err());
}

#[test]
fn test_category_filter() {
    let config = ScanConfig {
        categories: Some(["Contact Information".to_string()].into_iter().collect()),
        ..Default::default()
    };
    let matches =
        dlpscan::scanner::scan_text_with_config("Email: test@example.com SSN: 123-45-6789", &config)
            .unwrap();
    assert!(
        matches.iter().all(|m| m.category == "Contact Information"),
        "Category filter should exclude non-contact matches"
    );
}

#[test]
fn test_min_confidence_filter() {
    let config = ScanConfig {
        min_confidence: 0.9,
        ..Default::default()
    };
    let matches =
        dlpscan::scanner::scan_text_with_config("SSN: 123-45-6789 and email test@example.com", &config)
            .unwrap();
    assert!(
        matches.iter().all(|m| m.confidence >= 0.9),
        "All matches should meet min_confidence threshold"
    );
}

// ---------------------------------------------------------------------------
// Evasion detection integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_evasion_percent_encoded_ssn() {
    let matches = scan_text("SSN: %31%32%33-%34%35-%36%37%38%39").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect percent-encoded SSN"
    );
}

#[test]
fn test_evasion_html_entity_ssn() {
    let matches = scan_text("SSN: &#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect HTML-entity-encoded SSN"
    );
}

#[test]
fn test_evasion_css_comment_injection() {
    let matches = scan_text("Card: 4/**/5/**/3/**/2/**/0/**/1/**/5/**/1/**/1/**/2/**/8/**/3/**/0/**/3/**/6/**/6").unwrap();
    assert!(
        matches.iter().any(|m| m.category.contains("Credit Card")),
        "Should detect CSS-comment-injected credit card"
    );
}

#[test]
fn test_evasion_excessive_delimiter() {
    let matches = scan_text("Card: 4532--0151--1283--0366").unwrap();
    assert!(
        matches.iter().any(|m| m.category.contains("Credit Card")),
        "Should detect excessive-delimiter credit card"
    );
}

#[test]
fn test_evasion_zero_width_chars() {
    let matches = scan_text("SSN: 1\u{200B}2\u{200B}3-4\u{200B}5-6\u{200B}7\u{200B}8\u{200B}9").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect SSN with zero-width characters"
    );
}

#[test]
fn test_evasion_fullwidth_digits() {
    let matches = scan_text("SSN: \u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect fullwidth-digit SSN"
    );
}

// ---------------------------------------------------------------------------
// Guard integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_guard_flag_mode() {
    use dlpscan::{InputGuard, Action, Preset};
    // Use PciDss preset which includes credit card category
    let guard = InputGuard::new()
        .with_action(Action::Flag)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366").unwrap();
    assert!(!result.is_clean, "Should flag text with credit card");
    assert!(result.redacted_text.is_none(), "Flag mode should not redact");
}

#[test]
fn test_guard_redact_mode() {
    use dlpscan::{InputGuard, Action, Preset};
    let guard = InputGuard::new()
        .with_action(Action::Redact)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366").unwrap();
    assert!(!result.is_clean);
    assert!(result.redacted_text.is_some(), "Redact mode should produce redacted text");
    let redacted = result.redacted_text.unwrap();
    assert!(
        !redacted.contains("4532015112830366"),
        "Redacted text should not contain original card number"
    );
}

#[test]
fn test_guard_reject_mode() {
    use dlpscan::{InputGuard, Action, Preset};
    let guard = InputGuard::new()
        .with_action(Action::Reject)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366");
    assert!(result.is_err(), "Reject mode should return error on sensitive data");
}

#[test]
fn test_guard_clean_text_passes() {
    use dlpscan::{InputGuard, Action, Preset};
    let guard = InputGuard::new()
        .with_action(Action::Reject)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Hello world, nothing sensitive here.");
    assert!(result.is_ok(), "Clean text should pass even in reject mode");
}

// ---------------------------------------------------------------------------
// API handler integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_api_handle_scan() {
    use dlpscan::api::{handle_scan, ScanRequest, handle_health};

    let req = ScanRequest {
        text: "My email is test@example.com".to_string(),
        action: "flag".to_string(),
        presets: vec!["pii".to_string()],
        categories: vec![],
        min_confidence: 0.0,
        require_context: false,
    };

    let resp = handle_scan(&req).unwrap();
    assert!(resp.finding_count > 0, "Should find email in scan");

    let health = handle_health();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn test_api_handle_batch_scan() {
    use dlpscan::api::{handle_batch_scan, BatchScanRequest, ScanRequest};

    let req = BatchScanRequest {
        items: vec![
            ScanRequest {
                text: "SSN: 123-45-6789".to_string(),
                action: "flag".to_string(),
                presets: vec![],
                categories: vec![],
                min_confidence: 0.0,
                require_context: false,
            },
            ScanRequest {
                text: "Clean text here".to_string(),
                action: "flag".to_string(),
                presets: vec![],
                categories: vec![],
                min_confidence: 0.0,
                require_context: false,
            },
        ],
    };

    let resp = handle_batch_scan(&req).unwrap();
    assert_eq!(resp.results.len(), 2);
    assert!(resp.results[0].finding_count > 0, "First item should have findings");
}

// ---------------------------------------------------------------------------
// RBAC integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_rbac_permission_matrix() {
    use dlpscan::rbac::{Role, Permission, role_has_permission};

    assert!(role_has_permission(Role::Admin, Permission::ManagePatterns));
    assert!(role_has_permission(Role::Admin, Permission::ExportVault));
    assert!(role_has_permission(Role::Viewer, Permission::ViewStatus));
    assert!(!role_has_permission(Role::Viewer, Permission::Scan));
    assert!(role_has_permission(Role::Operator, Permission::Scan));
    assert!(!role_has_permission(Role::Operator, Permission::ManagePatterns));
}

// ---------------------------------------------------------------------------
// Compliance integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_compliance_report_generation() {
    let matches = scan_text("Card: 4532015112830366").unwrap();
    let reporter = dlpscan::ComplianceReporter::new("Integration Test");
    reporter.add_scan_result(&matches, "test-input");
    let report = reporter.generate();
    assert!(!report.compliance_status.is_empty(), "Should have compliance status");
    // Serialize to JSON
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("compliance_status"), "JSON should contain compliance_status");
}

// ---------------------------------------------------------------------------
// Token vault integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_tokenize_and_detokenize() {
    use dlpscan::guard::TokenVault;

    let mut vault = TokenVault::new("TEST", None);
    let token = vault.tokenize("123-45-6789", "SSN");

    assert!(token.starts_with("TEST_"));
    assert_ne!(token, "123-45-6789");

    let original = vault.detokenize(&token);
    assert_eq!(original, Some("123-45-6789"));

    // Deterministic
    let token2 = vault.tokenize("123-45-6789", "SSN");
    assert_eq!(token, token2);
}

// ---------------------------------------------------------------------------
// Streaming scanner integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_scanner() {
    let scanner = dlpscan::StreamScanner::new(4096, 200);
    let mut all_matches = scanner.feed("Here is an SSN: 123-45-6789 embedded in a larger document.");
    all_matches.extend(scanner.flush());
    assert!(
        all_matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Stream scanner should detect SSN, got: {:?}",
        all_matches.iter().map(|m| &m.sub_category).collect::<Vec<_>>()
    );
}
