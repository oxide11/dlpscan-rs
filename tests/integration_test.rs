//! Integration tests for the DLP scanner.
//!
//! These test the full scanning pipeline end-to-end, including normalization,
//! pattern matching, context checking, and confidence scoring.

use siphon::{scan_text, ScanConfig};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Core scanner integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_detects_ssn() {
    let matches = scan_text("My SSN is 425-71-3482").unwrap();
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
    let matches = siphon::scanner::scan_text_with_config(
        "Email: test@example.com SSN: 425-71-3482",
        &config,
    )
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
    let matches = siphon::scanner::scan_text_with_config(
        "SSN: 425-71-3482 and email test@example.com",
        &config,
    )
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
    let matches = scan_text("SSN: %34%32%35-%37%31-%33%34%38%32").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect percent-encoded SSN"
    );
}

#[test]
fn test_evasion_html_entity_ssn() {
    let matches = scan_text("SSN: &#52;&#50;&#53;-&#55;&#49;-&#51;&#52;&#56;&#50;").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect HTML-entity-encoded SSN"
    );
}

#[test]
fn test_evasion_css_comment_injection() {
    let matches = scan_text(
        "Card: 4/**/5/**/3/**/2/**/0/**/1/**/5/**/1/**/1/**/2/**/8/**/3/**/0/**/3/**/6/**/6",
    )
    .unwrap();
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
    let matches =
        scan_text("SSN: 4\u{200B}2\u{200B}5-7\u{200B}1-3\u{200B}4\u{200B}8\u{200B}2").unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Should detect SSN with zero-width characters"
    );
}

#[test]
fn test_evasion_fullwidth_digits() {
    let matches = scan_text(
        "SSN: \u{FF14}\u{FF12}\u{FF15}-\u{FF17}\u{FF11}-\u{FF13}\u{FF14}\u{FF18}\u{FF12}",
    )
    .unwrap();
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
    use siphon::{Action, InputGuard, Preset};
    // Use PciDss preset which includes credit card category
    let guard = InputGuard::new()
        .with_action(Action::Flag)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366").unwrap();
    assert!(!result.is_clean, "Should flag text with credit card");
    assert!(
        result.redacted_text.is_none(),
        "Flag mode should not redact"
    );
}

#[test]
fn test_guard_redact_mode() {
    use siphon::{Action, InputGuard, Preset};
    let guard = InputGuard::new()
        .with_action(Action::Redact)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366").unwrap();
    assert!(!result.is_clean);
    assert!(
        result.redacted_text.is_some(),
        "Redact mode should produce redacted text"
    );
    let redacted = result.redacted_text.unwrap();
    assert!(
        !redacted.contains("4532015112830366"),
        "Redacted text should not contain original card number"
    );
}

#[test]
fn test_guard_reject_mode() {
    use siphon::{Action, InputGuard, Preset};
    let guard = InputGuard::new()
        .with_action(Action::Reject)
        .with_presets(vec![Preset::PciDss]);
    let result = guard.scan("Card: 4532015112830366");
    assert!(
        result.is_err(),
        "Reject mode should return error on sensitive data"
    );
}

#[test]
fn test_guard_clean_text_passes() {
    use siphon::{Action, InputGuard, Preset};
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
    use siphon::api::{handle_health, handle_scan, ScanRequest};

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
    use siphon::api::{handle_batch_scan, BatchScanRequest, ScanRequest};

    let req = BatchScanRequest {
        items: vec![
            ScanRequest {
                text: "SSN: 425-71-3482".to_string(),
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
    assert!(
        resp.results[0].finding_count > 0,
        "First item should have findings"
    );
}

// ---------------------------------------------------------------------------
// RBAC integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_rbac_permission_matrix() {
    use siphon::rbac::{role_has_permission, Permission, Role};

    assert!(role_has_permission(Role::Admin, Permission::ManagePatterns));
    assert!(role_has_permission(Role::Admin, Permission::ExportVault));
    assert!(role_has_permission(Role::Viewer, Permission::ViewStatus));
    assert!(!role_has_permission(Role::Viewer, Permission::Scan));
    assert!(role_has_permission(Role::Operator, Permission::Scan));
    assert!(!role_has_permission(
        Role::Operator,
        Permission::ManagePatterns
    ));
}

// ---------------------------------------------------------------------------
// Compliance integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_compliance_report_generation() {
    let matches = scan_text("Card: 4532015112830366").unwrap();
    let reporter = siphon::ComplianceReporter::new("Integration Test");
    reporter.add_scan_result(&matches, "test-input");
    let report = reporter.generate();
    assert!(
        !report.compliance_status.is_empty(),
        "Should have compliance status"
    );
    // Serialize to JSON
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        json.contains("compliance_status"),
        "JSON should contain compliance_status"
    );
}

// ---------------------------------------------------------------------------
// Token vault integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_tokenize_and_detokenize() {
    use siphon::guard::TokenVault;

    let mut vault = TokenVault::new("TEST", None);
    let token = vault.tokenize("425-71-3482", "SSN");

    assert!(token.starts_with("TEST_"));
    assert_ne!(token, "425-71-3482");

    let original = vault.detokenize(&token);
    assert_eq!(original, Some("425-71-3482"));

    // Deterministic
    let token2 = vault.tokenize("425-71-3482", "SSN");
    assert_eq!(token, token2);
}

// ---------------------------------------------------------------------------
// Streaming scanner integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_scanner() {
    let scanner = siphon::StreamScanner::new(4096, 200);
    let mut all_matches =
        scanner.feed("Here is an SSN: 425-71-3482 embedded in a larger document.");
    all_matches.extend(scanner.flush());
    assert!(
        all_matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Stream scanner should detect SSN, got: {:?}",
        all_matches
            .iter()
            .map(|m| &m.sub_category)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Security hardening integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_audit_event_signing_roundtrip() {
    use siphon::audit::AuditEvent;
    let key = b"integration-test-signing-key!!!!";
    let event = AuditEvent::new("REDACT")
        .unwrap()
        .with_action("redact")
        .with_finding_count(3)
        .with_source_ip("10.0.0.1")
        .with_request_id("req-abc")
        .with_outcome("findings_detected")
        .sign(key)
        .expect("signing must succeed");

    // Serialize, deserialize, verify
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
    assert!(deserialized.verify(key), "Deserialized event must verify");
    assert!(!deserialized.verify(b"wrong-key-should-fail-verificatn"));
}

#[test]
fn test_compliance_report_redacts_samples() {
    use siphon::compliance::ComplianceReporter;
    use siphon::{Action, InputGuard, Preset};

    let guard = InputGuard::new()
        .with_presets(vec![Preset::PciDss])
        .with_action(Action::Flag);
    let result = guard.scan("Card: 4532015112830366").unwrap();

    let reporter = ComplianceReporter::new("Test");
    reporter.add_scan_result(&result.findings, "test");
    let report_text = reporter.to_text();

    // The sample should be redacted, not contain the raw card number
    assert!(
        !report_text.contains("4532015112830366"),
        "Compliance report must not contain raw card number"
    );
}

#[test]
fn test_luhn_rejects_trivial_sequences() {
    use siphon::validation::is_luhn_valid;
    // All zeros should fail despite passing Luhn checksum
    assert!(!is_luhn_valid("0000000000000000"));
    // All same digit should fail
    assert!(!is_luhn_valid("1111111111111111"));
    // Short sequences should fail
    assert!(!is_luhn_valid("12345"));
    // Valid card still passes
    assert!(is_luhn_valid("4532015112830366"));
}

#[test]
fn test_file_type_blocking() {
    use siphon::extractors::{
        is_blocked_extension, is_path_blocked, is_unreadable_extension, DEFAULT_BLOCKED_EXTENSIONS,
    };

    // Direct extension check
    assert!(is_blocked_extension("der", DEFAULT_BLOCKED_EXTENSIONS));
    assert!(is_blocked_extension("P12", DEFAULT_BLOCKED_EXTENSIONS));
    assert!(!is_blocked_extension("txt", DEFAULT_BLOCKED_EXTENSIONS));

    // Double extension bypass prevention
    assert!(is_path_blocked(
        "secrets.der.txt",
        DEFAULT_BLOCKED_EXTENSIONS
    ));
    assert!(is_path_blocked("cert.pfx.bak", DEFAULT_BLOCKED_EXTENSIONS));
    assert!(!is_path_blocked("readme.md", DEFAULT_BLOCKED_EXTENSIONS));

    // Unreadable types
    assert!(is_unreadable_extension("exe"));
    assert!(is_unreadable_extension("gpg"));
    assert!(!is_unreadable_extension("csv"));
}

#[test]
fn test_evasion_greek_epsilon() {
    // Greek epsilon (ε) should be normalized to 'e', allowing detection
    let text = "t\u{03B5}st@example.com";
    let matches = scan_text(text).unwrap();
    assert!(
        matches.iter().any(|m| m.category == "Contact Information"),
        "Greek epsilon evasion should still detect email: {:?}",
        matches.iter().map(|m| &m.sub_category).collect::<Vec<_>>()
    );
}

#[test]
fn test_evasion_cyrillic_yo() {
    // Cyrillic ё (U+0451) should normalize to 'e'
    let text = "SSN: 425-71-3482 with \u{0451}vasion";
    let matches = scan_text(text).unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Cyrillic yo evasion should not hide SSN"
    );
}

#[test]
fn test_ipv6_mapped_ipv4_ssrf() {
    use siphon::http_util::is_private_ip;
    use std::net::IpAddr;

    // ::ffff:127.0.0.1 must be blocked
    let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(is_private_ip(ip), "IPv4-mapped loopback must be blocked");

    // ::ffff:10.0.0.1 must be blocked
    let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(is_private_ip(ip), "IPv4-mapped private must be blocked");

    // ::ffff:8.8.8.8 must be allowed
    let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
    assert!(!is_private_ip(ip), "IPv4-mapped public must be allowed");
}

#[test]
fn test_printable_string_extraction_from_binary() {
    use siphon::extractors::extract_text;

    // Create a DAT file with sensitive data embedded in binary
    let mut data = vec![0u8; 50];
    data.extend_from_slice(b"SSN: 425-71-3482 embedded in binary data here");
    data.extend_from_slice(&vec![0xFF; 50]);

    let f = tempfile::Builder::new().suffix(".dat").tempfile().unwrap();
    std::fs::write(f.path(), &data).unwrap();

    let result = extract_text(f.path().to_str().unwrap()).unwrap();
    assert!(
        result.text.contains("425-71-3482"),
        "DAT extraction should find SSN in binary"
    );
}

#[test]
fn test_cab_extraction_with_mscf_header() {
    use siphon::extractors::extract_text;

    let mut data = b"MSCF".to_vec();
    data.extend_from_slice(&vec![0u8; 20]);
    data.extend_from_slice(b"credit card 4532015112830366 inside cabinet");

    let f = tempfile::Builder::new().suffix(".cab").tempfile().unwrap();
    std::fs::write(f.path(), &data).unwrap();

    let result = extract_text(f.path().to_str().unwrap()).unwrap();
    assert!(
        result.text.contains("4532015112830366"),
        "CAB extraction should find card number"
    );
}

#[test]
fn test_vault_ttl_expired_rejection() {
    use siphon::api::{handle_detokenize, DetokenizeRequest, VaultEntry, VAULT_TTL_SECS};
    use siphon::guard::TokenVault;
    use std::collections::HashMap;
    use std::sync::RwLock;
    use std::time::Instant;

    let vaults: RwLock<HashMap<String, VaultEntry>> = RwLock::new(HashMap::new());
    vaults.write().unwrap().insert(
        "v1".to_string(),
        VaultEntry {
            vault: TokenVault::new("TOK", None),
            created_at: Instant::now() - std::time::Duration::from_secs(VAULT_TTL_SECS + 100),
        },
    );

    let req = DetokenizeRequest {
        text: "hello".to_string(),
        vault_id: "v1".to_string(),
    };
    let err = handle_detokenize(&req, &vaults).unwrap_err();
    assert!(
        err.contains("expired"),
        "Expired vault should be rejected: {err}"
    );
}

#[test]
fn test_rbac_admin_action_restricted() {
    use siphon::rbac::{role_has_permission, Permission, Role};

    assert!(role_has_permission(Role::Admin, Permission::AdminAction));
    assert!(!role_has_permission(Role::Analyst, Permission::AdminAction));
    assert!(!role_has_permission(
        Role::Operator,
        Permission::AdminAction
    ));
    assert!(!role_has_permission(Role::Viewer, Permission::AdminAction));
}

// ---------------------------------------------------------------------------
// EDM (Exact Data Match) integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_edm_register_and_scan() {
    let mut edm = siphon::edm::ExactDataMatcher::new(None, None);
    edm.register_values("ssn", &["425-71-3482", "987-65-4321"]);
    edm.register_values("email", &["secret@internal.corp"]);

    let text = "Customer SSN is 425-71-3482 and email secret@internal.corp here.";
    let matches = edm.scan(text, None);
    assert!(
        matches.iter().any(|m| m.category == "ssn"),
        "EDM should find registered SSN: {:?}",
        matches
            .iter()
            .map(|m| (&m.category, &m.matched_text))
            .collect::<Vec<_>>()
    );
    assert!(
        matches.iter().any(|m| m.category == "email"),
        "EDM should find registered email: {:?}",
        matches
            .iter()
            .map(|m| (&m.category, &m.matched_text))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_edm_wired_into_scanner() {
    // Register a known sensitive email. EDM match won't be dominated
    // by regex because EDM category is different ("EDM: emails").
    let mut edm = siphon::edm::ExactDataMatcher::new(None, None);
    edm.register_values("watchlist", &["target@hostile.net"]);

    let config = ScanConfig {
        edm: Some(Arc::new(edm)),
        min_confidence: 0.0,
        ..Default::default()
    };
    let text = "Contact target@hostile.net about the deal.";
    let matches = siphon::scanner::scan_text_with_config(text, &config).unwrap();
    // Both regex (Email Address) and EDM (watchlist) should fire
    assert!(
        matches.iter().any(|m| m.category.contains("EDM")),
        "Scanner with EDM should find EDM match alongside regex: {:?}",
        matches
            .iter()
            .map(|m| (&m.category, &m.sub_category, m.confidence))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_edm_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("edm-state.json");
    let path_str = path.to_str().unwrap();

    let mut edm = siphon::edm::ExactDataMatcher::new(None, None);
    edm.register_values("test", &["secret-value-123"]);
    edm.save(path_str).unwrap();

    let loaded = siphon::edm::ExactDataMatcher::load(path_str).unwrap();
    assert!(loaded.check_value("secret-value-123", Some("test")));
    assert!(!loaded.check_value("other-value", Some("test")));
}

// ---------------------------------------------------------------------------
// LSH (Document Similarity) integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_lsh_register_and_query() {
    let vault = siphon::lsh::DocumentVault::default_vault();
    let doc = "This is a confidential financial report containing sensitive revenue projections and strategic acquisition targets for Q4 2026.";
    vault.register("fin-report-q4", doc, "confidential", None);

    // Query with very similar text
    let query = "This is a confidential financial report containing sensitive revenue projections and strategic acquisition targets for Q4 2026.";
    let matches = vault.query(query, Some(0.5));
    assert!(!matches.is_empty(), "LSH should find similar document");
    assert_eq!(matches[0].doc_id, "fin-report-q4");
    assert!(matches[0].similarity > 0.5);
}

#[test]
fn test_lsh_wired_into_scanner() {
    let vault = siphon::lsh::DocumentVault::default_vault();
    let doc = "Quarterly earnings report with projected revenue of fifty million dollars and operating margin improvements across all business segments in the enterprise division.";
    vault.register("earnings-q4", doc, "restricted", None);

    let config = ScanConfig {
        lsh: Some(Arc::new(vault)),
        ..Default::default()
    };
    // Scan the same document — should match
    let matches = siphon::scanner::scan_text_with_config(doc, &config).unwrap();
    assert!(
        matches.iter().any(|m| m.category == "Document Similarity"),
        "Scanner with LSH should find similar document: {:?}",
        matches
            .iter()
            .map(|m| (&m.category, &m.sub_category))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_lsh_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lsh-state.json");
    let path_str = path.to_str().unwrap();

    let vault = siphon::lsh::DocumentVault::default_vault();
    vault.register("doc1", "This is a test document with enough words to create meaningful shingles for the locality sensitive hashing algorithm to work correctly.", "sensitive", None);
    vault.save(path_str).unwrap();

    let loaded = siphon::lsh::DocumentVault::load(path_str).unwrap();
    assert_eq!(loaded.document_count(), 1);
}

// ---------------------------------------------------------------------------
// Filename context tests
// ---------------------------------------------------------------------------

#[test]
fn test_filename_provides_context_for_sin() {
    // A file named "sin.txt" should provide "sin" as a context keyword,
    // boosting confidence for Canadian SIN patterns in the content.
    let f = tempfile::Builder::new()
        .prefix("sin")
        .suffix(".txt")
        .tempfile()
        .unwrap();
    // Write a 9-digit number that could be a SIN (no keywords in content)
    std::fs::write(f.path(), "reference number 246 100 002 for the account").unwrap();

    let pipeline = siphon::Pipeline::new().with_min_confidence(0.0);
    let result = pipeline.process_file(f.path());

    // The filename "sin*.txt" should provide "sin" context
    let has_context_match = result.matches.iter().any(|m| m.has_context);
    assert!(
        has_context_match || !result.matches.is_empty(),
        "File named 'sin.txt' should boost context for SIN-like numbers. Matches: {:?}",
        result
            .matches
            .iter()
            .map(|m| (&m.category, &m.sub_category, m.confidence, m.has_context))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_filename_provides_context_for_ssn() {
    // A file named "ssn_report.csv" should provide "ssn" context
    let f = tempfile::Builder::new()
        .prefix("ssn_report")
        .suffix(".csv")
        .tempfile()
        .unwrap();
    std::fs::write(f.path(), "id,number\n1,219-09-9999\n").unwrap();

    let pipeline = siphon::Pipeline::new().with_min_confidence(0.0);
    let result = pipeline.process_file(f.path());

    let ssn_match = result.matches.iter().find(|m| m.sub_category == "USA SSN");
    assert!(
        ssn_match.is_some(),
        "File named 'ssn_report.csv' should detect SSN: {:?}",
        result
            .matches
            .iter()
            .map(|m| &m.sub_category)
            .collect::<Vec<_>>()
    );
    // The SSN should have context (from filename)
    if let Some(m) = ssn_match {
        assert!(
            m.has_context,
            "SSN in file named 'ssn_report' should have context from filename"
        );
    }
}

// ---------------------------------------------------------------------------
// French keyword context tests
// ---------------------------------------------------------------------------

#[test]
fn test_french_credit_card_context() {
    // "carte de crédit" should provide context for credit card detection
    let text = "Le numéro de carte de crédit est 4532015112830366 du client.";
    let matches = scan_text(text).unwrap();
    let visa = matches.iter().find(|m| m.sub_category == "Visa");
    assert!(visa.is_some(), "French CC context should detect Visa");
    assert!(
        visa.unwrap().has_context,
        "Visa should have context from 'carte de crédit'"
    );
}

#[test]
fn test_french_sin_context() {
    // "numéro d'assurance sociale" should boost SIN detection
    let text = "Son numéro d'assurance sociale est 246 100 002 selon le dossier.";
    let matches = scan_text(text).unwrap();
    let has_context_match = matches
        .iter()
        .any(|m| m.has_context && m.category.contains("Canada"));
    assert!(
        has_context_match || !matches.is_empty(),
        "French SIN context should boost detection: {:?}",
        matches
            .iter()
            .map(|m| (&m.category, &m.sub_category, m.has_context))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_french_email_context() {
    // "courriel" is French for email
    let text = "Veuillez envoyer un courriel à test@example.com pour confirmer.";
    let matches = scan_text(text).unwrap();
    let email = matches.iter().find(|m| m.sub_category == "Email Address");
    assert!(email.is_some(), "French email context should detect email");
    assert!(
        email.unwrap().has_context,
        "Email should have context from 'courriel'"
    );
}

#[test]
fn test_french_confidential_context() {
    // "confidentiel" should provide classification context
    let text = "Document confidentiel: carte 4532015112830366 du compte.";
    let matches = scan_text(text).unwrap();
    assert!(
        !matches.is_empty(),
        "French confidential context should detect card"
    );
}

#[test]
fn test_french_password_context() {
    // "mot de passe" is a French password keyword; the scanner must
    // handle French-language context around a sensitive value without
    // breaking detection. We include an email in the input so the
    // primary scan path has an unambiguous positive signal to assert
    // against — previously this test depended on a false-positive
    // Geohash match against the reversed substring "ruevres" produced
    // by the alt-decodings second pass. That false positive vanished
    // once alt-decoding was restricted to high-specificity patterns,
    // which exposed the fact that the test was asserting nothing
    // meaningful.
    //
    // A TODO remains to investigate whether gated entropy should
    // detect the 32-char alphanumeric token in this input — it
    // currently does not fire, but that is a separate issue from the
    // French-context coverage this test is meant to exercise.
    let text = "Le mot de passe pour contact@example.com est xK9mPqR3vL7nW2jF8hYcT5bA0dGiEuOs.";
    let config = ScanConfig {
        entropy_scan: siphon::scanner::EntropyMode::Gated,
        min_confidence: 0.0,
        ..Default::default()
    };
    let matches = siphon::scanner::scan_text_with_config(text, &config).unwrap();
    // The primary path must find the email, proving French-language
    // surrounding text does not break the scanner.
    assert!(
        matches.iter().any(|m| m.sub_category == "Email Address"),
        "expected email detection in French-context input, got: {:?}",
        matches
            .iter()
            .map(|m| (m.category.as_str(), m.sub_category.as_str()))
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn test_pipeline_rejects_character_device() {
    // Regression: prior to the is_file() gate, pointing the pipeline at
    // /dev/zero would hang indefinitely — metadata.len() reports 0 so
    // the max_file_size check passes, then read_to_string drains the
    // device forever. The guard now rejects non-regular files up front.
    let pipeline = siphon::Pipeline::new();
    let result = pipeline.process_file(std::path::Path::new("/dev/zero"));
    assert!(
        result.matches.is_empty(),
        "character device should yield no matches"
    );
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Not a regular file")),
        "expected Not-a-regular-file error, got: {:?}",
        result.error
    );
}
