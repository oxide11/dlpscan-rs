//! End-to-end forensics integration tests.
//!
//! Exercises `siphon_core::forensics::extract_metadata` against real
//! on-disk files (built inside each test), and the attribution
//! comparison end-to-end. Complements the module's unit tests by
//! going through the public API + filesystem path.

#![cfg(feature = "forensics")]

use std::io::Write;
use std::path::PathBuf;

use siphon_core::forensics::{
    compare, extract_metadata, AttributionScore, FileKind, FileMetadata, SignalKind,
};

// Build a minimal .docx with known metadata + RSIDs, write it to a
// temp file, return the path. Uses the same scaffolding as the unit
// tests — duplicated here so the integration test stays self-
// contained and doesn't rely on crate-internal helpers.
fn write_docx(
    dir: &tempfile::TempDir,
    name: &str,
    author: &str,
    last_editor: &str,
    rsids: &[&str],
    company: Option<&str>,
) -> PathBuf {
    let path = dir.path().join(name);
    let file = std::fs::File::create(&path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let core = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>{author}</dc:creator>
  <cp:lastModifiedBy>{last_editor}</cp:lastModifiedBy>
</cp:coreProperties>"#
    );
    zw.start_file("docProps/core.xml", opts).unwrap();
    zw.write_all(core.as_bytes()).unwrap();

    let company_tag = company
        .map(|c| format!("<Company>{c}</Company>"))
        .unwrap_or_default();
    let app = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Word 2021</Application>
  {company_tag}
</Properties>"#
    );
    zw.start_file("docProps/app.xml", opts).unwrap();
    zw.write_all(app.as_bytes()).unwrap();

    if !rsids.is_empty() {
        let mut settings = String::from(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:rsids>"#,
        );
        settings.push_str(&format!("<w:rsidRoot w:val=\"{}\"/>", rsids[0]));
        for r in &rsids[1..] {
            settings.push_str(&format!("<w:rsid w:val=\"{r}\"/>"));
        }
        settings.push_str("</w:rsids></w:settings>");
        zw.start_file("word/settings.xml", opts).unwrap();
        zw.write_all(settings.as_bytes()).unwrap();
    }
    zw.finish().unwrap();
    path
}

#[test]
fn extract_metadata_via_public_api_populates_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_docx(
        &tmp,
        "leaked.docx",
        "Jane Analyst",
        "Jane Analyst",
        &["DEADBEEF"],
        Some("Acme Corp"),
    );

    let meta: FileMetadata = extract_metadata(&path).unwrap();

    assert_eq!(meta.kind, FileKind::Docx);
    assert_eq!(meta.creator.as_deref(), Some("Jane Analyst"));
    assert_eq!(meta.application.as_deref(), Some("Microsoft Word 2021"));
    assert_eq!(meta.company.as_deref(), Some("Acme Corp"));
    assert_eq!(meta.rsids, vec!["DEADBEEF".to_string()]);
    assert_eq!(meta.size_bytes, std::fs::metadata(&path).unwrap().len());
    assert_eq!(meta.content_hash.len(), 64, "sha256 hex should be 64 chars");
}

#[test]
fn extract_metadata_rejects_unknown_extension() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("whatever.bin");
    std::fs::write(&path, b"garbage").unwrap();

    let err = extract_metadata(&path).unwrap_err();
    assert!(
        format!("{err}").contains("unknown file kind"),
        "expected unknown-kind error, got: {err}"
    );
}

#[test]
fn attribution_flags_shared_rsid_root_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    let doc1 = write_docx(
        &tmp,
        "payroll-q1.docx",
        "Alice",
        "Alice",
        &["AAA111", "BBB222"],
        Some("Acme"),
    );
    let doc2 = write_docx(
        &tmp,
        "payroll-q2.docx",
        "Bob",
        "Bob",
        &["AAA111", "CCC333"], // same root as doc1
        Some("Different Corp"),
    );

    let m1 = extract_metadata(&doc1).unwrap();
    let m2 = extract_metadata(&doc2).unwrap();

    let score: AttributionScore = compare(&m1, &m2);
    assert!(score.total >= 0.50);
    assert!(score
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::RsidRootMatch));
}

#[test]
fn attribution_score_serializes_to_json() {
    let tmp = tempfile::tempdir().unwrap();
    let p1 = write_docx(&tmp, "a.docx", "Alice", "Alice", &["AAA", "BBB"], None);
    let p2 = write_docx(&tmp, "b.docx", "Alice", "Alice", &["AAA", "CCC"], None);

    let m1 = extract_metadata(&p1).unwrap();
    let m2 = extract_metadata(&p2).unwrap();
    let score = compare(&m1, &m2);

    // The CLI's --json mode relies on serde_json::to_string working
    // cleanly over the whole score — any Option field that isn't
    // Serialize would break the round-trip.
    let json = serde_json::to_string(&score).unwrap();
    let back: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(back["total"].as_f64().unwrap() > 0.0);
    assert!(back["signals"].is_array());
}
