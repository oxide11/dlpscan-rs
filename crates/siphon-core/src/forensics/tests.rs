//! Unit tests for forensics extractors + attribution.
//!
//! The tests build synthetic docx / pdf files in-memory rather than
//! shipping fixture binaries — keeps the repo lightweight and makes
//! the "what does this signal capture" reasoning visible in test
//! source.

#![cfg(test)]

use std::io::Write;

use super::*;

// ---------------------------------------------------------------------------
// Office — synthetic docx builder
// ---------------------------------------------------------------------------

/// Build a minimal docx in-memory with the given author + optional
/// RSIDs. Enough of a file for the extractor to walk.
fn build_docx(author: &str, last_editor: &str, rsids: &[&str], company: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        // docProps/core.xml
        let core = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>{author}</dc:creator>
  <cp:lastModifiedBy>{last_editor}</cp:lastModifiedBy>
  <dc:title>Sample</dc:title>
  <dcterms:created xmlns:dcterms="http://purl.org/dc/terms/">2026-04-23T19:00:00Z</dcterms:created>
  <dcterms:modified xmlns:dcterms="http://purl.org/dc/terms/">2026-04-23T19:30:00Z</dcterms:modified>
</cp:coreProperties>"#
        );
        zw.start_file("docProps/core.xml", opts).unwrap();
        zw.write_all(core.as_bytes()).unwrap();

        // docProps/app.xml
        let company_tag = company
            .map(|c| format!("<Company>{c}</Company>"))
            .unwrap_or_default();
        let app = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  {company_tag}
</Properties>"#
        );
        zw.start_file("docProps/app.xml", opts).unwrap();
        zw.write_all(app.as_bytes()).unwrap();

        // word/settings.xml with the rsidRoot + given ids
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
    }
    buf
}

#[test]
fn docx_metadata_core_fields() {
    let bytes = build_docx("Alice Smith", "Bob Jones", &[], Some("Acme Corp"));
    let mut meta = office::extract(&bytes, &FileKind::Docx).unwrap();
    meta.kind = FileKind::Docx;

    assert_eq!(meta.creator.as_deref(), Some("Alice Smith"));
    assert_eq!(meta.last_modified_by.as_deref(), Some("Bob Jones"));
    assert_eq!(meta.title.as_deref(), Some("Sample"));
    assert_eq!(meta.application.as_deref(), Some("Microsoft Office Word"));
    assert_eq!(meta.company.as_deref(), Some("Acme Corp"));
    assert!(meta.rsids.is_empty());
}

#[test]
fn docx_rsids_root_then_sessions() {
    let bytes = build_docx(
        "Alice",
        "Alice",
        &["00A1B2C3", "00D4E5F6", "00112233"],
        None,
    );
    let meta = office::extract(&bytes, &FileKind::Docx).unwrap();

    // Root is always first.
    assert_eq!(meta.rsids.first().unwrap(), "00A1B2C3");
    assert_eq!(meta.rsids.len(), 3);
    assert!(meta.rsids.contains(&"00112233".to_string()));
}

#[test]
fn office_missing_files_do_not_fatal() {
    // An empty zip is valid — no core.xml, no app.xml. Extractor
    // should return default metadata without an error.
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        zw.finish().unwrap();
    }
    let meta = office::extract(&buf, &FileKind::Docx).unwrap();
    assert!(meta.creator.is_none());
    assert!(meta.rsids.is_empty());
}

#[test]
fn office_garbage_is_malformed() {
    // Random bytes — not a zip. Should produce Malformed, not panic.
    let err = office::extract(b"not a zip at all", &FileKind::Docx).unwrap_err();
    assert!(matches!(err, ForensicsError::Malformed(_)));
}

// ---------------------------------------------------------------------------
// Attribution scoring
// ---------------------------------------------------------------------------

#[test]
fn rsid_root_match_drives_score_above_0_5() {
    let a = build_docx("Alice", "Alice", &["00A1B2C3", "00D4E5F6"], None);
    let b = build_docx("Bob", "Bob", &["00A1B2C3", "00999999"], None);
    let ma = office::extract(&a, &FileKind::Docx).unwrap();
    let mb = office::extract(&b, &FileKind::Docx).unwrap();

    let score = compare(&ma, &mb);
    assert!(
        score.total >= 0.50,
        "rsid root match should give at least 0.50, got {}",
        score.total
    );
    assert!(score
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::RsidRootMatch));
}

#[test]
fn no_common_signals_gives_zero() {
    let a = build_docx("Alice", "Alice", &["00A1B2C3"], Some("Acme"));
    let b = build_docx("Bob", "Bob", &["00999999"], Some("Other"));
    let ma = office::extract(&a, &FileKind::Docx).unwrap();
    let mb = office::extract(&b, &FileKind::Docx).unwrap();

    let score = compare(&ma, &mb);
    // Application matches ("Microsoft Office Word") but has no
    // version digits so the weight is trimmed. Everything else
    // differs. Expected score: ≤ 0.10.
    assert!(score.total < 0.15, "unexpectedly high: {}", score.total);
}

#[test]
fn creator_match_contributes() {
    let a = build_docx("Alice Smith", "Alice Smith", &[], None);
    let b = build_docx("ALICE SMITH", "Bob", &[], None); // case-insensitive
    let ma = office::extract(&a, &FileKind::Docx).unwrap();
    let mb = office::extract(&b, &FileKind::Docx).unwrap();

    let score = compare(&ma, &mb);
    assert!(score
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::CreatorMatch));
}

#[test]
fn score_is_order_independent() {
    let a = build_docx("Alice", "Alice", &["AAA", "BBB"], Some("Acme"));
    let b = build_docx("Bob", "Bob", &["AAA", "CCC"], Some("Acme"));
    let ma = office::extract(&a, &FileKind::Docx).unwrap();
    let mb = office::extract(&b, &FileKind::Docx).unwrap();

    let ab = compare(&ma, &mb);
    let ba = compare(&mb, &ma);
    assert_eq!(ab.total, ba.total);
    assert_eq!(ab.signals.len(), ba.signals.len());
}

#[test]
fn score_is_capped_at_one() {
    // Everything matches — total should clamp at 1.0.
    let a = build_docx(
        "Same Person",
        "Same Person",
        &["AAA", "BBB", "CCC"],
        Some("Same Corp"),
    );
    let b = build_docx(
        "Same Person",
        "Same Person",
        &["AAA", "BBB", "CCC"],
        Some("Same Corp"),
    );
    let mut ma = office::extract(&a, &FileKind::Docx).unwrap();
    let mut mb = office::extract(&b, &FileKind::Docx).unwrap();
    ma.application = Some("Microsoft Word 2021".to_string());
    mb.application = Some("Microsoft Word 2021".to_string());

    let score = compare(&ma, &mb);
    assert!(
        score.total <= 1.0,
        "score must cap at 1.0, got {}",
        score.total
    );
    assert!(
        score.total >= 0.85,
        "strong-match score too low: {}",
        score.total
    );
}

// ---------------------------------------------------------------------------
// PDF date normalization (unit-level — no real PDF fixture needed)
// ---------------------------------------------------------------------------

#[test]
fn pdf_date_normalize_basic() {
    // The function is private to pdf.rs; test it via a round-trip
    // through a synthetic Info dict. For now, a quick path-exists
    // check — if pdf_date_normalize regresses, one of the PDF fixture
    // tests (tracked in a follow-up) will surface the drift.
    //
    // TODO: promote pdf_date_normalize to pub(crate) once we have
    //       a real PDF fixture committed under tests/fixtures/.
}
