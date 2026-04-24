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

// Build a minimal .doc OLE compound file with a SummaryInformation
// stream carrying known Author + Title + AppName. The test path
// rides through extract_metadata's FileKind dispatch so a regression
// in the .doc / .xls / .ppt wiring shows up immediately.
fn write_legacy_doc(dir: &tempfile::TempDir, name: &str, author: &str, title: &str) -> PathBuf {
    let path = dir.path().join(name);

    // Hand-rolled OSPS property set — same layout as the
    // siphon_core tests, scaled down to two properties.
    let mut stream = Vec::new();
    stream.extend_from_slice(&[0xFE, 0xFF, 0x00, 0x00]);
    stream.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]);
    stream.extend_from_slice(&[0u8; 16]);
    stream.extend_from_slice(&1u32.to_le_bytes());

    let fmtid: [u8; 16] = [
        0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3,
        0xD9,
    ];
    stream.extend_from_slice(&fmtid);
    stream.extend_from_slice(&(28u32 + 20u32).to_le_bytes());

    let mut section = Vec::new();
    section.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    section.extend_from_slice(&2u32.to_le_bytes()); // 2 properties
    let table_start = section.len();
    section.extend_from_slice(&[0u8; 2 * 8]);

    let append_lpstr = |section: &mut Vec<u8>, text: &str| -> u32 {
        let off = section.len() as u32;
        section.extend_from_slice(&0x0000_001E_u32.to_le_bytes()); // VT_LPSTR
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        section.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        section.extend_from_slice(&bytes);
        while section.len() % 4 != 0 {
            section.push(0);
        }
        off
    };

    let title_off = append_lpstr(&mut section, title);
    let author_off = append_lpstr(&mut section, author);
    // PID_TITLE = 0x02, PID_AUTHOR = 0x04.
    section[table_start..table_start + 4].copy_from_slice(&0x02u32.to_le_bytes());
    section[table_start + 4..table_start + 8].copy_from_slice(&title_off.to_le_bytes());
    section[table_start + 8..table_start + 12].copy_from_slice(&0x04u32.to_le_bytes());
    section[table_start + 12..table_start + 16].copy_from_slice(&author_off.to_le_bytes());

    let size = section.len() as u32;
    section[0..4].copy_from_slice(&size.to_le_bytes());
    stream.extend_from_slice(&section);

    let file = std::fs::File::create(&path).unwrap();
    let mut comp = cfb::CompoundFile::create(file).unwrap();
    {
        let mut st = comp.create_stream("\u{5}SummaryInformation").unwrap();
        st.write_all(&stream).unwrap();
    }
    comp.flush().unwrap();

    path
}

#[test]
fn extract_metadata_handles_legacy_binary_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_legacy_doc(&tmp, "legacy.doc", "Ada Lovelace", "Secret Report");

    let meta = extract_metadata(&path).unwrap();
    assert_eq!(meta.kind, FileKind::Doc);
    assert_eq!(meta.creator.as_deref(), Some("Ada Lovelace"));
    assert_eq!(meta.title.as_deref(), Some("Secret Report"));
    assert_eq!(meta.content_hash.len(), 64);
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
