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
// PDF — build a real minimal PDF with lopdf, then round-trip it
// through the extractor. Catches regressions in both the Info-dict
// walk and the date-normalization path.
// ---------------------------------------------------------------------------

/// Build a minimal PDF with a known Info dictionary, an /ID array,
/// and optionally an XMP stream. Uses lopdf's builder so the
/// resulting bytes match what a real producer would emit
/// (cross-reference table, correct offsets, valid trailer).
fn build_pdf(author: &str, producer: &str, id_first: &[u8], xmp: Option<&str>) -> Vec<u8> {
    use lopdf::{dictionary, Document, Object, Stream};

    let mut doc = Document::with_version("1.7");

    // /Pages — required by spec, empty.
    let pages_id = doc.new_object_id();
    doc.set_object(
        pages_id,
        dictionary! {
            "Type" => "Pages",
            "Kids" => Object::Array(vec![]),
            "Count" => 0_i64,
        },
    );

    // /Info — Author + Producer + CreationDate.
    let info_id = doc.add_object(dictionary! {
        "Author" => Object::string_literal(author.to_string()),
        "Producer" => Object::string_literal(producer.to_string()),
        "CreationDate" => Object::string_literal("D:20260423194200Z"),
    });

    // /Catalog — points at Pages, optionally at an XMP Metadata stream.
    let mut catalog = dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    };
    if let Some(xmp_xml) = xmp {
        let xmp_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "Metadata",
                "Subtype" => "XML",
            },
            xmp_xml.as_bytes().to_vec(),
        ));
        catalog.set(*b"Metadata", Object::Reference(xmp_id));
    }
    let catalog_id = doc.add_object(catalog);

    doc.trailer.set("Root", catalog_id);
    doc.trailer.set("Info", info_id);

    // /ID — two 16-byte blobs. Test checks the hex round-trip.
    let id_second = b"0123456789ABCDEF";
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::string_literal(id_first.to_vec()),
            Object::string_literal(id_second.to_vec()),
        ]),
    );

    let mut buf = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

#[test]
fn pdf_info_dict_populates_fields() {
    let bytes = build_pdf("Jane Analyst", "siphon-test 1.0", b"ABCDEF0123456789", None);

    let mut meta = pdf::extract(&bytes).unwrap();
    meta.kind = FileKind::Pdf;

    assert_eq!(meta.creator.as_deref(), Some("Jane Analyst"));
    assert_eq!(meta.application.as_deref(), Some("siphon-test 1.0"));
    // CreationDate normalizes D:20260423194200Z → 2026-04-23T19:42:00Z
    assert_eq!(
        meta.created_at.as_deref(),
        Some("2026-04-23T19:42:00Z"),
        "D: prefix + trailing Z must normalise to ISO-8601"
    );

    // /ID first token → lower-case hex of the bytes.
    let (id0, id1) = meta.pdf_doc_id.expect("/ID must be populated");
    assert_eq!(id0, "41424344454630313233343536373839"); // "ABCDEF0123456789" hex
    assert_eq!(id1, "30313233343536373839414243444546"); // "0123456789ABCDEF" hex
}

#[test]
fn pdf_xmp_parser_extracts_adobe_metadata() {
    // Test the XMP parser directly. The end-to-end PDF round-trip
    // through lopdf's Metadata stream is left to real producers —
    // what we care about here is the RDF/XML walk logic.
    let xmp = r#"<?xpacket begin='' id=''?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description
     xmlns:xmp="http://ns.adobe.com/xap/1.0/"
     xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
     xmlns:dc="http://purl.org/dc/elements/1.1/">
   <xmp:CreatorTool>Acme Writer 3.2</xmp:CreatorTool>
   <xmpMM:DocumentID>uuid:abc123</xmpMM:DocumentID>
   <xmpMM:InstanceID>uuid:def456</xmpMM:InstanceID>
   <dc:title>Leaked report</dc:title>
   <dc:creator>Acme Author</dc:creator>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>"#;

    let mut meta = FileMetadata::default();
    pdf::parse_xmp(xmp, &mut meta);

    // CreatorTool → application.
    assert_eq!(meta.application.as_deref(), Some("Acme Writer 3.2"));
    assert_eq!(meta.creator.as_deref(), Some("Acme Author"));
    assert_eq!(meta.title.as_deref(), Some("Leaked report"));
    // DocumentID / InstanceID land in raw for attribution.
    assert_eq!(
        meta.raw.get("xmp:DocumentID").map(String::as_str),
        Some("uuid:abc123")
    );
    assert_eq!(
        meta.raw.get("xmp:InstanceID").map(String::as_str),
        Some("uuid:def456")
    );
}

#[test]
fn pdf_xmp_does_not_overwrite_populated_fields() {
    // assign_xmp uses if-let gates — once Info has populated a
    // field, XMP shouldn't clobber it even if the XMP disagrees.
    let mut meta = FileMetadata::default();
    meta.creator = Some("Jane (from Info)".to_string());

    let xmp = r#"<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:creator>Different (from XMP)</dc:creator>
    </rdf:Description>"#;

    pdf::parse_xmp(xmp, &mut meta);
    assert_eq!(meta.creator.as_deref(), Some("Jane (from Info)"));
}

#[test]
fn pdf_without_xmp_still_populates_info_fields() {
    let bytes = build_pdf("Alice", "pdf-writer", b"1234567890abcdef", None);
    let meta = pdf::extract(&bytes).unwrap();
    assert_eq!(meta.creator.as_deref(), Some("Alice"));
    // No XMP — nothing should be in the xmp:* raw entries.
    assert!(!meta.raw.keys().any(|k| k.starts_with("xmp:")));
}

#[test]
fn pdf_malformed_returns_error() {
    let err = pdf::extract(b"not a pdf at all").unwrap_err();
    assert!(matches!(err, ForensicsError::Malformed(_)));
}

// ---------------------------------------------------------------------------
// Legacy binary Office — build a tiny OLE Compound File with a
// SummaryInformation property set, then round-trip through the
// extractor. Uses the cfb crate for the OLE envelope and hand-
// assembles the property-set payload so the test exercises the
// extractor's real parse path.
// ---------------------------------------------------------------------------

fn build_ole_summary(author: &str, app_name: &str, title: &str) -> Vec<u8> {
    // Build the SummaryInformation stream payload first.
    let mut stream = Vec::new();

    // Property-set header (28 bytes):
    //   u16 byte order (0xFFFE)
    //   u16 version    (0)
    //   u32 OS         (win32 = 0x00020000 big-endian in spec, but
    //                   the actual file bytes are LE; 0x00000002 works)
    //   u8[16] CLSID   (all zero)
    //   u32 section count (1)
    stream.extend_from_slice(&[0xFE, 0xFF, 0x00, 0x00]);
    stream.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]);
    stream.extend_from_slice(&[0u8; 16]);
    stream.extend_from_slice(&1u32.to_le_bytes());

    // Section descriptor: 16-byte FMTID + u32 offset.
    //   FMTID = F29F85E0-4FF9-1068-AB91-08002B27B3D9 (SummaryInfo).
    let fmtid: [u8; 16] = [
        0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3,
        0xD9,
    ];
    stream.extend_from_slice(&fmtid);
    // Section starts right after the descriptor (offset 48 from
    // start of stream).
    let section_offset: u32 = 28 + 20;
    stream.extend_from_slice(&section_offset.to_le_bytes());

    // Build the section in a scratch buffer so we know its size.
    let mut section = Vec::new();
    // u32 size (patched below), u32 property count
    section.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    section.extend_from_slice(&3u32.to_le_bytes()); // 3 properties

    // We'll write the property-ID / offset table, then append the
    // values. Offsets are relative to the section start.
    // Reserve 3 × 8 bytes for the PID/offset table.
    let table_start = section.len();
    section.extend_from_slice(&[0u8; 3 * 8]);

    // Helper: append a VT_LPSTR and return its offset-from-section-start.
    let append_lpstr = |section: &mut Vec<u8>, text: &str| -> u32 {
        let off = section.len() as u32;
        section.extend_from_slice(&(VT_LPSTR_TAG).to_le_bytes());
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        section.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        section.extend_from_slice(&bytes);
        // 4-byte pad
        while section.len() % 4 != 0 {
            section.push(0);
        }
        off
    };

    let title_off = append_lpstr(&mut section, title);
    let author_off = append_lpstr(&mut section, author);
    let app_off = append_lpstr(&mut section, app_name);

    // Patch the table.
    let entries: [(u32, u32); 3] = [
        (PID_TITLE_CONST, title_off),
        (PID_AUTHOR_CONST, author_off),
        (PID_APP_NAME_CONST, app_off),
    ];
    for (i, (pid, off)) in entries.iter().enumerate() {
        let base = table_start + i * 8;
        section[base..base + 4].copy_from_slice(&pid.to_le_bytes());
        section[base + 4..base + 8].copy_from_slice(&off.to_le_bytes());
    }

    // Patch the section's leading size field.
    let size = section.len() as u32;
    section[0..4].copy_from_slice(&size.to_le_bytes());

    stream.extend_from_slice(&section);

    // Now wrap the payload in a CFB container.
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
    {
        let mut st = comp.create_stream("\u{5}SummaryInformation").unwrap();
        st.write_all(&stream).unwrap();
    }
    comp.flush().unwrap();
    buf.into_inner()
}

// VT_LPSTR tag (0x001E) + 2-byte padding — encoded as a u32 for
// direct little-endian append.
const VT_LPSTR_TAG: u32 = 0x0000_001E;
const PID_TITLE_CONST: u32 = 0x02;
const PID_AUTHOR_CONST: u32 = 0x04;
const PID_APP_NAME_CONST: u32 = 0x12;

#[test]
fn legacy_office_summary_info_roundtrip() {
    let bytes = build_ole_summary("Alice Analyst", "Microsoft Word 97", "Confidential Memo");
    let meta = legacy_office::extract(&bytes).unwrap();

    assert_eq!(meta.creator.as_deref(), Some("Alice Analyst"));
    assert_eq!(meta.title.as_deref(), Some("Confidential Memo"));
    assert_eq!(meta.application.as_deref(), Some("Microsoft Word 97"));
}

#[test]
fn legacy_office_garbage_returns_malformed() {
    let err = legacy_office::extract(b"not an OLE file").unwrap_err();
    assert!(matches!(err, ForensicsError::Malformed(_)));
}

#[test]
fn filekind_from_path_covers_legacy_extensions() {
    use std::path::Path;
    assert_eq!(FileKind::from_path(Path::new("foo.doc")), FileKind::Doc);
    assert_eq!(FileKind::from_path(Path::new("bar.xls")), FileKind::Xls);
    assert_eq!(FileKind::from_path(Path::new("baz.PPT")), FileKind::Ppt);
    assert_eq!(FileKind::from_path(Path::new("quux.docx")), FileKind::Docx);
}
