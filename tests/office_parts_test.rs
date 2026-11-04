//! The parts of an Office package that are not the body.
//!
//! A value does not have to be in a cell or on a slide to be in the file. It
//! can sit in a cell comment, a text box drawn over the sheet, a slide's
//! speaker notes, a review comment, a SmartArt diagram, or an Excel table
//! embedded in a Word document — and until 2026-10-19 every one of those
//! read as clean, because the OOXML reader opened `xl/worksheets/*` and
//! `ppt/slides/*` and nothing else. Each test here plants a value in one of
//! those places and asks the extractor for it.
//!
//! These live outside the conformance matrix because the matrix asks each
//! format exactly five questions, and "is the comment read" is a sixth. The
//! fixtures are built by hand so that each test shows the part it is about.

use std::io::Write;

const SSN: &str = "219-09-9999";
const CARD: &str = "4111111111111111";

const OOXML_DOC_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

/// A deflated ZIP of the given entries. Content types and relationships are
/// not what these tests are about, so the fixtures carry only the parts the
/// reader looks at plus the minimum that makes them a package.
fn package(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            z.start_file(*name, opts).unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

fn rels(target: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{OOXML_DOC_REL}" Target="{target}"/></Relationships>"#
    )
}

fn worksheet(cells: &[&str]) -> String {
    let rows: String = cells
        .iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                r#"<row r="{n}"><c r="A{n}" t="inlineStr"><is><t>{v}</t></is></c></row>"#,
                n = i + 1
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData></worksheet>"#
    )
}

fn slide(text: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#
    )
}

/// A workbook with one innocuous sheet plus whatever extra parts the test adds.
fn xlsx_with(extra: &[(&str, &[u8])]) -> Vec<u8> {
    let r = rels("xl/workbook.xml");
    let wb = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>"#;
    let sheet = worksheet(&["Region", "EMEA"]);
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("_rels/.rels", r.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes()),
    ];
    entries.extend_from_slice(extra);
    package(&entries)
}

/// A deck with one innocuous slide plus whatever extra parts the test adds.
fn pptx_with(extra: &[(&str, &[u8])]) -> Vec<u8> {
    let r = rels("ppt/presentation.xml");
    let pres = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>"#;
    let s = slide("Roadmap");
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("_rels/.rels", r.as_bytes()),
        ("ppt/presentation.xml", pres.as_bytes()),
        ("ppt/slides/slide1.xml", s.as_bytes()),
    ];
    entries.extend_from_slice(extra);
    package(&entries)
}

/// A document with one innocuous paragraph plus whatever extra parts the
/// test adds.
fn docx_with(extra: &[(&str, &[u8])]) -> Vec<u8> {
    let r = rels("word/document.xml");
    let doc = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly summary</w:t></w:r></w:p></w:body></w:document>"#;
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("_rels/.rels", r.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
    ];
    entries.extend_from_slice(extra);
    package(&entries)
}

fn extract(bytes: &[u8], suffix: &str) -> siphon::extractors::ExtractionResult {
    let mut f = tempfile::Builder::new()
        .prefix("siphon-office-parts-")
        .suffix(suffix)
        .tempfile()
        .unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    siphon::extractors::extract_text(f.path().to_str().unwrap()).unwrap()
}

fn assert_complete(result: &siphon::extractors::ExtractionResult) {
    assert!(
        result.inspection.unread_reasons().is_empty(),
        "a well-formed package must read as complete, got: {}",
        result.inspection.describe().join("\n")
    );
}

// ---------------------------------------------------------------------------
// xlsx
// ---------------------------------------------------------------------------

#[test]
fn xlsx_cell_comment_is_read() {
    let comments = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><authors><author>Reviewer</author></authors><commentList><comment ref="B2" authorId="0"><text><r><rPr><b/><sz val="9"/><rFont val="Tahoma"/></rPr><t>Reviewer:</t></r><r><t xml:space="preserve"> customer SSN {SSN}</t></r></text></comment></commentList></comments>"#
    );
    let bytes = xlsx_with(&[("xl/comments1.xml", comments.as_bytes())]);
    let result = extract(&bytes, ".xlsx");
    assert_eq!(result.format, "xlsx");
    assert!(
        result.text.contains(SSN),
        "the comment's text is part of the workbook; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn xlsx_adjacent_comments_do_not_run_together() {
    // Two comments are two notes. Without a boundary between them the first
    // value's last digit runs into the next comment's first letter, which is
    // enough to break a word-bounded pattern.
    let comments = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><authors><author>A</author></authors><commentList><comment ref="A1" authorId="0"><text><t>{SSN}</t></text></comment><comment ref="A2" authorId="0"><text><t>next</t></text></comment></commentList></comments>"#
    );
    let bytes = xlsx_with(&[("xl/comments1.xml", comments.as_bytes())]);
    let result = extract(&bytes, ".xlsx");
    assert!(
        result.text.contains(&format!("{SSN}\nnext")),
        "a comment boundary must be a line boundary; got: {:?}",
        result.text
    );
}

#[test]
fn xlsx_threaded_comment_is_read() {
    let threaded = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ThreadedComments xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"><threadedComment ref="C3" dT="2026-10-19T12:00:00Z" personId="{{0}}" id="{{1}}"><text>Card on file {CARD}</text></threadedComment></ThreadedComments>"#
    );
    let bytes = xlsx_with(&[(
        "xl/threadedComments/threadedComment1.xml",
        threaded.as_bytes(),
    )]);
    let result = extract(&bytes, ".xlsx");
    assert!(
        result.text.contains(CARD),
        "threaded comments are comments; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn xlsx_drawing_text_box_is_read() {
    let drawing = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><xdr:twoCellAnchor><xdr:sp><xdr:txBody><a:bodyPr/><a:p><a:r><a:t>Note: SSN {SSN}</a:t></a:r></a:p></xdr:txBody></xdr:sp></xdr:twoCellAnchor></xdr:wsDr>"#
    );
    let bytes = xlsx_with(&[("xl/drawings/drawing1.xml", drawing.as_bytes())]);
    let result = extract(&bytes, ".xlsx");
    assert!(
        result.text.contains(SSN),
        "a text box over the sheet is on the sheet; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn xlsx_chart_cache_is_not_read() {
    // A chart's data cache repeats cells the worksheet pass already read,
    // with no separators between the numbers. Reading it would invent digit
    // runs that appear in no cell.
    let chart = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart><c:plotArea><c:barChart><c:ser><c:val><c:numRef><c:numCache><c:pt idx="0"><c:v>4111</c:v></c:pt><c:pt idx="1"><c:v>1111</c:v></c:pt><c:pt idx="2"><c:v>1111</c:v></c:pt><c:pt idx="3"><c:v>1111</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser></c:barChart></c:plotArea></c:chart></c:chartSpace>"#;
    let bytes = xlsx_with(&[("xl/charts/chart1.xml", chart.as_bytes())]);
    let result = extract(&bytes, ".xlsx");
    assert!(
        !result.text.contains("4111"),
        "chart caches stay unread; got: {:?}",
        result.text
    );
}

// ---------------------------------------------------------------------------
// pptx
// ---------------------------------------------------------------------------

#[test]
fn pptx_speaker_notes_are_read() {
    let notes = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Mention the pilot account, card {CARD}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>"#
    );
    let bytes = pptx_with(&[("ppt/notesSlides/notesSlide1.xml", notes.as_bytes())]);
    let result = extract(&bytes, ".pptx");
    assert_eq!(result.format, "pptx");
    assert!(
        result.text.contains(CARD),
        "speaker notes ship with the deck; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn pptx_legacy_comment_is_read() {
    let comments = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:cmLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cm authorId="0" dt="2026-10-19T12:00:00" idx="1"><p:pos x="10" y="10"/><p:text>SSN {SSN}</p:text></p:cm><p:cm authorId="0" dt="2026-10-19T12:01:00" idx="2"><p:pos x="10" y="10"/><p:text>next</p:text></p:cm></p:cmLst>"#
    );
    let bytes = pptx_with(&[("ppt/comments/comment1.xml", comments.as_bytes())]);
    let result = extract(&bytes, ".pptx");
    assert!(
        result.text.contains(&format!("{SSN}\nnext")),
        "a review comment is read, and ends where it ends; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn pptx_modern_comment_is_read() {
    let comments = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p188:cmLst xmlns:p188="http://schemas.microsoft.com/office/powerpoint/2018/8/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p188:cm id="{{1}}" authorId="{{0}}" created="2026-10-19T12:00:00"><p188:txBody><a:p><a:r><a:t>card {CARD}</a:t></a:r></a:p></p188:txBody></p188:cm></p188:cmLst>"#
    );
    let bytes = pptx_with(&[("ppt/comments/modernComment_100_1.xml", comments.as_bytes())]);
    let result = extract(&bytes, ".pptx");
    assert!(
        result.text.contains(CARD),
        "the 2018 comment part is a comment too; got: {:?}",
        result.text
    );
}

#[test]
fn pptx_smartart_diagram_text_is_read() {
    let data = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<dgm:dataModel xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><dgm:ptLst><dgm:pt modelId="{{1}}"><dgm:t><a:bodyPr/><a:p><a:r><a:t>Owner SSN {SSN}</a:t></a:r></a:p></dgm:t></dgm:pt></dgm:ptLst></dgm:dataModel>"#
    );
    let bytes = pptx_with(&[("ppt/diagrams/data1.xml", data.as_bytes())]);
    let result = extract(&bytes, ".pptx");
    assert!(
        result.text.contains(SSN),
        "SmartArt text is slide text; got: {:?}",
        result.text
    );
}

// ---------------------------------------------------------------------------
// embedded objects
// ---------------------------------------------------------------------------

#[test]
fn docx_embedded_workbook_is_read() {
    let inner = xlsx_with(&[(
        "xl/worksheets/sheet2.xml",
        worksheet(&["card", CARD]).as_bytes(),
    )]);
    let bytes = docx_with(&[(
        "word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        inner.as_slice(),
    )]);
    let result = extract(&bytes, ".docx");
    assert_eq!(result.format, "docx");
    assert!(
        result.text.contains("Quarterly summary"),
        "the host document is still read; got: {:?}",
        result.text
    );
    assert!(
        result.text.contains(CARD),
        "an embedded workbook is part of the document; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn pptx_embedded_document_is_read() {
    let inner = docx_with(&[]);
    let bytes = pptx_with(&[(
        "ppt/embeddings/Microsoft_Word_Document1.docx",
        inner.as_slice(),
    )]);
    let result = extract(&bytes, ".pptx");
    assert!(
        result.text.contains("Quarterly summary"),
        "an embedded document is read; got: {:?}",
        result.text
    );
    assert_complete(&result);
}

#[test]
fn embedded_object_inside_an_embedded_object_is_reported_not_opened() {
    let innermost = docx_with(&[]);
    let middle = xlsx_with(&[(
        "xl/embeddings/Microsoft_Word_Document1.docx",
        innermost.as_slice(),
    )]);
    let bytes = docx_with(&[(
        "word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        middle.as_slice(),
    )]);
    let result = extract(&bytes, ".docx");
    assert!(
        !result.text.contains("Quarterly summary")
            || result.text.matches("Quarterly summary").count() == 1,
        "the innermost document must not be read; got: {:?}",
        result.text
    );
    let described = result.inspection.describe().join("\n");
    assert!(
        described.contains("Microsoft_Word_Document1.docx")
            && described.contains("Microsoft_Excel_Worksheet1.xlsx"),
        "the unopened object is named under the entry that held it; got: {described}"
    );
}

#[test]
fn embedded_object_that_is_not_a_package_is_named_and_is_not_a_gap() {
    // An OLE `.bin` is not something this reader opens. The host is read in
    // full; the object is named as `NotText`, the informational reason, so
    // the inspection is incomplete (the object was not read) and has no gap
    // (nothing a fail-closed ingress should act on).
    let bytes = docx_with(&[(
        "word/embeddings/oleObject1.bin",
        b"\xd0\xcf\x11\xe0 not a zip",
    )]);
    let result = extract(&bytes, ".docx");
    assert!(result.text.contains("Quarterly summary"));
    assert!(!result.inspection.is_complete());
    assert!(
        !result.inspection.has_gap(),
        "a passed-over object is not a gap: {}",
        result.inspection.describe().join("\n")
    );
    assert!(
        matches!(
            result.inspection.unread_reasons(),
            [siphon::Unread::NotText { unit }] if unit == "entry word/embeddings/oleObject1.bin"
        ),
        "{:?}",
        result.inspection
    );
}

#[test]
fn document_artwork_is_not_listed() {
    // A picture under `word/media/` is the document's own artwork, not an
    // object pasted into it; listing it would make every illustrated docx
    // incomplete for no one's benefit.
    let bytes = docx_with(&[("word/media/image1.png", b"\x89PNG not really")]);
    let result = extract(&bytes, ".docx");
    assert!(result.text.contains("Quarterly summary"));
    assert_complete(&result);
}

#[test]
fn embedded_entry_that_is_not_a_zip_is_reported() {
    // Named like a package, not one. The reader says it could not open it
    // rather than passing it off as read.
    let bytes = docx_with(&[(
        "word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        b"not a zip at all",
    )]);
    let result = extract(&bytes, ".docx");
    assert!(result.text.contains("Quarterly summary"));
    let described = result.inspection.describe().join("\n");
    assert!(
        described.contains("Microsoft_Excel_Worksheet1.xlsx"),
        "an embedded object that did not open is reported; got: {described}"
    );
}
