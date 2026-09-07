//! Fixture builders.
//!
//! Every fixture the matrix uses is constructed here, in-process, so nothing
//! binary is committed to the repository. Two of these are more work than
//! they look — [`pdf`] computes a real cross-reference table because
//! `pdf-extract` rejects a PDF whose offsets do not resolve, and [`png`]
//! emits valid zlib using stored deflate blocks so no encoder dependency is
//! needed. Both are worth it: a fixture you can read is a fixture someone
//! can fix.

use std::io::Write as _;

/// A ZIP with the given entries, stored uncompressed so the bytes stay
/// greppable and a truncation lands somewhere predictable.
pub fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(entries, zip::CompressionMethod::Stored)
}

/// A deflated ZIP — the shape a real Office file has, and the one where a
/// byte-level scan of the container finds nothing.
pub fn zip_deflated(entries: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(entries, zip::CompressionMethod::Deflated)
}

fn zip_with(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default().compression_method(method);
        for (name, data) in entries {
            z.start_file::<_, ()>(*name, opts)
                .expect("fixture zip entry");
            z.write_all(data).expect("fixture zip write");
        }
        z.finish().expect("fixture zip finish");
    }
    buf.into_inner()
}

fn content_types(overrides: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
{overrides}
</Types>"#
    )
}

fn rels(target: &str, ty: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="{ty}" Target="{target}"/>
</Relationships>"#
    )
}

const OOXML_DOC_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

/// A DOCX with one paragraph per entry.
pub fn docx(paragraphs: &[&str]) -> Vec<u8> {
    let body: String = paragraphs
        .iter()
        .map(|p| format!("<w:p><w:r><w:t xml:space=\"preserve\">{p}</w:t></w:r></w:p>"))
        .collect();
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>{body}</w:body></w:document>"#
    );
    let ct = content_types(
        r#"<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>"#,
    );
    let r = rels("word/document.xml", OOXML_DOC_REL);
    zip_deflated(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", r.as_bytes()),
        ("word/document.xml", document.as_bytes()),
    ])
}

/// An XLSX with one sheet per entry, each a single column of inline strings.
///
/// Inline (`t="inlineStr"`) rather than the shared-string table so the
/// fixture stays readable in this file; calamine reads both.
pub fn xlsx(sheets: &[(&str, &[&str])]) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let sheet_overrides: String = (1..=sheets.len())
        .map(|i| format!(
            r#"<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#
        ))
        .collect();
    entries.push((
        "[Content_Types].xml".into(),
        content_types(&format!(
            r#"<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>{sheet_overrides}"#
        ))
        .into_bytes(),
    ));
    entries.push((
        "_rels/.rels".into(),
        rels("xl/workbook.xml", OOXML_DOC_REL).into_bytes(),
    ));

    let sheet_tags: String = sheets
        .iter()
        .enumerate()
        .map(|(i, (name, _))| {
            format!(
                r#"<sheet name="{name}" sheetId="{n}" r:id="rId{n}"/>"#,
                n = i + 1
            )
        })
        .collect();
    entries.push((
        "xl/workbook.xml".into(),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>{sheet_tags}</sheets></workbook>"#
        )
        .into_bytes(),
    ));

    let sheet_rels: String = (1..=sheets.len())
        .map(|i| format!(
            r#"<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>"#
        ))
        .collect();
    entries.push((
        "xl/_rels/workbook.xml.rels".into(),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{sheet_rels}</Relationships>"#
        )
        .into_bytes(),
    ));

    for (i, (_, rows)) in sheets.iter().enumerate() {
        let body: String = rows
            .iter()
            .enumerate()
            .map(|(r, v)| {
                format!(
                    r#"<row r="{n}"><c r="A{n}" t="inlineStr"><is><t xml:space="preserve">{v}</t></is></c></row>"#,
                    n = r + 1
                )
            })
            .collect();
        entries.push((
            format!("xl/worksheets/sheet{}.xml", i + 1),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>{body}</sheetData></worksheet>"#
            )
            .into_bytes(),
        ));
    }

    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    zip_deflated(&refs)
}

/// A PPTX with one slide per entry.
pub fn pptx(slides: &[&str]) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let overrides: String = (1..=slides.len())
        .map(|i| format!(
            r#"<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>"#
        ))
        .collect();
    entries.push((
        "[Content_Types].xml".into(),
        content_types(&format!(
            r#"<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>{overrides}"#
        ))
        .into_bytes(),
    ));
    entries.push((
        "_rels/.rels".into(),
        rels("ppt/presentation.xml", OOXML_DOC_REL).into_bytes(),
    ));
    entries.push((
        "ppt/presentation.xml".into(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>"#
            .to_vec(),
    ));

    for (i, text) in slides.iter().enumerate() {
        entries.push((
            format!("ppt/slides/slide{}.xml", i + 1),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
 xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:sp><p:txBody>
<a:p><a:r><a:t>{text}</a:t></a:r></a:p>
</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#
            )
            .into_bytes(),
        ));
    }

    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    zip_deflated(&refs)
}

/// An OpenDocument file (`odt`/`ods`/`odp`) — a ZIP whose `content.xml` holds
/// the text. `mimetype` must be the first entry and stored, per the ODF spec.
pub fn odf(mime: &str, paragraphs: &[&str]) -> Vec<u8> {
    let body: String = paragraphs
        .iter()
        .map(|p| format!("<text:p>{p}</text:p>"))
        .collect();
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
 xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
<office:body><office:text>{body}</office:text></office:body>
</office:document-content>"#
    );

    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file::<_, ()>(
            "mimetype",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .expect("odf mimetype");
        z.write_all(mime.as_bytes()).expect("odf mimetype write");
        z.start_file::<_, ()>(
            "content.xml",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .expect("odf content");
        z.write_all(content.as_bytes()).expect("odf content write");
        z.finish().expect("odf finish");
    }
    buf.into_inner()
}

/// A single-page PDF with an uncompressed content stream and a correctly
/// computed cross-reference table.
///
/// The xref offsets are computed rather than faked because `pdf-extract`
/// refuses a PDF whose offsets do not resolve — which is exactly what makes
/// the `Damaged` slot meaningful: breaking the offsets is a real parse
/// failure, not a cosmetic one.
pub fn pdf(lines: &[&str]) -> Vec<u8> {
    let text: String = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let escaped = l
                .replace('\\', r"\\")
                .replace('(', r"\(")
                .replace(')', r"\)");
            format!("BT /F1 12 Tf 72 {} Td ({escaped}) Tj ET\n", 720 - i * 18)
        })
        .collect();

    let objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!("<< /Length {} >>\nstream\n{text}endstream", text.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];

    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A MIME message. `parts` are `(content_type, transfer_encoding, body)`; an
/// empty slice produces a single-part text message.
pub fn eml(subject: &str, body: &str, parts: &[(&str, &str, &str)]) -> String {
    if parts.is_empty() {
        return format!(
            "From: sender@example.com\r\nTo: recipient@example.com\r\n\
             Subject: {subject}\r\nContent-Type: text/plain\r\n\r\n{body}\r\n"
        );
    }
    let mut out = format!(
        "From: sender@example.com\r\nTo: recipient@example.com\r\n\
         Subject: {subject}\r\n\
         Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n\
         --BOUNDARY\r\nContent-Type: text/plain\r\n\r\n{body}\r\n"
    );
    for (i, (ctype, enc, data)) in parts.iter().enumerate() {
        out.push_str(&format!(
            "--BOUNDARY\r\nContent-Type: {ctype}; name=\"part{i}\"\r\n\
             Content-Disposition: attachment; filename=\"part{i}\"\r\n\
             Content-Transfer-Encoding: {enc}\r\n\r\n{data}\r\n"
        ));
    }
    out.push_str("--BOUNDARY--\r\n");
    out
}

/// Base64 wrapped at 76 columns, as a mail client emits it.
///
/// The wrapping matters: unwrapped base64 is decoded incidentally by the
/// normalizer, so only the wrapped form exercises the attachment decode path
/// — which is where the bypass was.
pub fn b64_wrapped(data: &[u8]) -> String {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.encode(data);
    raw.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Plain base64, unwrapped.
pub fn b64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// An 8-bit greyscale PNG, `pixel(x, y)` supplying each sample.
///
/// Written by hand rather than through an encoder: the `image` crate is
/// behind the `barcode` feature, and a fixture builder that only exists when
/// the thing it tests is enabled is a fixture builder that cannot test the
/// disabled case. Compression uses stored deflate blocks, which is valid
/// zlib and needs no compressor.
pub fn png(w: u32, h: u32, pixel: impl Fn(u32, u32) -> u8) -> Vec<u8> {
    let mut raw = Vec::with_capacity(((w + 1) * h) as usize);
    for y in 0..h {
        raw.push(0u8); // filter type: none
        for x in 0..w {
            raw.push(pixel(x, y));
        }
    }

    let mut z = vec![0x78, 0x01]; // zlib header, no preset dict
    let chunks: Vec<&[u8]> = raw.chunks(65535).collect();
    for (i, block) in chunks.iter().enumerate() {
        z.push(u8::from(i + 1 == chunks.len())); // BFINAL, BTYPE=stored
        z.extend_from_slice(&(block.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        z.extend_from_slice(block);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // depth 8, greyscale, no interlace

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    out.extend_from_slice(&png_chunk(b"IDAT", &z));
    out.extend_from_slice(&png_chunk(b"IEND", b""));
    out
}

fn png_chunk(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    let mut body = tag.to_vec();
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// A 7z archive, via `sevenz-rust`'s writer.
#[cfg(feature = "archives")]
pub fn sevenz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture.7z");
    {
        let mut w = sevenz_rust::SevenZWriter::create(&path).expect("7z create");
        for (name, data) in entries {
            // Mutated from `new()` rather than built as a struct literal:
            // `content_methods` is private, so a literal cannot be written
            // from outside the crate even with `..Default::default()`.
            // `create_archive_entry` is the other option and it is
            // deprecated — it reads metadata off a real file, and there
            // isn't one here; these bytes are in memory.
            let mut entry = sevenz_rust::SevenZArchiveEntry::new();
            entry.name = (*name).to_string();
            entry.has_stream = true;
            entry.size = data.len() as u64;
            w.push_archive_entry(entry, Some(std::io::Cursor::new(data.to_vec())))
                .expect("7z entry");
        }
        w.finish().expect("7z finish");
    }
    std::fs::read(&path).expect("7z read back")
}

/// A SQLite database with a single `records(label, value)` table.
#[cfg(feature = "data-formats")]
pub fn sqlite(rows: &[(&str, &str)]) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).expect("sqlite open");
        conn.execute("CREATE TABLE records (label TEXT, value TEXT)", [])
            .expect("sqlite ddl");
        for (label, value) in rows {
            conn.execute(
                "INSERT INTO records (label, value) VALUES (?1, ?2)",
                rusqlite::params![label, value],
            )
            .expect("sqlite insert");
        }
    }
    std::fs::read(&path).expect("sqlite read back")
}
