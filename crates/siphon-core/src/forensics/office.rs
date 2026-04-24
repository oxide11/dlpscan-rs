//! OOXML (docx / xlsx / pptx) metadata extractor.
//!
//! OOXML containers are ZIP archives with a predictable internal
//! layout:
//!
//! ```text
//! docProps/
//!   core.xml      ← Dublin Core — author, title, created, modified
//!   app.xml       ← application-specific — Application, Company
//! word/           (docx only)
//!   settings.xml  ← <w:rsids> block: root + every edit-session ID
//! ```
//!
//! We parse just what's needed for attribution and stash any
//! unknown tags in `FileMetadata::raw` for completeness.

use std::io::{Cursor, Read};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::{FileKind, FileMetadata, ForensicsError};

/// Parse an OOXML archive and populate a FileMetadata. The caller
/// sets `kind`, `path`, `size_bytes`, and `content_hash` after this
/// returns.
pub fn extract(bytes: &[u8], kind: &FileKind) -> Result<FileMetadata, ForensicsError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ForensicsError::Malformed(format!("not a valid zip: {e}")))?;

    let mut meta = FileMetadata::default();

    // The core + app files are authored the same way regardless of
    // container type, so we read them unconditionally and ignore
    // absence (a malformed or stripped container may omit them).
    if let Ok(xml) = read_entry(&mut archive, "docProps/core.xml") {
        parse_core_xml(&xml, &mut meta)?;
    }
    if let Ok(xml) = read_entry(&mut archive, "docProps/app.xml") {
        parse_app_xml(&xml, &mut meta)?;
    }

    // Settings.xml lives in different paths per container type. We
    // only bother with docx because xlsx/pptx don't ship an
    // equivalent RSID block — their edit tracking goes through
    // different mechanisms that rarely carry attribution value.
    if matches!(kind, FileKind::Docx) {
        if let Ok(xml) = read_entry(&mut archive, "word/settings.xml") {
            parse_settings_rsids(&xml, &mut meta)?;
        }
    }

    Ok(meta)
}

/// Pull a named entry out of a ZIP archive as a UTF-8 string.
/// Returns an error if the entry doesn't exist or isn't readable as
/// text.
fn read_entry<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
) -> Result<String, ForensicsError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|e| ForensicsError::Malformed(format!("{name}: {e}")))?;
    let mut buf = String::new();
    entry
        .read_to_string(&mut buf)
        .map_err(|e| ForensicsError::Malformed(format!("{name} read: {e}")))?;
    Ok(buf)
}

/// Parse `docProps/core.xml` — Dublin Core tags. The schema is
/// stable enough that a dumb tag-name switch covers every producer
/// we care about.
fn parse_core_xml(xml: &str, meta: &mut FileMetadata) -> Result<(), ForensicsError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut cur: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                cur = Some(tag_local_name(e.name().as_ref()));
            }
            Ok(Event::Text(e)) => {
                if let Some(tag) = &cur {
                    let text = decode_text(&e);
                    if text.is_empty() {
                        continue;
                    }
                    match tag.as_str() {
                        "creator" => meta.creator = Some(text),
                        "lastModifiedBy" => meta.last_modified_by = Some(text),
                        "title" => meta.title = Some(text),
                        "subject" => meta.subject = Some(text),
                        "keywords" => meta.keywords = Some(text),
                        "created" => meta.created_at = Some(text),
                        "modified" => meta.modified_at = Some(text),
                        other => {
                            meta.raw.entry(format!("cp:{other}")).or_insert(text);
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                cur = None;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ForensicsError::Malformed(format!("core.xml parse: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// Parse `docProps/app.xml` — application/company fields plus
/// freeform properties like TotalTime and Pages.
fn parse_app_xml(xml: &str, meta: &mut FileMetadata) -> Result<(), ForensicsError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut cur: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                cur = Some(tag_local_name(e.name().as_ref()));
            }
            Ok(Event::Text(e)) => {
                if let Some(tag) = &cur {
                    let text = decode_text(&e);
                    if text.is_empty() {
                        continue;
                    }
                    match tag.as_str() {
                        "Application" => meta.application = Some(text),
                        "Company" => meta.company = Some(text),
                        other => {
                            meta.raw.entry(format!("app:{other}")).or_insert(text);
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                cur = None;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ForensicsError::Malformed(format!("app.xml parse: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// Parse `word/settings.xml` for the `<w:rsids>` block. Output is
/// ordered so the first entry is the `rsidRoot` (producer
/// convention) — investigators compare roots across files to tell
/// whether two documents were authored on the same Word install.
fn parse_settings_rsids(xml: &str, meta: &mut FileMetadata) -> Result<(), ForensicsError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut rsid_root: Option<String> = None;
    let mut rsids: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                let local = tag_local_name(e.name().as_ref());
                // The interesting tags are rsidRoot + rsid. Both carry
                // the hex ID as the `w:val` attribute.
                if local == "rsidRoot" || local == "rsid" {
                    if let Some(val) = attr_value(&e, b"val") {
                        if local == "rsidRoot" {
                            rsid_root = Some(val);
                        } else {
                            rsids.push(val);
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ForensicsError::Malformed(format!(
                    "settings.xml parse: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    // Root goes first unconditionally — consumers rely on
    // meta.rsids[0] == rsidRoot for attribution. Subsequent session
    // IDs are de-duped against what's already in meta.rsids.
    if let Some(root) = rsid_root {
        meta.rsids.push(root);
    }
    for rsid in rsids {
        if !meta.rsids.contains(&rsid) {
            meta.rsids.push(rsid);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// XML helpers — namespace-stripping so "dc:creator" and "creator"
// read as the same tag. The real tag names we care about are
// namespace-qualified in their own files (e.g. `<dc:creator>` in
// core.xml), but since the core/app tag vocabularies don't collide
// with each other, stripping the prefix keeps the parse loop tidy.
// ---------------------------------------------------------------------------

fn tag_local_name(qname: &[u8]) -> String {
    let full = std::str::from_utf8(qname).unwrap_or("");
    match full.rfind(':') {
        Some(i) => full[i + 1..].to_string(),
        None => full.to_string(),
    }
}

/// Decode a BytesText into an owned String, unescaping XML entities.
/// `quick_xml::escape::unescape` handles `&amp;` / `&lt;` / `&#NN;`
/// etc.; lossy UTF-8 decoding keeps us moving if a producer wrote
/// an invalid byte sequence.
fn decode_text(e: &quick_xml::events::BytesText<'_>) -> String {
    let raw = String::from_utf8_lossy(e.as_ref());
    match quick_xml::escape::unescape(&raw) {
        Ok(cow) => cow.into_owned(),
        Err(_) => raw.into_owned(),
    }
}

/// Find an attribute's value by local name on a start/empty tag.
/// Returns None if the attribute is missing or unreadable.
fn attr_value(e: &quick_xml::events::BytesStart, local: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        let key = attr.key.as_ref();
        // Strip any `w:` / `xmlns:` prefix before comparing.
        let key_local = match key.iter().rposition(|&b| b == b':') {
            Some(i) => &key[i + 1..],
            None => key,
        };
        if key_local == local {
            return std::str::from_utf8(attr.value.as_ref())
                .ok()
                .map(|s| s.to_string());
        }
    }
    None
}
