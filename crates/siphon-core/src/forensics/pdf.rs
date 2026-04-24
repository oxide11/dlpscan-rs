//! PDF metadata extractor.
//!
//! Three sources are read:
//!   1. The trailer's `/Info` dictionary — legacy pre-PDF-1.4
//!      metadata. Still populated by every producer for back-compat.
//!   2. The `/ID` array in the trailer — two 16-byte hex tokens:
//!      original ID (stable across edits) + current ID (rotates).
//!   3. The XMP metadata stream, reachable via
//!      `/Catalog -> /Metadata`. This is the richer Adobe-style
//!      metadata — `xmp:CreatorTool`, `xmpMM:DocumentID`,
//!      `xmpMM:InstanceID`, the full Dublin Core namespace, and
//!      any photoshop / exif namespaces a producer embedded.
//!      DocumentID in particular is a strong attribution signal —
//!      it's a UUID assigned at first save and preserved across
//!      every subsequent edit that didn't re-export the file.

use lopdf::{Document, Object};

use super::{FileMetadata, ForensicsError};

pub fn extract(bytes: &[u8]) -> Result<FileMetadata, ForensicsError> {
    let doc = Document::load_mem(bytes)
        .map_err(|e| ForensicsError::Malformed(format!("pdf parse: {e}")))?;

    let mut meta = FileMetadata::default();

    // --- Info dictionary --------------------------------------------------
    // lopdf exposes it via the trailer's /Info reference. Older
    // producers write unquoted hex strings; lopdf normalises both
    // to `Object::String(bytes, format)`.
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok(id) = info_ref.as_reference() {
            if let Ok(info_obj) = doc.get_object(id) {
                if let Ok(info) = info_obj.as_dict() {
                    for (key, val) in info.iter() {
                        let key_s = std::str::from_utf8(key).unwrap_or("").to_string();
                        if let Some(text) = stringify(val) {
                            assign_info(&mut meta, &key_s, text);
                        }
                    }
                }
            }
        }
    }

    // --- Document ID ------------------------------------------------------
    if let Ok(id_obj) = doc.trailer.get(b"ID") {
        if let Ok(arr) = id_obj.as_array() {
            if arr.len() >= 2 {
                let first = stringify(&arr[0]).unwrap_or_default();
                let second = stringify(&arr[1]).unwrap_or_default();
                if !first.is_empty() && !second.is_empty() {
                    meta.pdf_doc_id = Some((hexify(&first), hexify(&second)));
                }
            }
        }
    }

    // --- Version ----------------------------------------------------------
    // PDF version is on the root Catalog or the file header. The
    // header is easiest — lopdf exposes it directly.
    if !doc.version.is_empty() {
        meta.raw
            .insert("pdf:version".to_string(), doc.version.clone());
    }

    // --- XMP metadata stream ---------------------------------------------
    // /Root -> /Metadata gives us a stream of RDF/XML. Producers
    // that don't write XMP (old versions, scan-only pipelines)
    // simply don't carry this reference — absence is not an error.
    if let Some(xmp) = read_xmp_stream(&doc) {
        parse_xmp(&xmp, &mut meta);
    }

    Ok(meta)
}

/// Resolve /Root -> /Metadata, decode the stream bytes, and return
/// them as a UTF-8 string. Returns None for any missing link or
/// non-stream object in the chain — the caller treats absence as
/// "no XMP metadata present" rather than a parse error.
fn read_xmp_stream(doc: &Document) -> Option<String> {
    let root_ref = doc.trailer.get(b"Root").ok()?;
    let root_id = root_ref.as_reference().ok()?;
    let root_obj = doc.get_object(root_id).ok()?;
    let root_dict = root_obj.as_dict().ok()?;

    let meta_ref = root_dict.get(b"Metadata").ok()?;
    let (_, meta_obj) = doc.dereference(meta_ref).ok()?;
    let stream = meta_obj.as_stream().ok()?;

    // PDF streams can be FlateDecode, ASCII85Decode, etc. lopdf's
    // decompressed_content walks the /Filter chain for us.
    let bytes = stream.decompressed_content().ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Walk the XMP RDF/XML looking for the handful of tags that carry
/// attribution value. Anything that doesn't map to a first-class
/// FileMetadata field goes into `raw["xmp:*"]` for manual review.
///
/// XMP is nested RDF, but in practice every producer serialises the
/// interesting values as simple `<ns:Tag>value</ns:Tag>` elements.
/// A SAX-style walk keyed on the local tag name is more forgiving
/// of namespace-prefix variation than a strict RDF parser — and the
/// failure mode when a producer does something unusual is "miss one
/// signal", not a crash.
pub(crate) fn parse_xmp(xml: &str, meta: &mut FileMetadata) {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

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
                    let text = String::from_utf8_lossy(e.as_ref()).trim().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    assign_xmp(meta, tag, text);
                }
            }
            // XMP also stores values inside rdf:Description attributes
            // sometimes — pick them up here so we don't miss Adobe's
            // compact form.
            Ok(Event::Empty(e)) => {
                for attr in e.attributes().flatten() {
                    let key = tag_local_name(attr.key.as_ref());
                    let val = String::from_utf8_lossy(&attr.value).into_owned();
                    if !val.is_empty() {
                        assign_xmp(meta, &key, val);
                    }
                }
            }
            Ok(Event::End(_)) => {
                cur = None;
            }
            Ok(Event::Eof) => break,
            // Any parse error — treat as "no more XMP signals" and
            // return what we have. Don't fail the whole extract over
            // a producer's malformed XML.
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

fn assign_xmp(meta: &mut FileMetadata, tag: &str, value: String) {
    // Don't overwrite what the Info dict already populated —
    // producers often disagree between Info and XMP, and the Info
    // dict is the ordained legacy source.
    match tag {
        "creator" if meta.creator.is_none() => meta.creator = Some(value),
        "title" if meta.title.is_none() => meta.title = Some(value),
        "subject" if meta.subject.is_none() => meta.subject = Some(value),
        "CreatorTool" if meta.application.is_none() => meta.application = Some(value),
        "Producer" if meta.application.is_none() => meta.application = Some(value),
        "CreateDate" if meta.created_at.is_none() => meta.created_at = Some(value),
        "ModifyDate" if meta.modified_at.is_none() => meta.modified_at = Some(value),
        // DocumentID is a UUID minted at first save and persists
        // across every edit. Strongest PDF attribution signal after
        // the /ID first token — investigators correlate it when the
        // Info dict has been stripped.
        "DocumentID" => {
            meta.raw.insert("xmp:DocumentID".to_string(), value);
        }
        "InstanceID" => {
            meta.raw.insert("xmp:InstanceID".to_string(), value);
        }
        other => {
            // Only stash signal-bearing tags in `raw` — skip generic
            // structural XML ("li", "Seq", "Bag", "Alt", "Description",
            // "rdf", "xmpmeta") that carries no metadata value of its
            // own. Keeps the `raw` dump readable in the CLI.
            let structural = matches!(
                other,
                "li" | "Seq" | "Bag" | "Alt" | "Description" | "rdf" | "xmpmeta" | "RDF" | "x"
            );
            if !structural {
                meta.raw.entry(format!("xmp:{other}")).or_insert(value);
            }
        }
    }
}

/// Namespace-strip a tag name: `dc:creator` -> `creator`.
fn tag_local_name(qname: &[u8]) -> String {
    let full = std::str::from_utf8(qname).unwrap_or("");
    match full.rfind(':') {
        Some(i) => full[i + 1..].to_string(),
        None => full.to_string(),
    }
}

/// Drop an Info-dict value into the right FileMetadata field. Keys
/// are the PDF spec's canonical capitalisation (`Author`, `Title`,
/// `Producer`, etc.), but we lower-case for the match to tolerate
/// non-conforming producers.
fn assign_info(meta: &mut FileMetadata, key: &str, value: String) {
    match key {
        "Title" => meta.title = Some(value),
        "Author" => meta.creator = Some(value),
        "Subject" => meta.subject = Some(value),
        "Keywords" => meta.keywords = Some(value),
        "Creator" => {
            // PDF's /Creator is the application that authored the
            // source *document*; /Producer is the one that wrote
            // the PDF. The producer is more useful for attribution,
            // but we want both — stash Creator in raw.
            meta.raw.insert("pdf:Creator".to_string(), value);
        }
        "Producer" => meta.application = Some(value),
        "CreationDate" => meta.created_at = Some(pdf_date_normalize(&value)),
        "ModDate" => meta.modified_at = Some(pdf_date_normalize(&value)),
        other => {
            meta.raw.insert(format!("pdf:{other}"), value);
        }
    }
}

/// Extract the string value from an `Object::String` or similar.
/// Returns None for references / arrays / dictionaries.
fn stringify(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Object::Name(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

/// Render a binary blob as lower-case hex. Used for the /ID tokens,
/// which PDF spec encodes as 16-byte binary strings but investigators
/// traditionally quote as hex.
fn hexify(s: &str) -> String {
    hex::encode(s.as_bytes())
}

/// Normalise PDF date strings (e.g. `D:20260423194200Z` or
/// `D:20260423194200+02'00'`) to ISO-8601-ish. If the input doesn't
/// match the expected prefix, pass it through verbatim — investigators
/// can eyeball the raw value.
fn pdf_date_normalize(raw: &str) -> String {
    let s = raw.trim_start_matches("D:");
    if s.len() < 14 || !s[0..14].bytes().all(|b| b.is_ascii_digit()) {
        return raw.to_string();
    }
    // YYYY-MM-DDTHH:MM:SS + optional trailing tz
    let base = format!(
        "{}-{}-{}T{}:{}:{}",
        &s[0..4],
        &s[4..6],
        &s[6..8],
        &s[8..10],
        &s[10..12],
        &s[12..14],
    );
    // Preserve `Z`, or re-shape `+HH'mm'` to `+HH:MM`.
    let tz = &s[14..];
    if tz.is_empty() {
        base
    } else if tz == "Z" {
        format!("{base}Z")
    } else if tz.len() >= 3 && (tz.starts_with('+') || tz.starts_with('-')) {
        let hh = &tz[1..3];
        let mm = tz
            .bytes()
            .filter(|b| b.is_ascii_digit())
            .skip(2)
            .take(2)
            .map(char::from)
            .collect::<String>();
        format!(
            "{base}{sign}{hh}:{mm}",
            sign = &tz[0..1],
            mm = if mm.len() == 2 { mm } else { "00".to_string() }
        )
    } else {
        base
    }
}
