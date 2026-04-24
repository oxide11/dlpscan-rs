//! PDF metadata extractor.
//!
//! Two sources are read:
//!   1. The trailer's `/Info` dictionary — legacy pre-PDF-1.4
//!      metadata. Still populated by every producer for back-compat.
//!   2. The `/ID` array in the trailer — two 16-byte hex tokens:
//!      original ID (stable across edits) + current ID (rotates).
//!
//! We deliberately do NOT parse the XMP metadata stream yet —
//! pulling it requires walking the `/Catalog /Metadata` chain and
//! decoding the embedded RDF/XML. When the forensics module grows
//! a second sprint, that's the obvious next signal to add.

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

    Ok(meta)
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
