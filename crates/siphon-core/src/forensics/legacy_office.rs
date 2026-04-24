//! Legacy binary Office (.doc / .xls / .ppt) metadata extractor.
//!
//! Pre-2007 Office documents are OLE Compound Files — structured
//! like a filesystem inside a single binary blob. The metadata we
//! want lives in two well-known streams:
//!
//!   `/\x05SummaryInformation`          — Title, Author, Subject,
//!                                        Keywords, Last Author,
//!                                        CreateTime, LastSaveTime,
//!                                        AppName
//!   `/\x05DocumentSummaryInformation`  — Company, Manager,
//!                                        extended custom properties
//!
//! Each stream holds a **Property Set** (OSPS spec), a
//! three-layer format: a fixed header, one or more sections keyed
//! by FMTID, and per-section property-ID → offset tables pointing
//! at typed values.
//!
//! This parser handles the subset of VT_ tags that Office actually
//! uses in practice:
//!   VT_LPSTR (0x001E) — 8-bit string, null-terminated, CP1252
//!   VT_LPWSTR (0x001F) — UTF-16LE string
//!   VT_FILETIME (0x0040) — 64-bit 100ns ticks since 1601-01-01 UTC
//!
//! Anything else gets skipped rather than crashing — a producer
//! that embeds a VT_BLOB in its property set still yields a valid
//! (if partial) FileMetadata.

use std::io::{Cursor, Read};

use super::{FileMetadata, ForensicsError};

/// FMTID of the standard SummaryInformation property set —
/// `{F29F85E0-4FF9-1068-AB91-08002B27B3D9}` — written little-endian
/// per the OSPS storage format.
const FMTID_SUMMARY: [u8; 16] = [
    0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
];

/// FMTID of DocumentSummaryInformation —
/// `{D5CDD502-2E9C-101B-9397-08002B2CF9AE}`.
const FMTID_DOCSUMMARY: [u8; 16] = [
    0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
];

// SummaryInformation property IDs (OSPS spec table 2.1).
const PID_TITLE: u32 = 0x02;
const PID_SUBJECT: u32 = 0x03;
const PID_AUTHOR: u32 = 0x04;
const PID_KEYWORDS: u32 = 0x05;
const PID_COMMENTS: u32 = 0x06;
const PID_LAST_AUTHOR: u32 = 0x08;
const PID_CREATE_TIME: u32 = 0x0C;
const PID_LAST_SAVE_TIME: u32 = 0x0D;
const PID_APP_NAME: u32 = 0x12;

// DocumentSummaryInformation property IDs (OSPS spec table 2.2).
const PID_COMPANY: u32 = 0x0F;
const PID_MANAGER: u32 = 0x0E;

// VT_ type tags.
const VT_LPSTR: u16 = 0x001E;
const VT_LPWSTR: u16 = 0x001F;
const VT_FILETIME: u16 = 0x0040;

/// Parse a legacy binary Office file (.doc / .xls / .ppt) and
/// populate a `FileMetadata`. The caller sets `kind`, `path`,
/// `size_bytes`, and `content_hash`.
pub fn extract(bytes: &[u8]) -> Result<FileMetadata, ForensicsError> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| ForensicsError::Malformed(format!("not a valid OLE file: {e}")))?;

    let mut meta = FileMetadata::default();

    // The well-known stream names start with a 0x05 control byte —
    // that's a Microsoft convention for "system" streams. cfb's
    // path API handles the encoding as long as we include it.
    for name in &["\u{5}SummaryInformation", "\u{5}DocumentSummaryInformation"] {
        if comp.exists(name) {
            let mut buf = Vec::new();
            if let Ok(mut stream) = comp.open_stream(name) {
                if stream.read_to_end(&mut buf).is_ok() {
                    parse_property_set(&buf, &mut meta);
                }
            }
        }
    }

    Ok(meta)
}

/// Parse an OSPS property set from a stream's raw bytes, matching
/// each recognised section FMTID to the per-section handler.
fn parse_property_set(bytes: &[u8], meta: &mut FileMetadata) {
    // Header layout:
    //   u16 byte order  (0xFFFE)
    //   u16 version
    //   u16 system-identifier-major
    //   u16 system-identifier-minor  (really two u16s = 4 bytes)
    //   [16] CLSID
    //   u32 section count
    //   then: section count × (16-byte FMTID + u32 offset)
    if bytes.len() < 28 {
        return;
    }
    if bytes[0..2] != [0xFE, 0xFF] {
        // Not a property set.
        return;
    }
    let section_count = u32_le(&bytes[24..28]) as usize;
    if section_count == 0 || section_count > 256 {
        return; // sanity — real files have 1-2 sections
    }

    let mut cur = 28;
    for _ in 0..section_count {
        if cur + 20 > bytes.len() {
            return;
        }
        let fmtid: [u8; 16] = bytes[cur..cur + 16].try_into().unwrap_or([0; 16]);
        let offset = u32_le(&bytes[cur + 16..cur + 20]) as usize;
        cur += 20;

        if offset + 8 > bytes.len() {
            continue;
        }
        // Section layout:
        //   u32 size
        //   u32 property count
        //   then: property count × (u32 id + u32 offset)
        //   then: typed values at those offsets
        let section = &bytes[offset..];
        parse_section(section, &fmtid, meta);
    }
}

/// Parse a single section inside a property set. Dispatches each
/// recognised property to the right FileMetadata field.
fn parse_section(section: &[u8], fmtid: &[u8; 16], meta: &mut FileMetadata) {
    if section.len() < 8 {
        return;
    }
    let prop_count = u32_le(&section[4..8]) as usize;
    if prop_count > 512 {
        return; // sanity cap
    }

    for i in 0..prop_count {
        let entry_off = 8 + i * 8;
        if entry_off + 8 > section.len() {
            return;
        }
        let pid = u32_le(&section[entry_off..entry_off + 4]);
        let val_off = u32_le(&section[entry_off + 4..entry_off + 8]) as usize;
        if val_off + 4 > section.len() {
            continue;
        }
        let ty = u16_le(&section[val_off..val_off + 2]);
        // Values are stored as u32-sized TypedPropertyValue — but
        // the first 4 bytes are the type (u16) + padding (u16).
        let payload = &section[val_off + 4..];

        let value = decode_value(ty, payload);
        if value.is_empty() {
            continue;
        }

        assign_property(fmtid, pid, value, meta);
    }
}

/// Map a (FMTID, Property ID) pair to the right FileMetadata field.
fn assign_property(fmtid: &[u8; 16], pid: u32, value: String, meta: &mut FileMetadata) {
    if fmtid == &FMTID_SUMMARY {
        match pid {
            PID_TITLE => meta.title = Some(value),
            PID_SUBJECT => meta.subject = Some(value),
            PID_AUTHOR => meta.creator = Some(value),
            PID_KEYWORDS => meta.keywords = Some(value),
            PID_LAST_AUTHOR => meta.last_modified_by = Some(value),
            PID_CREATE_TIME => meta.created_at = Some(value),
            PID_LAST_SAVE_TIME => meta.modified_at = Some(value),
            PID_APP_NAME => meta.application = Some(value),
            PID_COMMENTS => {
                meta.raw.insert("ole:Comments".to_string(), value);
            }
            other => {
                meta.raw
                    .entry(format!("ole:summary:{other:#06x}"))
                    .or_insert(value);
            }
        }
    } else if fmtid == &FMTID_DOCSUMMARY {
        match pid {
            PID_COMPANY => meta.company = Some(value),
            PID_MANAGER => {
                meta.raw.insert("ole:Manager".to_string(), value);
            }
            other => {
                meta.raw
                    .entry(format!("ole:docsummary:{other:#06x}"))
                    .or_insert(value);
            }
        }
    }
}

/// Decode a typed property value. Returns "" for unsupported types
/// so the caller can skip them without branching.
fn decode_value(ty: u16, payload: &[u8]) -> String {
    match ty {
        VT_LPSTR => decode_lpstr(payload),
        VT_LPWSTR => decode_lpwstr(payload),
        VT_FILETIME => decode_filetime(payload),
        _ => String::new(),
    }
}

/// VT_LPSTR: u32 length + ANSI (CP1252) bytes, null-terminated.
/// The length includes the null. We strip it for the user-facing
/// string.
fn decode_lpstr(payload: &[u8]) -> String {
    if payload.len() < 4 {
        return String::new();
    }
    let len = u32_le(&payload[0..4]) as usize;
    if len == 0 || 4 + len > payload.len() {
        return String::new();
    }
    let raw = &payload[4..4 + len];
    let trimmed = trim_trailing_null(raw);
    // CP1252 is ASCII-compatible for the common case. For the
    // occasional non-ASCII byte (smart quote, accented name), lossy
    // UTF-8 decode renders a replacement char rather than crash.
    String::from_utf8_lossy(trimmed).into_owned()
}

/// VT_LPWSTR: u32 length (in chars, not bytes) + UTF-16LE + null.
fn decode_lpwstr(payload: &[u8]) -> String {
    if payload.len() < 4 {
        return String::new();
    }
    let chars = u32_le(&payload[0..4]) as usize;
    let byte_len = chars.saturating_mul(2);
    if byte_len == 0 || 4 + byte_len > payload.len() {
        return String::new();
    }
    let mut u16s: Vec<u16> = Vec::with_capacity(chars);
    for chunk in payload[4..4 + byte_len].chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break; // stop at null — the length sometimes over-counts
        }
        u16s.push(unit);
    }
    String::from_utf16_lossy(&u16s)
}

/// VT_FILETIME: i64 100-ns ticks since 1601-01-01 UTC. We convert
/// to ISO-8601 so it lines up with the OOXML timestamps downstream
/// code already handles.
fn decode_filetime(payload: &[u8]) -> String {
    if payload.len() < 8 {
        return String::new();
    }
    let lo = u32_le(&payload[0..4]) as u64;
    let hi = u32_le(&payload[4..8]) as u64;
    let ticks = (hi << 32) | lo;
    if ticks == 0 {
        return String::new();
    }
    // Offset between FILETIME epoch (1601-01-01) and Unix (1970).
    const OFFSET_SECS: i64 = 11_644_473_600;
    let unix_secs = (ticks / 10_000_000) as i64 - OFFSET_SECS;
    // Reuse Rust's system-time math to format — avoids pulling
    // chrono just for one date formatter.
    let secs_per_day: i64 = 86_400;
    let days = unix_secs.div_euclid(secs_per_day);
    let secs_of_day = unix_secs.rem_euclid(secs_per_day);
    let (y, m, d) = days_to_ymd(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days-since-1970-01-01 to a (year, month, day) triple.
/// Gregorian, proleptic; no timezone adjustment (values are already
/// UTC). Lifted from a standard algorithm — avoids a date-library
/// dependency just for a handful of format timestamps.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Days from year 0 to 1970 = 719_468 by convention.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}

fn trim_trailing_null(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && b[end - 1] == 0 {
        end -= 1;
    }
    &b[..end]
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
