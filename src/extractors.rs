//! Multi-format text extraction for DLP scanning.
//!
//! Provides a registry of extractors for different file formats.
//! Always available: plain text, RTF, EML. Feature-gated: PDF, Office.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Maximum file size for extraction (100 MB).
pub const MAX_EXTRACT_SIZE: usize = 100 * 1024 * 1024;

/// Maximum total extracted size from archives (500 MB).
const MAX_EXTRACT_TOTAL_SIZE: u64 = 500 * 1024 * 1024;

/// Maximum single entry size from archives (100 MB).
const MAX_EXTRACT_ENTRY_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of files to extract from archives.
const MAX_EXTRACT_FILE_COUNT: usize = 10_000;

/// Sanitize an archive entry name to prevent path traversal attacks.
/// Returns None if the path is unsafe (contains `..`, absolute paths, etc).
fn sanitize_archive_path(base: &std::path::Path, entry_name: &str) -> Option<std::path::PathBuf> {
    let cleaned = Path::new(entry_name)
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect::<std::path::PathBuf>();

    if cleaned.as_os_str().is_empty() {
        return None;
    }

    let full_path = base.join(&cleaned);

    // Double-check the resolved path is under the base directory
    if !full_path.starts_with(base) {
        return None;
    }

    Some(full_path)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of text extraction from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub text: String,
    pub format: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl ExtractionResult {
    pub fn new(text: String, format: &str) -> Self {
        Self {
            text,
            format: format.to_string(),
            metadata: HashMap::new(),
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: &str) -> Self {
        self.warnings.push(warning.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Extractor function signature.
pub type ExtractorFn = fn(&str) -> Result<ExtractionResult, String>;

// ---------------------------------------------------------------------------
// Extractor Registry
// ---------------------------------------------------------------------------

static CUSTOM_EXTRACTORS: Lazy<Mutex<HashMap<String, ExtractorFn>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Register a custom extractor for a file extension.
pub fn register_extractor(extension: &str, func: ExtractorFn) {
    let ext = extension.trim_start_matches('.').to_lowercase();
    CUSTOM_EXTRACTORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(ext, func);
}

/// Get the extractor for a file extension.
pub fn get_extractor(file_path: &str) -> Option<ExtractorFn> {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())?;

    // Check custom extractors first
    if let Some(func) = CUSTOM_EXTRACTORS.lock().unwrap_or_else(|e| e.into_inner()).get(&ext) {
        return Some(*func);
    }

    // Built-in extractors
    match ext.as_str() {
        // Plain text formats (including TSV and certificate/key files)
        "txt" | "csv" | "tsv" | "log" | "json" | "xml" | "html" | "htm" | "yaml" | "yml"
        | "toml" | "ini" | "cfg" | "conf" | "md" | "rst" | "py" | "js" | "ts" | "java"
        | "go" | "rs" | "rb" | "php" | "sh" | "bat" | "ps1" | "sql" | "env" | "c" | "cpp"
        | "h" | "hpp" | "css" | "scss" | "less" | "jsx" | "tsx" | "vue" | "svelte" | "swift"
        | "kt" | "scala" | "r" | "m" | "mm"
        | "pem" | "cer" | "crt" | "key" | "pub" | "csr" | "der" | "p12" | "pfx"
            => Some(extract_plain_text),

        // RTF (custom parser, no deps)
        "rtf" => Some(extract_rtf),

        // EML (email, stdlib parser)
        "eml" => Some(extract_eml),

        // Contact file formats
        "vcf" | "vcard" => Some(extract_vcard),
        "contact" => Some(extract_windows_contact),
        "ldif" | "ldi" => Some(extract_ldif),

        // Calendar
        "ics" | "ical" | "ifb" => Some(extract_ics),

        // Email archives
        "mbox" | "mbx" => Some(extract_mbox),

        // Web archives
        "mhtml" | "mht" => Some(extract_mhtml),
        "warc" => Some(extract_warc),

        // OpenDocument (ZIP-based, same infra as OOXML)
        "odt" | "ods" | "odp" => Some(extract_opendocument),

        // Outlook MSG (OLE2)
        #[cfg(feature = "msg")]
        "msg" => Some(extract_msg),

        // Archives
        #[cfg(feature = "archives")]
        "rar" => Some(extract_rar),
        #[cfg(feature = "archives")]
        "7z" => Some(extract_7z),

        // Data formats
        #[cfg(feature = "data-formats")]
        "parquet" => Some(extract_parquet),
        #[cfg(feature = "data-formats")]
        "db" | "sqlite" | "sqlite3" => Some(extract_sqlite),

        _ => {
            // Try format detection by magic bytes
            detect_and_extract(file_path)
        }
    }
}

/// Extract text from a file, auto-detecting format.
pub fn extract_text(file_path: &str) -> Result<ExtractionResult, String> {
    // Check file size
    let metadata = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    if metadata.len() as usize > MAX_EXTRACT_SIZE {
        return Err(format!(
            "File too large: {} bytes (max {})",
            metadata.len(),
            MAX_EXTRACT_SIZE
        ));
    }

    if let Some(extractor) = get_extractor(file_path) {
        extractor(file_path)
    } else {
        // Default to plain text
        extract_plain_text(file_path)
    }
}

/// List all supported extensions (built-in + custom).
pub fn supported_extensions() -> Vec<String> {
    let mut exts: Vec<String> = vec![
        "txt", "csv", "tsv", "log", "json", "xml", "html", "htm", "yaml", "yml", "toml", "ini",
        "cfg", "conf", "md", "rst", "py", "js", "ts", "java", "go", "rs", "rb", "php", "sh",
        "bat", "ps1", "sql", "env", "rtf", "eml", "vcf", "vcard", "contact", "ldif",
        "c", "cpp", "h", "hpp", "css", "scss",
        "pem", "cer", "crt", "key", "pub", "csr",
        "ics", "ical",
        "mbox", "mbx",
        "mhtml", "mht",
        "warc",
        "odt", "ods", "odp",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    if let Ok(custom) = CUSTOM_EXTRACTORS.lock() {
        exts.extend(custom.keys().cloned());
    }

    exts.sort();
    exts.dedup();
    exts
}

// ---------------------------------------------------------------------------
// Format detection by magic bytes
// ---------------------------------------------------------------------------

fn detect_and_extract(file_path: &str) -> Option<ExtractorFn> {
    let mut buf = [0u8; 8];
    let file = std::fs::File::open(file_path).ok()?;
    use std::io::Read;
    let mut reader = std::io::BufReader::new(file);
    let n = reader.read(&mut buf).ok()?;
    if n < 4 {
        return None;
    }

    // PDF: %PDF
    if &buf[..4] == b"%PDF" {
        return Some(extract_plain_text); // Fallback; use pdf feature for real extraction
    }

    // RTF: {\rtf
    if n >= 5 && &buf[..5] == b"{\\rtf" {
        return Some(extract_rtf);
    }

    // ZIP-based (Office): PK\x03\x04
    if &buf[..4] == b"PK\x03\x04" {
        return Some(extract_zip_based);
    }

    // OLE2 (MSG): D0 CF 11 E0 A1 B1 1A E1
    #[cfg(feature = "msg")]
    if n >= 8 && buf[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Some(extract_msg);
    }

    // RAR: Rar!\x1a\x07
    #[cfg(feature = "archives")]
    if n >= 6 && &buf[..6] == b"Rar!\x1a\x07" {
        return Some(extract_rar);
    }

    // 7z: 7z\xBC\xAF\x27\x1C
    #[cfg(feature = "archives")]
    if n >= 6 && buf[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(extract_7z);
    }

    // Parquet: PAR1
    #[cfg(feature = "data-formats")]
    if n >= 4 && &buf[..4] == b"PAR1" {
        return Some(extract_parquet);
    }

    // SQLite: "SQLite format 3\0"
    #[cfg(feature = "data-formats")]
    if n >= 6 && &buf[..6] == b"SQLite" {
        return Some(extract_sqlite);
    }

    // Text-based format detection (read only first 8192 bytes)
    let content_result: Result<String, std::io::Error> = (|| {
        let f = std::fs::File::open(file_path)?;
        let mut limited = std::io::Read::take(f, 8192);
        let mut buf = Vec::with_capacity(8192);
        std::io::Read::read_to_end(&mut limited, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    })();
    if let Ok(content) = content_result {
        let trimmed = content.trim_start();

        // vCard: BEGIN:VCARD
        if trimmed.starts_with("BEGIN:VCARD") {
            return Some(extract_vcard);
        }

        // iCalendar: BEGIN:VCALENDAR
        if trimmed.starts_with("BEGIN:VCALENDAR") {
            return Some(extract_ics);
        }

        // LDIF: starts with dn: (skip comments)
        let first_meaningful = trimmed
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty());
        if let Some(line) = first_meaningful {
            if line.starts_with("dn:") || line.starts_with("dn::") {
                return Some(extract_ldif);
            }
        }

        // jCard: JSON array containing "vcard"
        if trimmed.starts_with('[') && trimmed.contains("\"vcard\"") {
            return Some(extract_jcard);
        }

        // Windows Contacts: XML with Contact namespace
        if trimmed.starts_with("<?xml") && trimmed.contains("schemas.microsoft.com/Contact") {
            return Some(extract_windows_contact);
        }

        // MBOX: starts with "From "
        if trimmed.starts_with("From ") {
            return Some(extract_mbox);
        }

        // MHTML: MIME with multipart/related
        if trimmed.starts_with("MIME-Version:") || trimmed.starts_with("From:") {
            if trimmed.contains("multipart/related") || trimmed.contains("multipart/alternative") {
                return Some(extract_mhtml);
            }
        }

        // WARC: WARC/1.x
        if trimmed.starts_with("WARC/") {
            return Some(extract_warc);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Built-in extractors
// ---------------------------------------------------------------------------

/// Extract text from a plain text file (UTF-8 with error replacement).
fn extract_plain_text(file_path: &str) -> Result<ExtractionResult, String> {
    let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("txt");
    Ok(ExtractionResult::new(text, ext))
}

/// Extract text from an RTF file (lightweight parser, no external deps).
fn extract_rtf(file_path: &str) -> Result<ExtractionResult, String> {
    let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let content = String::from_utf8_lossy(&bytes);
    let text = parse_rtf(&content);
    Ok(ExtractionResult::new(text, "rtf"))
}

/// Lightweight RTF parser.
fn parse_rtf(input: &str) -> String {
    let mut output = String::new();
    let mut chars = input.chars().peekable();
    let mut depth: i32 = 0;
    let mut skip_group = false;
    let mut skip_depth = 0;

    // Groups to skip
    let skip_groups = [
        "fonttbl", "colortbl", "stylesheet", "info", "pict", "header", "footer",
        "footnote", "annotation",
    ];

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                depth += 1;
                if skip_group && depth <= skip_depth {
                    continue;
                }
            }
            '}' => {
                if skip_group && depth == skip_depth {
                    skip_group = false;
                }
                depth -= 1;
            }
            '\\' if !skip_group => {
                // Control word
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphabetic() {
                        word.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }

                if skip_groups.contains(&word.as_str()) {
                    skip_group = true;
                    skip_depth = depth;
                    continue;
                }

                match word.as_str() {
                    "par" | "line" => output.push('\n'),
                    "tab" => output.push('\t'),
                    "u" => {
                        // Unicode escape: \uN
                        let mut num_str = String::new();
                        if let Some(&c) = chars.peek() {
                            if c == '-' || c.is_ascii_digit() {
                                num_str.push(c);
                                chars.next();
                                while let Some(&c) = chars.peek() {
                                    if c.is_ascii_digit() {
                                        num_str.push(c);
                                        chars.next();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        if let Ok(code) = num_str.parse::<i32>() {
                            let code = if code < 0 { code + 65536 } else { code };
                            if let Some(c) = char::from_u32(code as u32) {
                                output.push(c);
                            }
                        }
                        // Skip replacement character
                        if let Some(&c) = chars.peek() {
                            if c == '?' || c == '*' {
                                chars.next();
                            }
                        }
                    }
                    _ => {
                        // Skip numeric parameter
                        if let Some(&c) = chars.peek() {
                            if c == '-' || c.is_ascii_digit() {
                                chars.next();
                                while let Some(&c) = chars.peek() {
                                    if c.is_ascii_digit() {
                                        chars.next();
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        // Consume delimiter space
                        if let Some(&' ') = chars.peek() {
                            chars.next();
                        }
                    }
                }
            }
            '\'' if !skip_group => {
                // Hex escape: \'XX
                // Actually this comes after backslash, handled above
            }
            _ if !skip_group && depth >= 1 => {
                if ch != '\r' && ch != '\n' {
                    output.push(ch);
                }
            }
            _ => {}
        }
    }

    output.trim().to_string()
}

/// Extract text from an EML (email) file.
fn extract_eml(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    let mut in_headers = true;
    let mut headers = HashMap::new();

    for line in content.lines() {
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim().to_string();
                // Include important headers
                if ["from", "to", "subject", "date", "cc", "bcc"].contains(&key.as_str()) {
                    text.push_str(&format!("{}: {}\n", key, value));
                    headers.insert(key, value);
                }
            }
        } else {
            text.push_str(line);
            text.push('\n');
        }
    }

    let mut result = ExtractionResult::new(text, "eml");
    for (k, v) in headers {
        result = result.with_metadata(&k, &v);
    }
    Ok(result)
}

/// Extract text from ZIP-based formats (docx, xlsx, pptx).
fn extract_zip_based(file_path: &str) -> Result<ExtractionResult, String> {
    let file = std::fs::File::open(file_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut text = String::new();

    // Detect format by checking for key files
    let is_docx = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|f| f.name().starts_with("word/"))
            .unwrap_or(false)
    });
    let is_xlsx = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|f| f.name().starts_with("xl/"))
            .unwrap_or(false)
    });
    let is_pptx = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|f| f.name().starts_with("ppt/"))
            .unwrap_or(false)
    });

    let format = if is_docx {
        "docx"
    } else if is_xlsx {
        "xlsx"
    } else if is_pptx {
        "pptx"
    } else {
        "zip"
    };

    // Extract XML content from relevant files
    let xml_paths: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let file = archive.by_index(i).ok()?;
            let name = file.name().to_string();
            if name.ends_with(".xml") {
                match format {
                    "docx" if name.starts_with("word/") => Some(name),
                    "xlsx" if name.starts_with("xl/worksheets/") || name.contains("sharedStrings") => {
                        Some(name)
                    }
                    "pptx" if name.starts_with("ppt/slides/") => Some(name),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect();

    let mut total_read: u64 = 0;
    let mut entry_count: usize = 0;

    for xml_path in xml_paths {
        if entry_count >= MAX_EXTRACT_FILE_COUNT {
            break;
        }
        if let Ok(mut file) = archive.by_name(&xml_path) {
            // Skip entries larger than the per-entry limit
            if file.size() > MAX_EXTRACT_ENTRY_SIZE {
                continue;
            }
            // Check total budget before reading
            if total_read + file.size() > MAX_EXTRACT_TOTAL_SIZE {
                break;
            }
            use std::io::Read;
            let mut xml_content = String::new();
            if file.read_to_string(&mut xml_content).is_ok() {
                total_read += xml_content.len() as u64;
                entry_count += 1;
                // Simple XML text extraction: strip tags
                text.push_str(&strip_xml_tags(&xml_content));
                text.push('\n');
            }
        }
    }

    Ok(ExtractionResult::new(text.trim().to_string(), format))
}

/// Simple XML tag stripper that preserves text content.
fn strip_xml_tags(xml: &str) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    let mut last_was_close = false;

    for ch in xml.chars() {
        match ch {
            '<' => {
                in_tag = true;
                last_was_close = false;
            }
            '>' => {
                in_tag = false;
                last_was_close = true;
            }
            _ if !in_tag => {
                if last_was_close && !output.is_empty() && !output.ends_with(' ') && !output.ends_with('\n') {
                    // Add space between text from different tags
                }
                output.push(ch);
                last_was_close = false;
            }
            _ => {}
        }
    }

    // Clean up: collapse whitespace
    let mut result = String::new();
    let mut prev_space = false;
    for ch in output.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }

    result.trim().to_string()
}

// ---------------------------------------------------------------------------
// Contact file extractors
// ---------------------------------------------------------------------------

/// Extract text from vCard (.vcf) files.
///
/// Handles vCard 2.1, 3.0, and 4.0. Extracts all PII-bearing properties:
/// name, email, phone, address, birthday, organization, notes.
/// Supports line folding, quoted-printable encoding, and multiple contacts.
fn extract_vcard(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let unfolded = unfold_lines(&content);
    let mut text = String::new();
    let mut contact_count = 0u32;
    let mut in_vcard = false;

    for line in unfolded.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("BEGIN:VCARD") {
            in_vcard = true;
            contact_count += 1;
            if contact_count > 1 {
                text.push_str("\n---\n");
            }
            continue;
        }
        if trimmed.eq_ignore_ascii_case("END:VCARD") {
            in_vcard = false;
            continue;
        }
        if !in_vcard {
            continue;
        }

        // Parse property: split on first unescaped colon
        let (prop_with_params, raw_value) = match split_vcard_line(trimmed) {
            Some(pair) => pair,
            None => continue,
        };

        // Extract property name (before any ;TYPE= params)
        let prop_name = prop_with_params
            .split(';')
            .next()
            .unwrap_or("")
            .to_uppercase();

        // Decode value (handle quoted-printable)
        let value = if prop_with_params.to_uppercase().contains("ENCODING=QUOTED-PRINTABLE") {
            decode_quoted_printable(raw_value)
        } else {
            raw_value.to_string()
        };

        // Extract type label if present
        let type_label = extract_vcard_type(&prop_with_params);

        match prop_name.as_str() {
            "FN" => {
                text.push_str(&format!("Name: {}\n", value));
            }
            "N" => {
                // N:family;given;additional;prefix;suffix
                let parts: Vec<&str> = value.split(';').collect();
                let name_parts: Vec<&str> = parts
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !name_parts.is_empty() {
                    text.push_str(&format!("Structured Name: {}\n", name_parts.join(" ")));
                }
            }
            "EMAIL" => {
                let label = type_label.as_deref().unwrap_or("Email");
                text.push_str(&format!("{}: {}\n", label, value));
            }
            "TEL" => {
                let label = type_label.as_deref().unwrap_or("Phone");
                text.push_str(&format!("{}: {}\n", label, value));
            }
            "ADR" => {
                // ADR: PO Box;extended;street;city;state;postal;country
                let parts: Vec<&str> = value.split(';').collect();
                let addr_parts: Vec<&str> = parts
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !addr_parts.is_empty() {
                    let label = type_label.as_deref().unwrap_or("Address");
                    text.push_str(&format!("{}: {}\n", label, addr_parts.join(", ")));
                }
            }
            "BDAY" => {
                text.push_str(&format!("Birthday: {}\n", value));
            }
            "ORG" => {
                let org = value.replace(';', ", ");
                text.push_str(&format!("Organization: {}\n", org));
            }
            "TITLE" => {
                text.push_str(&format!("Title: {}\n", value));
            }
            "NOTE" => {
                text.push_str(&format!("Note: {}\n", value));
            }
            "URL" => {
                text.push_str(&format!("URL: {}\n", value));
            }
            "GENDER" => {
                text.push_str(&format!("Gender: {}\n", value));
            }
            "NICKNAME" => {
                text.push_str(&format!("Nickname: {}\n", value));
            }
            "CATEGORIES" => {
                text.push_str(&format!("Categories: {}\n", value));
            }
            "ROLE" => {
                text.push_str(&format!("Role: {}\n", value));
            }
            "GEO" => {
                text.push_str(&format!("Geo: {}\n", value));
            }
            "IMPP" | "X-JABBER" | "X-SKYPE-USERNAME" | "X-AIM" => {
                text.push_str(&format!("IM: {}\n", value));
            }
            "X-SOCIALPROFILE" => {
                text.push_str(&format!("Social: {}\n", value));
            }
            _ => {
                // Skip VERSION, PRODID, UID, REV, PHOTO, LOGO, SOUND, KEY, etc.
            }
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "vcf");
    result = result.with_metadata("contact_count", &contact_count.to_string());
    Ok(result)
}

/// Split a vCard line into (property+params, value) at the first unescaped colon.
fn split_vcard_line(line: &str) -> Option<(&str, &str)> {
    // Find first colon not inside a parameter value
    for (i, ch) in line.char_indices() {
        if ch == ':' {
            return Some((&line[..i], &line[i + 1..]));
        }
    }
    None
}

/// Extract TYPE parameter from vCard property params.
fn extract_vcard_type(prop_params: &str) -> Option<String> {
    let upper = prop_params.to_uppercase();
    for part in upper.split(';').skip(1) {
        let part = part.trim();
        if part.starts_with("TYPE=") {
            let types = part.strip_prefix("TYPE=").unwrap();
            return Some(types.replace(',', "/"));
        }
        // vCard 2.1 style: TEL;HOME;VOICE:
        if ["HOME", "WORK", "CELL", "VOICE", "FAX", "PAGER", "PREF"]
            .contains(&part)
        {
            return Some(part.to_string());
        }
    }
    None
}

/// Unfold continuation lines (RFC 6350: CRLF + space/tab = continuation).
fn unfold_lines(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\r' {
            // Check for \r\n followed by space/tab
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume \n
                if chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
                    chars.next(); // consume space/tab — line continuation
                    continue;
                }
                result.push('\n');
            } else {
                result.push(ch);
            }
        } else if ch == '\n' {
            // Check for \n followed by space/tab (Unix line endings)
            if chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
                chars.next(); // consume space/tab — line continuation
                continue;
            }
            result.push('\n');
        } else {
            result.push(ch);
        }
    }

    result
}

/// Decode quoted-printable encoded text.
fn decode_quoted_printable(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len() {
                if bytes[i + 1] == b'\r' || bytes[i + 1] == b'\n' {
                    // Soft line break
                    i += if bytes[i + 1] == b'\r' && i + 2 < bytes.len() && bytes[i + 2] == b'\n' {
                        3
                    } else {
                        2
                    };
                    continue;
                }
                if let (Some(hi), Some(lo)) = (
                    hex_digit(bytes[i + 1]),
                    hex_digit(bytes[i + 2]),
                ) {
                    result.push(hi * 16 + lo);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i]);
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8_lossy(&result).to_string()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Extract text from Windows Contacts (.contact) XML files.
fn extract_windows_contact(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();

    // Extract text from known PII-bearing XML elements
    let pii_elements = [
        ("FullName", "Name"),
        ("GivenName", "Given Name"),
        ("FamilyName", "Family Name"),
        ("Prefix", "Prefix"),
        ("Suffix", "Suffix"),
        ("Nickname", "Nickname"),
        ("Address", "Email"),
        ("Number", "Phone"),
        ("StreetAddress", "Street"),
        ("City", "City"),
        ("StateOrProvince", "State"),
        ("PostalCode", "Postal Code"),
        ("Country", "Country"),
        ("Birthday", "Birthday"),
        ("OrganizationName", "Organization"),
        ("Department", "Department"),
        ("JobTitle", "Job Title"),
        ("URL", "URL"),
        ("Note", "Note"),
        ("Gender", "Gender"),
    ];

    for (element, label) in &pii_elements {
        let open_tag = format!("<c:{}>", element);
        let close_tag = format!("</c:{}>", element);
        // Also handle without namespace prefix
        let open_tag2 = format!("<{}>", element);
        let close_tag2 = format!("</{}>", element);

        for (open, close) in [(&open_tag, &close_tag), (&open_tag2, &close_tag2)] {
            let mut search_from = 0;
            while let Some(start) = content[search_from..].find(open.as_str()) {
                let abs_start = search_from + start + open.len();
                if let Some(end) = content[abs_start..].find(close.as_str()) {
                    let value = content[abs_start..abs_start + end].trim();
                    if !value.is_empty() && !value.starts_with('<') {
                        text.push_str(&format!("{}: {}\n", label, value));
                    }
                    search_from = abs_start + end + close.len();
                } else {
                    break;
                }
            }
        }
    }

    if text.is_empty() {
        // Fallback: strip all XML tags
        text = strip_xml_tags(&content);
    }

    Ok(ExtractionResult::new(text.trim().to_string(), "contact"))
}

/// Extract text from LDIF (.ldif) files.
///
/// Extracts PII-bearing LDAP attributes: cn, sn, givenName, mail,
/// telephoneNumber, postalAddress, street, l, st, postalCode, title, o, ou.
fn extract_ldif(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    let mut record_count = 0u32;

    let pii_attrs: HashMap<&str, &str> = [
        ("cn", "Name"),
        ("sn", "Surname"),
        ("givenname", "Given Name"),
        ("displayname", "Display Name"),
        ("mail", "Email"),
        ("telephonenumber", "Phone"),
        ("facsimiletelephonenumber", "Fax"),
        ("mobile", "Mobile"),
        ("homephone", "Home Phone"),
        ("postaladdress", "Address"),
        ("street", "Street"),
        ("l", "City"),
        ("st", "State"),
        ("postalcode", "Postal Code"),
        ("c", "Country"),
        ("o", "Organization"),
        ("ou", "Department"),
        ("title", "Title"),
        ("description", "Description"),
        ("uid", "User ID"),
        ("employeenumber", "Employee Number"),
        ("employeetype", "Employee Type"),
    ]
    .into_iter()
    .collect();

    // Unfold continuation lines (LDIF uses leading space for continuation)
    let mut unfolded_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous line
            if let Some(last) = unfolded_lines.last_mut() {
                last.push_str(line[1..].trim_start());
            }
        } else {
            unfolded_lines.push(line.to_string());
        }
    }

    for line in &unfolded_lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("dn:") {
            record_count += 1;
            if record_count > 1 {
                text.push_str("\n---\n");
            }
            continue;
        }
        // Skip changetype and control lines
        if line.starts_with("changetype:") || line.starts_with("control:") || line == "-" {
            continue;
        }

        // Parse attribute: value
        if let Some(colon_pos) = line.find(':') {
            let attr = line[..colon_pos].trim().to_lowercase();
            let mut value = line[colon_pos + 1..].trim().to_string();

            // Base64 encoded value (attr:: value)
            if value.starts_with(':') {
                let b64 = value[1..].trim();
                if let Ok(decoded) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    b64,
                ) {
                    value = String::from_utf8_lossy(&decoded).to_string();
                }
            }

            // LDIF postalAddress uses $ as line separator
            if attr == "postaladdress" {
                value = value.replace('$', ", ");
            }

            if let Some(label) = pii_attrs.get(attr.as_str()) {
                if !value.is_empty() {
                    text.push_str(&format!("{}: {}\n", label, value));
                }
            }
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "ldif");
    result = result.with_metadata("record_count", &record_count.to_string());
    Ok(result)
}

/// Extract text from jCard (JSON vCard, RFC 7095) files.
fn extract_jcard(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut text = String::new();

    // jCard can be a single vcard array or an array of vcards
    let vcards = if value.is_array() {
        let arr = value.as_array().unwrap();
        if arr.first().and_then(|v| v.as_str()) == Some("vcard") {
            // Single vcard: ["vcard", [...properties...]]
            vec![&value]
        } else {
            // Array of vcards
            arr.iter().collect()
        }
    } else {
        return Err("Expected JSON array for jCard".to_string());
    };

    for (i, vcard) in vcards.iter().enumerate() {
        if i > 0 {
            text.push_str("\n---\n");
        }

        let properties = match vcard.as_array() {
            Some(arr) if arr.len() >= 2 => {
                arr[1].as_array()
            }
            _ => continue,
        };

        let Some(props) = properties else { continue };

        for prop in props {
            let prop_arr = match prop.as_array() {
                Some(a) if a.len() >= 4 => a,
                _ => continue,
            };

            let name = prop_arr[0].as_str().unwrap_or("");
            let value_part = &prop_arr[3];

            let value_str = match value_part {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => {
                    // Structured value (N, ADR)
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
                _ => value_part.to_string(),
            };

            if value_str.is_empty() {
                continue;
            }

            // Extract type from parameters
            let params = prop_arr[1].as_object();
            let type_label = params
                .and_then(|p| p.get("type"))
                .map(|t| match t {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Array(a) => a
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join("/"),
                    _ => String::new(),
                })
                .filter(|s| !s.is_empty());

            match name {
                "fn" => text.push_str(&format!("Name: {}\n", value_str)),
                "n" => text.push_str(&format!("Structured Name: {}\n", value_str)),
                "email" => {
                    let label = type_label.as_deref().unwrap_or("Email");
                    text.push_str(&format!("{}: {}\n", label, value_str));
                }
                "tel" => {
                    let label = type_label.as_deref().unwrap_or("Phone");
                    // Strip tel: URI prefix
                    let phone = value_str.strip_prefix("tel:").unwrap_or(&value_str);
                    text.push_str(&format!("{}: {}\n", label, phone));
                }
                "adr" => {
                    let label = type_label.as_deref().unwrap_or("Address");
                    text.push_str(&format!("{}: {}\n", label, value_str));
                }
                "bday" => text.push_str(&format!("Birthday: {}\n", value_str)),
                "org" => text.push_str(&format!("Organization: {}\n", value_str)),
                "title" => text.push_str(&format!("Title: {}\n", value_str)),
                "note" => text.push_str(&format!("Note: {}\n", value_str)),
                "url" => text.push_str(&format!("URL: {}\n", value_str)),
                "gender" => text.push_str(&format!("Gender: {}\n", value_str)),
                "nickname" => text.push_str(&format!("Nickname: {}\n", value_str)),
                "geo" => text.push_str(&format!("Geo: {}\n", value_str)),
                "impp" => text.push_str(&format!("IM: {}\n", value_str)),
                _ => {}
            }
        }
    }

    Ok(ExtractionResult::new(text.trim().to_string(), "jcard"))
}

// ---------------------------------------------------------------------------
// ICS (iCalendar) extractor
// ---------------------------------------------------------------------------

/// Extract text from iCalendar (.ics) files.
///
/// Extracts PII-bearing properties from VEVENT, VTODO, VJOURNAL, VFREEBUSY:
/// summary, description, location, organizer, attendees, contacts, comments.
fn extract_ics(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let unfolded = unfold_lines(&content);
    let mut text = String::new();
    let mut event_count = 0u32;
    let mut in_component = false;

    for line in unfolded.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("BEGIN:VEVENT")
            || trimmed.starts_with("BEGIN:VTODO")
            || trimmed.starts_with("BEGIN:VJOURNAL")
            || trimmed.starts_with("BEGIN:VFREEBUSY")
        {
            in_component = true;
            event_count += 1;
            if event_count > 1 {
                text.push_str("\n---\n");
            }
            continue;
        }
        if trimmed.starts_with("END:VEVENT")
            || trimmed.starts_with("END:VTODO")
            || trimmed.starts_with("END:VJOURNAL")
            || trimmed.starts_with("END:VFREEBUSY")
        {
            in_component = false;
            continue;
        }

        // Also extract calendar-level properties
        if !in_component && !trimmed.starts_with("BEGIN:") && !trimmed.starts_with("END:") {
            // Calendar-level: X-WR-CALNAME, PRODID
            if let Some((prop, val)) = split_vcard_line(trimmed) {
                let prop_name = prop.split(';').next().unwrap_or("").to_uppercase();
                match prop_name.as_str() {
                    "X-WR-CALNAME" => text.push_str(&format!("Calendar: {}\n", val)),
                    _ => {}
                }
            }
            continue;
        }

        if !in_component {
            continue;
        }

        let (prop_with_params, value) = match split_vcard_line(trimmed) {
            Some(pair) => pair,
            None => continue,
        };

        let prop_name = prop_with_params
            .split(';')
            .next()
            .unwrap_or("")
            .to_uppercase();

        match prop_name.as_str() {
            "SUMMARY" => text.push_str(&format!("Summary: {}\n", value)),
            "DESCRIPTION" => text.push_str(&format!("Description: {}\n", value)),
            "LOCATION" => text.push_str(&format!("Location: {}\n", value)),
            "ORGANIZER" => {
                // ORGANIZER;CN=Name:mailto:email
                let cn = extract_ics_param(&prop_with_params, "CN");
                let email = value.strip_prefix("mailto:").or_else(|| value.strip_prefix("MAILTO:")).unwrap_or(&value);
                if let Some(name) = cn {
                    text.push_str(&format!("Organizer: {} <{}>\n", name, email));
                } else {
                    text.push_str(&format!("Organizer: {}\n", email));
                }
            }
            "ATTENDEE" => {
                let cn = extract_ics_param(&prop_with_params, "CN");
                let email = value.strip_prefix("mailto:").or_else(|| value.strip_prefix("MAILTO:")).unwrap_or(&value);
                if let Some(name) = cn {
                    text.push_str(&format!("Attendee: {} <{}>\n", name, email));
                } else {
                    text.push_str(&format!("Attendee: {}\n", email));
                }
            }
            "CONTACT" => text.push_str(&format!("Contact: {}\n", value)),
            "COMMENT" => text.push_str(&format!("Comment: {}\n", value)),
            "URL" => text.push_str(&format!("URL: {}\n", value)),
            "GEO" => text.push_str(&format!("Geo: {}\n", value)),
            "DTSTART" => text.push_str(&format!("Start: {}\n", value)),
            "DTEND" => text.push_str(&format!("End: {}\n", value)),
            "CATEGORIES" => text.push_str(&format!("Categories: {}\n", value)),
            _ => {}
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "ics");
    result = result.with_metadata("event_count", &event_count.to_string());
    Ok(result)
}

/// Extract a parameter value from an iCalendar property line.
/// e.g. extract_ics_param("ORGANIZER;CN=John Doe;ROLE=CHAIR", "CN") -> Some("John Doe")
fn extract_ics_param<'a>(prop_with_params: &'a str, param_name: &str) -> Option<&'a str> {
    let upper_param = param_name.to_uppercase();
    for part in prop_with_params.split(';').skip(1) {
        if let Some(eq_pos) = part.find('=') {
            let key = &part[..eq_pos];
            if key.eq_ignore_ascii_case(&upper_param) {
                let val = &part[eq_pos + 1..];
                // Strip surrounding quotes
                return Some(val.trim_matches('"'));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// MBOX email archive extractor
// ---------------------------------------------------------------------------

/// Extract text from MBOX (.mbox) email archives.
///
/// Parses "From " separator lines to split messages, then extracts
/// headers (From, To, Subject, Date, CC, BCC) and body text.
fn extract_mbox(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    let mut msg_count = 0u32;
    let mut in_headers = false;
    let mut in_body = false;

    for line in content.lines() {
        if line.starts_with("From ") && (line.len() > 5) {
            // New message separator
            if msg_count > 0 {
                text.push_str("\n---\n");
            }
            msg_count += 1;
            in_headers = true;
            in_body = false;
            continue;
        }

        if in_headers {
            if line.is_empty() {
                in_headers = false;
                in_body = true;
                continue;
            }
            // Extract PII headers
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim();
                if ["from", "to", "subject", "date", "cc", "bcc", "reply-to"]
                    .contains(&key.as_str())
                {
                    text.push_str(&format!("{}: {}\n", key, value));
                }
            }
        } else if in_body {
            // Skip quoted-printable encoding markers and MIME boundaries
            if line.starts_with("--") || line.starts_with("Content-") {
                continue;
            }
            text.push_str(line);
            text.push('\n');
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "mbox");
    result = result.with_metadata("message_count", &msg_count.to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// MHTML web archive extractor
// ---------------------------------------------------------------------------

/// Extract text from MHTML (.mhtml, .mht) web archive files.
///
/// Parses MIME multipart structure, extracts text/html and text/plain parts,
/// strips HTML tags from HTML content.
fn extract_mhtml(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();

    // Find boundary from Content-Type header
    let boundary = content
        .lines()
        .find_map(|line| {
            if line.to_lowercase().contains("boundary=") {
                let bnd = line.split("boundary=").nth(1)?;
                Some(bnd.trim_matches('"').trim_matches('\'').trim().to_string())
            } else {
                None
            }
        });

    if let Some(boundary) = boundary {
        let separator = format!("--{}", boundary);
        let parts: Vec<&str> = content.split(&separator).collect();

        for part in parts.iter().skip(1) {
            let part = part.trim_start_matches(['\r', '\n']);
            // Skip closing boundary
            if part.starts_with("--") {
                continue;
            }

            let mut is_text_html = false;
            let mut is_text_plain = false;
            let mut header_done = false;
            let mut body = String::new();

            for line in part.lines() {
                if !header_done {
                    if line.is_empty() {
                        header_done = true;
                        continue;
                    }
                    let lower = line.to_lowercase();
                    if lower.contains("content-type:") {
                        if lower.contains("text/html") {
                            is_text_html = true;
                        } else if lower.contains("text/plain") {
                            is_text_plain = true;
                        }
                    }
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }

            if is_text_plain {
                text.push_str(&body);
            } else if is_text_html {
                text.push_str(&strip_xml_tags(&body));
                text.push('\n');
            }
        }
    } else {
        // No boundary found — try to extract as single document
        // Check if there's HTML content after headers
        let mut header_done = false;
        for line in content.lines() {
            if !header_done {
                if line.is_empty() {
                    header_done = true;
                }
                // Extract from/to/subject headers
                if let Some(colon_pos) = line.find(':') {
                    let key = line[..colon_pos].trim().to_lowercase();
                    let value = line[colon_pos + 1..].trim();
                    if ["from", "to", "subject", "date"].contains(&key.as_str()) {
                        text.push_str(&format!("{}: {}\n", key, value));
                    }
                }
            } else {
                text.push_str(line);
                text.push('\n');
            }
        }
        // If it looks like HTML, strip tags
        if text.contains('<') && text.contains('>') {
            text = strip_xml_tags(&text);
        }
    }

    Ok(ExtractionResult::new(text.trim().to_string(), "mhtml"))
}

// ---------------------------------------------------------------------------
// WARC web archive extractor
// ---------------------------------------------------------------------------

/// Extract text from WARC (Web ARChive) files.
///
/// Parses WARC records, extracts text from response records.
fn extract_warc(file_path: &str) -> Result<ExtractionResult, String> {
    let content = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    let mut record_count = 0u32;
    let mut in_payload = false;
    let mut is_response = false;
    let mut past_http_headers = false;

    for line in content.lines() {
        if line.starts_with("WARC/") {
            // New WARC record header
            record_count += 1;
            in_payload = false;
            is_response = false;
            past_http_headers = false;
            continue;
        }

        if !in_payload {
            let lower = line.to_lowercase();
            if lower.starts_with("warc-type:") {
                let wtype = line.split(':').nth(1).unwrap_or("").trim().to_lowercase();
                is_response = wtype == "response" || wtype == "resource";
            }
            if lower.starts_with("warc-target-uri:") {
                let uri = line.split(':').nth(1).unwrap_or("").trim();
                if !uri.is_empty() {
                    text.push_str(&format!("URL: {}\n", line["WARC-Target-URI:".len()..].trim()));
                }
            }
            // Empty line separates WARC headers from payload
            if line.is_empty() {
                in_payload = true;
            }
            continue;
        }

        if !is_response {
            continue;
        }

        // Inside response payload — skip HTTP headers
        if !past_http_headers {
            if line.is_empty() {
                past_http_headers = true;
            }
            continue;
        }

        text.push_str(line);
        text.push('\n');
    }

    // Strip HTML tags from extracted content
    if text.contains('<') && text.contains('>') {
        text = strip_xml_tags(&text);
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "warc");
    result = result.with_metadata("record_count", &record_count.to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// OpenDocument (ODS/ODT/ODP) extractor
// ---------------------------------------------------------------------------

/// Extract text from OpenDocument format files (.odt, .ods, .odp).
///
/// These are ZIP archives containing XML content, similar to OOXML.
/// Main content is in content.xml (and optionally styles.xml for headers/footers).
fn extract_opendocument(file_path: &str) -> Result<ExtractionResult, String> {
    let file = std::fs::File::open(file_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut text = String::new();

    // Determine format from mimetype file
    let format = if let Ok(mut mt) = archive.by_name("mimetype") {
        use std::io::Read;
        let mut mimetype = String::new();
        mt.read_to_string(&mut mimetype).ok();
        if mimetype.contains("spreadsheet") {
            "ods"
        } else if mimetype.contains("presentation") {
            "odp"
        } else {
            "odt"
        }
    } else {
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("odt");
        ext
    };

    // Extract text from content.xml (primary content) and meta.xml (metadata)
    for xml_name in &["content.xml", "meta.xml", "styles.xml"] {
        if let Ok(mut file) = archive.by_name(xml_name) {
            // Skip entries larger than 100MB
            if file.size() > MAX_EXTRACT_ENTRY_SIZE {
                continue;
            }
            use std::io::Read;
            let mut xml_content = String::new();
            if file.read_to_string(&mut xml_content).is_ok() {
                text.push_str(&strip_xml_tags(&xml_content));
                text.push('\n');
            }
        }
    }

    Ok(ExtractionResult::new(text.trim().to_string(), format))
}

// ---------------------------------------------------------------------------
// MSG (Outlook email) extractor — requires `msg` feature
// ---------------------------------------------------------------------------

/// Extract text from Outlook MSG files using OLE2/CFB parsing.
#[cfg(feature = "msg")]
fn extract_msg(file_path: &str) -> Result<ExtractionResult, String> {
    let file = std::fs::File::open(file_path).map_err(|e| e.to_string())?;
    let mut comp = cfb::CompoundFile::open(file).map_err(|e| format!("Invalid MSG file: {}", e))?;
    let mut text = String::new();

    // MSG stores properties in streams like "__substg1.0_XXXX" where XXXX is the property tag
    // Common property tags (as stream names):
    // 0037 = Subject, 0042 = SentRepresentingName, 0065 = SentRepresentingEmail
    // 0C1A = SenderName, 0C1F = SenderEmail, 0E04 = DisplayTo
    // 0E03 = DisplayCc, 1000 = Body

    let property_streams: Vec<(String, &str)> = vec![
        ("__substg1.0_0037001F".to_string(), "Subject"),
        ("__substg1.0_0037001E".to_string(), "Subject"),
        ("__substg1.0_0C1A001F".to_string(), "From"),
        ("__substg1.0_0C1A001E".to_string(), "From"),
        ("__substg1.0_0C1F001F".to_string(), "From Email"),
        ("__substg1.0_0C1F001E".to_string(), "From Email"),
        ("__substg1.0_0E04001F".to_string(), "To"),
        ("__substg1.0_0E04001E".to_string(), "To"),
        ("__substg1.0_0E03001F".to_string(), "CC"),
        ("__substg1.0_0E03001E".to_string(), "CC"),
        ("__substg1.0_1000001F".to_string(), "Body"),
        ("__substg1.0_1000001E".to_string(), "Body"),
    ];

    for (stream_name, label) in &property_streams {
        let path = format!("/{}", stream_name);
        if let Ok(mut stream) = comp.open_stream(&path) {
            use std::io::Read;
            let mut buf = Vec::new();
            // Limit read to 100MB per stream to prevent memory exhaustion
            let mut limited = Read::take(&mut stream, MAX_EXTRACT_ENTRY_SIZE);
            if limited.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                // Try UTF-16LE first (001F suffix), then UTF-8/Latin1 (001E suffix)
                let content = if stream_name.ends_with("001F") {
                    // UTF-16LE
                    let u16s: Vec<u16> = buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&u16s)
                } else {
                    String::from_utf8_lossy(&buf).to_string()
                };

                let content = content.trim_end_matches('\0').trim();
                if !content.is_empty() {
                    text.push_str(&format!("{}: {}\n", label, content));
                }
            }
        }
    }

    Ok(ExtractionResult::new(text.trim().to_string(), "msg"))
}

// ---------------------------------------------------------------------------
// RAR archive extractor — requires `archives` feature
// ---------------------------------------------------------------------------

/// Extract text from RAR archives by listing file names and extracting text files.
#[cfg(feature = "archives")]
fn extract_rar(file_path: &str) -> Result<ExtractionResult, String> {
    let mut text = String::new();
    let mut file_count = 0u32;

    // List archive contents
    let archive = unrar::Archive::new(file_path)
        .open_for_listing()
        .map_err(|e| format!("Failed to open RAR: {}", e))?;

    let mut file_names = Vec::new();
    for entry in archive {
        if let Ok(entry) = entry {
            file_count += 1;
            file_names.push(entry.filename.to_string_lossy().to_string());
        }
    }

    text.push_str(&format!("RAR Archive ({} files):\n", file_count));
    for name in &file_names {
        text.push_str(&format!("  {}\n", name));
    }

    // Extract and read text content from small text files
    let text_extensions = ["txt", "csv", "tsv", "log", "json", "xml", "html", "yml",
        "yaml", "toml", "ini", "cfg", "conf", "md", "eml", "vcf", "ics", "sql", "env"];

    let tmp_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;

    // Use process mode to extract each file
    let archive = unrar::Archive::new(file_path)
        .open_for_processing()
        .map_err(|e| format!("Failed to open RAR for processing: {}", e))?;

    let mut cursor = archive;
    let mut total_extracted_size: u64 = 0;
    let mut extracted_count: usize = 0;
    while let Ok(Some(header)) = cursor.read_header() {
        let entry = header.entry();
        let name = entry.filename.to_string_lossy().to_string();

        // Check file count limit
        if extracted_count >= MAX_EXTRACT_FILE_COUNT {
            match header.skip() {
                Ok(next) => { cursor = next; continue; }
                Err(_) => break,
            }
        }

        // Validate entry name for path traversal BEFORE extraction
        let name_path = std::path::Path::new(&name);
        let has_traversal = name_path.components().any(|c| matches!(c, std::path::Component::ParentDir))
            || name_path.is_absolute();
        if has_traversal {
            match header.skip() {
                Ok(next) => { cursor = next; continue; }
                Err(_) => break,
            }
        }

        // Check total extracted size limit
        if total_extracted_size + entry.unpacked_size > MAX_EXTRACT_TOTAL_SIZE {
            match header.skip() {
                Ok(next) => { cursor = next; continue; }
                Err(_) => break,
            }
        }

        let ext = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if text_extensions.contains(&ext.as_str()) && entry.unpacked_size < 1_048_576 {
            total_extracted_size += entry.unpacked_size;
            extracted_count += 1;
            match header.extract_to(tmp_dir.path()) {
                Ok(next) => {
                    cursor = next;
                    // Sanitize path to prevent path traversal
                    if let Some(dest) = sanitize_archive_path(tmp_dir.path(), &name) {
                        if let Ok(content) = std::fs::read_to_string(&dest) {
                            text.push_str(&format!("\n--- {} ---\n", name));
                            let content: String = content.chars().take(100_000).collect();
                            text.push_str(&content);
                            text.push('\n');
                        }
                    }
                }
                Err(e) => {
                    // Try to continue despite error
                    text.push_str(&format!("\n--- {} (extraction error: {}) ---\n", name, e));
                    break;
                }
            }
        } else {
            match header.skip() {
                Ok(next) => cursor = next,
                Err(_) => break,
            }
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "rar");
    result = result.with_metadata("file_count", &file_count.to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// 7z archive extractor — requires `archives` feature
// ---------------------------------------------------------------------------

/// Extract text from 7z archives.
#[cfg(feature = "archives")]
fn extract_7z(file_path: &str) -> Result<ExtractionResult, String> {
    let mut text = String::new();
    let tmp_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;

    sevenz_rust::decompress_file(file_path, tmp_dir.path())
        .map_err(|e| format!("Failed to extract 7z: {}", e))?;

    let mut file_count = 0u32;
    let text_extensions = ["txt", "csv", "tsv", "log", "json", "xml", "html", "yml",
        "yaml", "toml", "ini", "cfg", "conf", "md", "eml", "vcf", "ics", "sql", "env"];

    // Walk extracted files
    fn walk_dir(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk_dir(&path, files);
                } else {
                    files.push(path);
                }
            }
        }
    }

    let mut files = Vec::new();
    walk_dir(tmp_dir.path(), &mut files);
    files.sort();

    // Canonicalize base path for path traversal checks
    let canonical_base = tmp_dir.path().canonicalize().unwrap_or_else(|_| tmp_dir.path().to_path_buf());

    // Archive bomb checks: enforce file count and total size limits
    if files.len() > MAX_EXTRACT_FILE_COUNT {
        return Err(format!(
            "7z archive exceeds maximum file count: {} (max {})",
            files.len(),
            MAX_EXTRACT_FILE_COUNT
        ));
    }
    let mut total_size: u64 = 0;
    for f in &files {
        if let Ok(meta) = f.metadata() {
            total_size += meta.len();
        }
    }
    if total_size > MAX_EXTRACT_TOTAL_SIZE {
        return Err(format!(
            "7z archive exceeds maximum extracted size: {} bytes (max {} bytes)",
            total_size,
            MAX_EXTRACT_TOTAL_SIZE
        ));
    }

    text.push_str(&format!("7z Archive ({} files):\n", files.len()));
    for f in &files {
        // Path traversal guard: verify canonical path is under temp dir
        if let Ok(canonical) = f.canonicalize() {
            if !canonical.starts_with(&canonical_base) {
                continue;
            }
        } else {
            continue;
        }
        if let Some(rel) = f.strip_prefix(tmp_dir.path()).ok() {
            text.push_str(&format!("  {}\n", rel.display()));
        }
        file_count += 1;
    }

    // Extract text from small text files (with path traversal guard)
    for f in &files {
        // Ensure file is actually under the temp dir using canonicalize
        if let Ok(canonical) = f.canonicalize() {
            if !canonical.starts_with(&canonical_base) {
                continue;
            }
        } else {
            continue;
        }

        let ext = f.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if text_extensions.contains(&ext.as_str()) {
            if let Ok(meta) = f.metadata() {
                if meta.len() < 1_048_576 {
                    if let Ok(content) = std::fs::read_to_string(f) {
                        let rel = f.strip_prefix(tmp_dir.path()).unwrap_or(f);
                        text.push_str(&format!("\n--- {} ---\n", rel.display()));
                        let content: String = content.chars().take(100_000).collect();
                        text.push_str(&content);
                        text.push('\n');
                    }
                }
            }
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "7z");
    result = result.with_metadata("file_count", &file_count.to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// Parquet extractor — requires `data-formats` feature
// ---------------------------------------------------------------------------

/// Extract text from Apache Parquet files.
///
/// Reads column data and formats as tab-separated text.
#[cfg(feature = "data-formats")]
fn extract_parquet(file_path: &str) -> Result<ExtractionResult, String> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::reader::RowIter;

    let file = std::fs::File::open(file_path).map_err(|e| e.to_string())?;
    let reader = SerializedFileReader::new(file)
        .map_err(|e| format!("Invalid Parquet file: {}", e))?;

    let metadata = reader.metadata();
    let schema = metadata.file_metadata().schema();
    let num_rows = metadata.file_metadata().num_rows();

    let mut text = String::new();

    // Write column headers
    let fields: Vec<String> = schema
        .get_fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    text.push_str(&fields.join("\t"));
    text.push('\n');

    // Read rows (limit to first 10000 rows for DLP scanning)
    let max_rows = 10_000usize;
    let iter = RowIter::from_file_into(Box::new(reader));

    let mut row_count = 0usize;
    for row in iter {
        if row_count >= max_rows {
            break;
        }
        let row = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Use Row's Display implementation which formats all fields
        let row_str: Vec<String> = row
            .get_column_iter()
            .map(|(_, field)| format!("{}", field))
            .collect();
        text.push_str(&row_str.join("\t"));
        text.push('\n');
        row_count += 1;
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "parquet");
    result = result.with_metadata("num_rows", &num_rows.to_string());
    result = result.with_metadata("num_columns", &fields.len().to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// SQLite extractor — requires `data-formats` feature
// ---------------------------------------------------------------------------

/// Extract text from SQLite database files.
///
/// Reads table contents and outputs as tab-separated text.
/// Scans all user tables (excludes sqlite_ internal tables).
#[cfg(feature = "data-formats")]
fn extract_sqlite(file_path: &str) -> Result<ExtractionResult, String> {
    let conn = rusqlite::Connection::open_with_flags(
        file_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Failed to open SQLite database: {}", e))?;

    let mut text = String::new();
    let max_rows_per_table = 5_000usize;

    // Get list of user tables
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| e.to_string())?;

    let tables: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    for table in &tables {
        // Reject table names with control characters or excessive length
        if table.len() > 256 || table.chars().any(|c| c.is_control()) {
            continue;
        }

        text.push_str(&format!("--- Table: {} ---\n", table));

        // Get column names
        let pragma_sql = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
        let mut pragma_stmt = conn.prepare(&pragma_sql).map_err(|e| e.to_string())?;
        let columns: Vec<String> = pragma_stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        text.push_str(&columns.join("\t"));
        text.push('\n');

        // Read rows
        let select_sql = format!(
            "SELECT * FROM \"{}\" LIMIT {}",
            table.replace('"', "\"\""),
            max_rows_per_table
        );
        let mut select_stmt = conn.prepare(&select_sql).map_err(|e| e.to_string())?;
        let col_count = columns.len();

        let mut rows = select_stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let values: Vec<String> = (0..col_count)
                .map(|i| {
                    row.get::<_, String>(i).unwrap_or_default()
                })
                .collect();
            text.push_str(&values.join("\t"));
            text.push('\n');
        }
        text.push('\n');
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "sqlite");
    result = result.with_metadata("table_count", &tables.len().to_string());
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_xml_tags() {
        let xml = "<root><para>Hello <b>World</b></para></root>";
        let text = strip_xml_tags(xml);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(!text.contains("<"));
    }

    #[test]
    fn test_parse_rtf_basic() {
        let rtf = r"{\rtf1\ansi Hello World\par Second line}";
        let text = parse_rtf(rtf);
        assert!(text.contains("Hello World"));
        assert!(text.contains("Second line"));
    }

    #[test]
    fn test_supported_extensions() {
        let exts = supported_extensions();
        assert!(exts.contains(&"txt".to_string()));
        assert!(exts.contains(&"rtf".to_string()));
        assert!(exts.contains(&"eml".to_string()));
    }

    #[test]
    fn test_extract_result_builder() {
        let result = ExtractionResult::new("test".to_string(), "txt")
            .with_warning("test warning")
            .with_metadata("key", "value");
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.metadata.get("key"), Some(&"value".to_string()));
    }

    use std::io::Write;

    fn write_temp(ext: &str, content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{}", ext))
            .tempfile()
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_extract_vcard_basic() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:John Doe\r\nEMAIL:john@example.com\r\nTEL:+1-555-123-4567\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
        assert!(result.text.contains("+1-555-123-4567"));
    }

    #[test]
    fn test_extract_vcard_structured_name() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;John;;Mr.;\r\nFN:Mr. John Doe\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Structured Name:"));
        assert!(result.text.contains("Doe"));
        assert!(result.text.contains("John"));
    }

    #[test]
    fn test_extract_vcard_address() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane\r\nADR;TYPE=HOME:;;123 Main St;Springfield;IL;62704;US\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("123 Main St"));
        assert!(result.text.contains("Springfield"));
    }

    #[test]
    fn test_extract_vcard_multi_contact() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Alice\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Alice"));
        assert!(result.text.contains("Bob"));
        assert!(result.text.contains("---")); // separator between contacts
    }

    #[test]
    fn test_extract_vcard_line_folding() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A Very Long Name That Gets\r\n Folded Across Lines\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        // After unfolding, continuation space is consumed, so words join directly
        assert!(result.text.contains("A Very Long Name That GetsFolded Across Lines"));
    }

    #[test]
    fn test_extract_vcard_birthday() {
        let f = write_temp("vcf", "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane\r\nBDAY:1990-05-15\r\nEND:VCARD\r\n");
        let result = extract_vcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Birthday: 1990-05-15"));
    }

    #[test]
    fn test_extract_ldif_basic() {
        let f = write_temp("ldif", "dn: cn=John Doe,ou=People,dc=example,dc=com\ncn: John Doe\nmail: john@example.com\ntelephonenumber: +1-555-987-6543\n\n");
        let result = extract_ldif(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
        assert!(result.text.contains("+1-555-987-6543"));
    }

    #[test]
    fn test_extract_ldif_multi_record() {
        let f = write_temp("ldif", "dn: cn=Alice,ou=People,dc=example,dc=com\ncn: Alice\nmail: alice@example.com\n\ndn: cn=Bob,ou=People,dc=example,dc=com\ncn: Bob\nmail: bob@example.com\n\n");
        let result = extract_ldif(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Alice"));
        assert!(result.text.contains("Bob"));
        assert!(result.text.contains("alice@example.com"));
        assert!(result.text.contains("bob@example.com"));
    }

    #[test]
    fn test_extract_jcard_basic() {
        let f = write_temp("json", r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text","John Doe"],["email",{},"text","john@example.com"],["tel",{},"uri","tel:+1-555-123-4567"]]]"#);
        let result = extract_jcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
        assert!(result.text.contains("+1-555-123-4567"));
    }

    #[test]
    fn test_extract_jcard_array() {
        let f = write_temp("json", r#"[["vcard",[["version",{},"text","4.0"],["fn",{},"text","Alice"]]],["vcard",[["version",{},"text","4.0"],["fn",{},"text","Bob"]]]]"#);
        let result = extract_jcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Alice"));
        assert!(result.text.contains("Bob"));
    }

    #[test]
    fn test_extract_windows_contact() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<contact:contact xmlns:contact="http://schemas.microsoft.com/Contact">
  <contact:NameCollection>
    <contact:Name>
      <contact:FormattedName>John Doe</contact:FormattedName>
      <contact:GivenName>John</contact:GivenName>
      <contact:FamilyName>Doe</contact:FamilyName>
    </contact:Name>
  </contact:NameCollection>
  <contact:EmailAddressCollection>
    <contact:EmailAddress>
      <contact:Address>john@example.com</contact:Address>
    </contact:EmailAddress>
  </contact:EmailAddressCollection>
  <contact:PhoneNumberCollection>
    <contact:PhoneNumber>
      <contact:Number>555-123-4567</contact:Number>
    </contact:PhoneNumber>
  </contact:PhoneNumberCollection>
</contact:contact>"#;
        let f = write_temp("contact", xml);
        let result = extract_windows_contact(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
        assert!(result.text.contains("555-123-4567"));
    }

    #[test]
    fn test_vcard_extension_registered() {
        let exts = supported_extensions();
        assert!(exts.contains(&"vcf".to_string()));
        assert!(exts.contains(&"vcard".to_string()));
        assert!(exts.contains(&"contact".to_string()));
        assert!(exts.contains(&"ldif".to_string()));
    }

    #[test]
    fn test_get_extractor_vcard() {
        assert!(get_extractor("test.vcf").is_some());
        assert!(get_extractor("test.vcard").is_some());
        assert!(get_extractor("test.contact").is_some());
        assert!(get_extractor("test.ldif").is_some());
    }

    #[test]
    fn test_decode_quoted_printable() {
        assert_eq!(decode_quoted_printable("Hello=20World"), "Hello World");
        assert_eq!(decode_quoted_printable("caf=C3=A9"), "café");
    }

    #[test]
    fn test_unfold_lines() {
        let input = "LINE1\r\n LINE1CONT\r\nLINE2\r\n\tLINE2CONT\r\n";
        let result = unfold_lines(input);
        // unfold normalizes \r\n to \n
        assert_eq!(result, "LINE1LINE1CONT\nLINE2LINE2CONT\n");
    }

    // --- ICS tests ---

    #[test]
    fn test_extract_ics_basic() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Team Meeting\r\nLOCATION:Room 101\r\nDTSTART:20260401T090000Z\r\nDTEND:20260401T100000Z\r\nORGANIZER;CN=Alice Smith:mailto:alice@example.com\r\nATTENDEE;CN=Bob Jones:mailto:bob@example.com\r\nDESCRIPTION:Discuss Q2 roadmap\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let f = write_temp("ics", ics);
        let result = extract_ics(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Team Meeting"));
        assert!(result.text.contains("Room 101"));
        assert!(result.text.contains("Alice Smith"));
        assert!(result.text.contains("alice@example.com"));
        assert!(result.text.contains("Bob Jones"));
        assert!(result.text.contains("bob@example.com"));
        assert!(result.text.contains("Discuss Q2 roadmap"));
    }

    #[test]
    fn test_extract_ics_multi_event() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Event 1\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:Event 2\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let f = write_temp("ics", ics);
        let result = extract_ics(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Event 1"));
        assert!(result.text.contains("Event 2"));
        assert!(result.text.contains("---"));
        assert_eq!(result.metadata.get("event_count"), Some(&"2".to_string()));
    }

    #[test]
    fn test_extract_ics_attendee_no_cn() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Test\r\nATTENDEE:mailto:user@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let f = write_temp("ics", ics);
        let result = extract_ics(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("user@example.com"));
    }

    // --- MBOX tests ---

    #[test]
    fn test_extract_mbox_basic() {
        let mbox = "From user@example.com Mon Jan  1 00:00:00 2026\nFrom: Alice <alice@example.com>\nTo: Bob <bob@example.com>\nSubject: Hello\nDate: Mon, 1 Jan 2026 00:00:00 +0000\n\nHi Bob, how are you?\n";
        let f = write_temp("mbox", mbox);
        let result = extract_mbox(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("alice@example.com"));
        assert!(result.text.contains("bob@example.com"));
        assert!(result.text.contains("Hello"));
        assert!(result.text.contains("Hi Bob"));
    }

    #[test]
    fn test_extract_mbox_multi_message() {
        let mbox = "From a@test.com Mon Jan  1 00:00:00 2026\nFrom: a@test.com\nSubject: First\n\nBody 1\n\nFrom b@test.com Tue Jan  2 00:00:00 2026\nFrom: b@test.com\nSubject: Second\n\nBody 2\n";
        let f = write_temp("mbox", mbox);
        let result = extract_mbox(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("First"));
        assert!(result.text.contains("Second"));
        assert!(result.text.contains("Body 1"));
        assert!(result.text.contains("Body 2"));
        assert_eq!(result.metadata.get("message_count"), Some(&"2".to_string()));
    }

    // --- MHTML tests ---

    #[test]
    fn test_extract_mhtml_basic() {
        let mhtml = "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"----=_Part_123\"\r\n\r\n------=_Part_123\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body><p>Hello World</p><p>Sensitive SSN: 123-45-6789</p></body></html>\r\n------=_Part_123--\r\n";
        let f = write_temp("mhtml", mhtml);
        let result = extract_mhtml(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Hello World"));
        assert!(result.text.contains("123-45-6789"));
    }

    #[test]
    fn test_extract_mhtml_text_plain() {
        let mhtml = "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"boundary42\"\r\n\r\n--boundary42\r\nContent-Type: text/plain\r\n\r\nPlain text content with email user@example.com\r\n--boundary42--\r\n";
        let f = write_temp("mht", mhtml);
        let result = extract_mhtml(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Plain text content"));
        assert!(result.text.contains("user@example.com"));
    }

    // --- WARC tests ---

    #[test]
    fn test_extract_warc_basic() {
        let warc = "WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: http://example.com/page\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Page content with phone 555-123-4567</body></html>\r\n\r\n";
        let f = write_temp("warc", warc);
        let result = extract_warc(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("555-123-4567"));
        assert!(result.text.contains("example.com"));
    }

    // --- OpenDocument tests ---

    #[test]
    fn test_extract_opendocument_odt() {
        // Create a minimal ODT file (ZIP with content.xml)
        let f = tempfile::Builder::new().suffix(".odt").tempfile().unwrap();
        {
            let file = std::fs::File::create(f.path()).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("mimetype", options).unwrap();
            zip.write_all(b"application/vnd.oasis.opendocument.text").unwrap();

            zip.start_file("content.xml", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\"?><office:document-content><office:body><office:text><text:p>Hello from ODT with email test@example.com</text:p></office:text></office:body></office:document-content>").unwrap();

            zip.finish().unwrap();
        }
        let result = extract_opendocument(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("Hello from ODT"));
        assert!(result.text.contains("test@example.com"));
    }

    // --- TSV / PEM extension tests ---

    #[test]
    fn test_tsv_registered() {
        assert!(get_extractor("data.tsv").is_some());
    }

    #[test]
    fn test_pem_registered() {
        assert!(get_extractor("server.pem").is_some());
        assert!(get_extractor("server.crt").is_some());
        assert!(get_extractor("private.key").is_some());
        assert!(get_extractor("cert.cer").is_some());
    }

    #[test]
    fn test_ics_registered() {
        assert!(get_extractor("calendar.ics").is_some());
    }

    #[test]
    fn test_mbox_registered() {
        assert!(get_extractor("mail.mbox").is_some());
    }

    #[test]
    fn test_mhtml_registered() {
        assert!(get_extractor("page.mhtml").is_some());
        assert!(get_extractor("page.mht").is_some());
    }

    #[test]
    fn test_warc_registered() {
        assert!(get_extractor("archive.warc").is_some());
    }

    #[test]
    fn test_opendocument_registered() {
        assert!(get_extractor("doc.odt").is_some());
        assert!(get_extractor("sheet.ods").is_some());
        assert!(get_extractor("pres.odp").is_some());
    }

    #[test]
    fn test_supported_extensions_new() {
        let exts = supported_extensions();
        assert!(exts.contains(&"tsv".to_string()));
        assert!(exts.contains(&"pem".to_string()));
        assert!(exts.contains(&"ics".to_string()));
        assert!(exts.contains(&"mbox".to_string()));
        assert!(exts.contains(&"mhtml".to_string()));
        assert!(exts.contains(&"warc".to_string()));
        assert!(exts.contains(&"odt".to_string()));
    }

    #[test]
    fn test_extract_ics_param() {
        assert_eq!(
            extract_ics_param("ORGANIZER;CN=John Doe;ROLE=CHAIR", "CN"),
            Some("John Doe")
        );
        assert_eq!(
            extract_ics_param("ATTENDEE;RSVP=TRUE;CN=\"Jane Smith\"", "CN"),
            Some("Jane Smith")
        );
        assert_eq!(
            extract_ics_param("ORGANIZER;CN=Test", "ROLE"),
            None
        );
    }

    #[test]
    fn test_detect_ics_content() {
        let f = write_temp("txt", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
        let result = detect_and_extract(f.path().to_str().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_mbox_content() {
        let f = write_temp("txt", "From user@test.com Mon Jan  1 00:00:00 2026\nFrom: user@test.com\nSubject: Test\n\nBody\n");
        let result = detect_and_extract(f.path().to_str().unwrap());
        assert!(result.is_some());
    }
}
