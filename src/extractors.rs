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

/// Maximum allowed compression ratio for a single archive entry
/// (uncompressed / compressed). Entries above this ratio are treated as
/// likely zip bombs and skipped. 100:1 accommodates text-heavy legit
/// content (docx/xlsx XML, source dumps, log files) while rejecting the
/// adversarial 10,000:1 and above patterns that burn CPU and RAM even
/// inside per-entry and total-size caps.
const MAX_ZIP_COMPRESSION_RATIO: u64 = 100;

/// Extensions inside an archive whose bytes are scanned as plain text.
/// Shared by the ZIP, RAR and 7z extractors so a sensitive file is caught
/// the same way whatever container it arrived in — a `.txt` full of card
/// numbers must not slip through just because it was zipped rather than
/// 7z'd. Keep the three walkers pointed at this one list.
const ARCHIVE_TEXT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "tsv", "log", "json", "xml", "html", "yml", "yaml", "toml", "ini", "cfg", "conf",
    "md", "eml", "vcf", "ics", "sql", "env",
];

/// Whether an archive entry name has a text extension we scan by content.
/// Case-insensitive on the extension only.
fn archive_entry_is_text(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| ARCHIVE_TEXT_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Archive/container extensions that appear *inside* another archive. We do
/// not recurse into these — deep recursion is where zip-bomb amplification
/// lives — but we must not skip them silently either: a sensitive file one
/// archive layer deep would otherwise pass with zero findings and no signal.
/// Instead the extractors surface a warning so an analyst sees that unscanned
/// content exists. Keep in sync with the formats the extractors otherwise
/// handle at the top level.
const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "tar", "cab", "lz", "lzma", "z",
    "zst", "zstd", "arj", "lha", "lzh",
];

/// Whether an archive entry is itself a nested archive/container.
fn archive_entry_is_nested_archive(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| NESTED_ARCHIVE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Cap on how many distinct nested-archive warnings we record for one file, so
/// a container packed with 10k inner archives can't produce 10k warning lines.
const MAX_NESTED_ARCHIVE_WARNINGS: usize = 20;

/// Check whether a ZIP entry's declared size vs. its compressed size
/// exceeds the configured bomb threshold. Returns true if the entry
/// should be skipped. Entries with a compressed_size of 0 (e.g. stored
/// directory headers) are treated as safe since there is nothing to
/// expand.
fn zip_entry_is_bomb(uncompressed: u64, compressed: u64) -> bool {
    if compressed == 0 {
        return false;
    }
    uncompressed / compressed > MAX_ZIP_COMPRESSION_RATIO
}

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
    if let Some(func) = CUSTOM_EXTRACTORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&ext)
    {
        return Some(*func);
    }

    // Built-in extractors
    match ext.as_str() {
        // Plain text formats (including TSV and certificate/key files)
        "txt" | "csv" | "tsv" | "log" | "json" | "xml" | "html" | "htm" | "yaml" | "yml"
        | "toml" | "ini" | "cfg" | "conf" | "md" | "rst" | "py" | "js" | "ts" | "java" | "go"
        | "rs" | "rb" | "php" | "sh" | "bat" | "ps1" | "sql" | "env" | "c" | "cpp" | "h"
        | "hpp" | "css" | "scss" | "less" | "jsx" | "tsx" | "vue" | "svelte" | "swift" | "kt"
        | "scala" | "r" | "m" | "mm" | "pem" | "cer" | "crt" | "key" | "pub" | "csr" => {
            Some(extract_plain_text)
        }

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

        // Barcode / QR code images
        #[cfg(feature = "barcode")]
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "tif" | "webp" => Some(extract_barcode),

        // Cabinet archives
        "cab" => Some(extract_cab),

        // Generic data files
        "dat" => Some(extract_dat),

        _ => {
            // Try format detection by magic bytes
            detect_and_extract(file_path)
        }
    }
}

/// Extract text from a file, auto-detecting format.
pub fn extract_text(file_path: &str) -> Result<ExtractionResult, String> {
    extract_text_with_policy(file_path, OnFormatMismatch::from_env())
}

/// Extract text with an explicit format-mismatch policy.
///
/// Separate from [`extract_text`] so a caller carrying its own configuration
/// can pass it, and so the policy is testable without mutating
/// process-global environment variables from tests that run in parallel.
pub fn extract_text_with_policy(
    file_path: &str,
    on_mismatch: OnFormatMismatch,
) -> Result<ExtractionResult, String> {
    // Check file size
    let metadata = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    if metadata.len() as usize > MAX_EXTRACT_SIZE {
        return Err(format!(
            "File too large: {} bytes (max {})",
            metadata.len(),
            MAX_EXTRACT_SIZE
        ));
    }

    // ---------------------------------------------------------------------
    // Arbitrate between what the name claims and what the bytes prove.
    //
    // The filename is the weakest signal there is and the only one an
    // attacker changes for free. FUTURE.md's corroboration entry states the
    // rule for exactly this shape of problem: an attacker-controlled signal
    // may weight a decision, it must never gate detection. Dispatching on the
    // extension alone gates it — `zip -q p.zip secrets.txt && mv p.zip
    // notes.txt` sent a deflated archive to the plain-text reader, which read
    // the compressed bytes as lossy UTF-8, found nothing, and returned a
    // faithful clean result with no warning at all.
    //
    // So the bytes lead and the name corroborates:
    //
    //   agree      the extension refines the family (zip -> docx vs odt vs
    //              a plain archive) and is used, because within a proven
    //              family it is the only thing that can tell them apart
    //   disagree   the content wins, and the disagreement is recorded — it is
    //              a finding in its own right, not a mistake to correct in
    //              silence
    //   no proof   the extension is used, exactly as before. Text has no
    //              signature, so this is the common path and it is unchanged
    //
    // Recorded in `metadata`, not `warnings`: a warning means "content we did
    // not read", and the milter defers on it. A renamed file that we then
    // read correctly *was* read. Conflating the two would defer every message
    // carrying a misnamed attachment.
    // ---------------------------------------------------------------------
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    let declared = ext.as_deref().and_then(declared_family);
    let actual = sniff_family(file_path);

    if let (Some(a), Some(e)) = (actual, ext.as_deref()) {
        if declared != Some(a) {
            let mismatch = format!("declared .{e}, content is {}", a.name());

            // Surfaced at warn level with structured fields, because this is
            // the shape of deliberate exfiltration rather than of an
            // ordinary mislabelled file — it is the line an operator alerts
            // on.
            if on_mismatch != OnFormatMismatch::Ignore {
                tracing::warn!(
                    path = %file_path,
                    declared_extension = %e,
                    content_family = %a.name(),
                    policy = ?on_mismatch,
                    "file extension contradicts its content"
                );
            }

            if on_mismatch == OnFormatMismatch::Reject {
                // Deliberately an extraction error: every caller already
                // fails closed on one, so the configured refusal reaches the
                // CLI's exit code, siphon-fs's response and the milter's
                // verdict without any of them having to learn a new signal.
                return Err(format!("refusing file: {mismatch}"));
            }

            if let Some(extractor) = detect_and_extract(file_path) {
                return extractor(file_path).map(|r| {
                    if on_mismatch == OnFormatMismatch::Ignore {
                        r
                    } else {
                        r.with_metadata("format_mismatch", &mismatch)
                    }
                });
            }
        }
    }

    if let Some(extractor) = get_extractor(file_path) {
        extractor(file_path)
    } else {
        // Nothing claimed this file. Whether reading it as text is faithful
        // depends on the content, not the extension: a `.weirdext` holding
        // prose is read correctly as prose, while a truncated Office file is
        // binary we failed to parse and must not be reported as merely clean.
        //
        // Deciding on the extension instead would defer every message
        // carrying an unfamiliar but perfectly textual attachment, which
        // under the fail-closed mail policy is a self-inflicted outage.
        if looks_like_text(file_path) {
            extract_plain_text(file_path)
        } else {
            extract_unparsed_binary(file_path)
        }
    }
}

/// Is this file plausibly text?
///
/// Sampled from the head rather than the whole file: the question is what
/// kind of thing this is, and a 30 MB read to answer it would be on the
/// milter's critical path for every unrecognised attachment.
fn looks_like_text(file_path: &str) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(file_path) else {
        return false;
    };
    let mut buf = [0u8; 8192];
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    if n == 0 {
        // An empty file is not binary, and calling it unparsed would warn
        // about nothing.
        return true;
    }
    let sample = &buf[..n];
    // A NUL byte is the strongest single signal of binary content; no text
    // encoding this scanner handles produces one.
    if sample.contains(&0) {
        return false;
    }
    // Otherwise judge by how much of it is printable. Compressed or encoded
    // payloads are close to uniformly distributed over all 256 values, so
    // they fail this comfortably, while UTF-8 prose passes it.
    let printable = sample
        .iter()
        .filter(|&&b| {
            b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80
        })
        .count();
    printable * 100 / n >= 85
}

/// List all supported extensions (built-in + custom).
pub fn supported_extensions() -> Vec<String> {
    let mut exts: Vec<String> = vec![
        "txt", "csv", "tsv", "log", "json", "xml", "html", "htm", "yaml", "yml", "toml", "ini",
        "cfg", "conf", "md", "rst", "py", "js", "ts", "java", "go", "rs", "rb", "php", "sh", "bat",
        "ps1", "sql", "env", "rtf", "eml", "vcf", "vcard", "contact", "ldif", "c", "cpp", "h",
        "hpp", "css", "scss", "pem", "cer", "crt", "key", "pub", "csr", "ics", "ical", "mbox",
        "mbx", "mhtml", "mht", "warc", "odt", "ods", "odp", "cab", "dat",
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

/// What to do when a file's name contradicts its content.
///
/// A file lying about what it is carries information beyond the payload
/// inside it. `report.csv` that is really a deflated ZIP is not a mislabelled
/// file — nothing produces that by accident — and some deployments will want
/// to stop it at the door regardless of whether the archive turns out to hold
/// anything sensitive. Others will want it recorded and passed on, because a
/// misnamed file is also what you get from a badly written export job.
///
/// Both are defensible, so it is a policy rather than a decision baked into
/// the extractor. Set with `SIPHON_ON_FORMAT_MISMATCH`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum OnFormatMismatch {
    /// Read by content, record the contradiction in
    /// `metadata["format_mismatch"]`, log it at warn level, and carry on.
    ///
    /// The default, because it is the one that cannot cause an outage. The
    /// file is still scanned — better than before the arbitration existed,
    /// where it was read by name and came back clean.
    #[default]
    Flag,
    /// Refuse the file: extraction returns `Err`.
    ///
    /// Every caller already fails closed on an extraction error, so this maps
    /// onto each service's existing vocabulary without new plumbing — the CLI
    /// exits non-zero, siphon-fs reports the file not scanned, and the milter
    /// counts the part uninspected, which under its default policy defers the
    /// message.
    Reject,
    /// Dispatch on content but record nothing.
    ///
    /// For a pipeline where misnamed files are routine and the noise is not
    /// worth it. Note this still fixes the bypass — the content is what gets
    /// read either way; only the reporting is suppressed.
    Ignore,
}

impl OnFormatMismatch {
    /// Parse from a configuration string.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "flag" => Ok(OnFormatMismatch::Flag),
            "reject" => Ok(OnFormatMismatch::Reject),
            "ignore" => Ok(OnFormatMismatch::Ignore),
            other => Err(format!(
                "invalid SIPHON_ON_FORMAT_MISMATCH {other:?} (expected flag, reject or ignore)"
            )),
        }
    }

    /// The configured policy, from `SIPHON_ON_FORMAT_MISMATCH`.
    ///
    /// An unparseable value falls back to the default rather than failing:
    /// this is read on the scan path, and a typo in an environment variable
    /// must not take a scanner down. It is logged once per read.
    pub fn from_env() -> Self {
        match std::env::var("SIPHON_ON_FORMAT_MISMATCH") {
            Ok(v) if !v.trim().is_empty() => Self::parse(&v).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "falling back to the default format-mismatch policy");
                Self::default()
            }),
            _ => Self::default(),
        }
    }
}

/// A container family identified from a file's own bytes.
///
/// Deliberately coarser than "format": the question this answers is *what
/// kind of thing is this*, not *which reader gets it*. ZIP is one family
/// covering docx, xlsx, pptx, odt and a plain archive, because at the byte
/// level they are indistinguishable — the extension is the thing that tells
/// them apart, and there it is corroborating evidence rather than a claim to
/// be taken on trust.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentFamily {
    Zip,
    Ole2,
    Pdf,
    Rtf,
    Rar,
    SevenZ,
    Parquet,
    Sqlite,
    Image,
}

impl ContentFamily {
    fn name(self) -> &'static str {
        match self {
            ContentFamily::Zip => "zip",
            ContentFamily::Ole2 => "ole2",
            ContentFamily::Pdf => "pdf",
            ContentFamily::Rtf => "rtf",
            ContentFamily::Rar => "rar",
            ContentFamily::SevenZ => "7z",
            ContentFamily::Parquet => "parquet",
            ContentFamily::Sqlite => "sqlite",
            ContentFamily::Image => "image",
        }
    }
}

/// What the *filename* claims this file is, or `None` for the text family and
/// for formats with no binary signature (eml, vcf, ics, mbox, warc, cab, dat).
///
/// `None` is not "unknown" — it is "claims to be something a text reader can
/// handle", which is precisely the claim that must not be taken on trust.
fn declared_family(ext: &str) -> Option<ContentFamily> {
    match ext {
        "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "jar" => {
            Some(ContentFamily::Zip)
        }
        "msg" | "doc" | "xls" | "ppt" => Some(ContentFamily::Ole2),
        "pdf" => Some(ContentFamily::Pdf),
        "rtf" => Some(ContentFamily::Rtf),
        "rar" => Some(ContentFamily::Rar),
        "7z" => Some(ContentFamily::SevenZ),
        "parquet" => Some(ContentFamily::Parquet),
        "db" | "sqlite" | "sqlite3" => Some(ContentFamily::Sqlite),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "tif" | "webp" => {
            Some(ContentFamily::Image)
        }
        _ => None,
    }
}

/// Identify the container family from the file's own bytes.
///
/// # Corroboration, at the byte level
///
/// Signatures are not equally good evidence, and acting on a weak one alone
/// is how a sniffer becomes its own bug. BMP's signature is the two ASCII
/// bytes `BM` — every CSV whose first column begins "BM" carries it — so it
/// is accepted only when the 4-byte size field behind it also matches the
/// real file length. Two independent facts agreeing is evidence; one weak
/// fact is a guess.
///
/// SQLite is checked against its full 16-byte `SQLite format 3\0` string
/// rather than the leading six characters, for the same reason: `SQLite` on
/// its own is a word that appears at the start of plenty of documentation.
///
/// Returns `None` when nothing is proven, which is the honest answer for
/// text — and `None` is what leaves the extension in charge, exactly as
/// before.
pub fn sniff_family(file_path: &str) -> Option<ContentFamily> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    let file = std::fs::File::open(file_path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    let n = reader.read(&mut buf).ok()?;
    let b = &buf[..n];

    if b.len() >= 4 && &b[..4] == b"%PDF" {
        return Some(ContentFamily::Pdf);
    }
    if b.len() >= 5 && &b[..5] == b"{\\rtf" {
        return Some(ContentFamily::Rtf);
    }
    // Local file header, or an empty/spanned archive. A ZIP with prefix data
    // — a self-extracting archive, or a polyglot — is not caught here; see
    // the FUTURE.md entry on multi-hypothesis extraction.
    if b.len() >= 4 && (&b[..4] == b"PK\x03\x04" || &b[..4] == b"PK\x05\x06") {
        return Some(ContentFamily::Zip);
    }
    if b.len() >= 8 && b[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Some(ContentFamily::Ole2);
    }
    if b.len() >= 6 && &b[..6] == b"Rar!\x1a\x07" {
        return Some(ContentFamily::Rar);
    }
    if b.len() >= 6 && b[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(ContentFamily::SevenZ);
    }
    if b.len() >= 4 && &b[..4] == b"PAR1" {
        return Some(ContentFamily::Parquet);
    }
    if b.len() >= 16 && &b[..16] == b"SQLite format 3\0" {
        return Some(ContentFamily::Sqlite);
    }

    // Images. Each of these is a distinctive multi-byte signature except BMP,
    // which is handled below.
    if b.len() >= 8 && b[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(ContentFamily::Image);
    }
    if b.len() >= 3 && b[..3] == [0xFF, 0xD8, 0xFF] {
        return Some(ContentFamily::Image);
    }
    if b.len() >= 6 && (&b[..6] == b"GIF87a" || &b[..6] == b"GIF89a") {
        return Some(ContentFamily::Image);
    }
    if b.len() >= 4 && (&b[..4] == b"II*\0" || &b[..4] == b"MM\0*") {
        return Some(ContentFamily::Image);
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Some(ContentFamily::Image);
    }
    // BMP: two ASCII bytes, far too weak on its own. Corroborate with the
    // little-endian file-size field at offset 2, which must equal the actual
    // length. A CSV that happens to start "BM" will not also encode its own
    // size there.
    if b.len() >= 6 && &b[..2] == b"BM" {
        let declared = u32::from_le_bytes([b[2], b[3], b[4], b[5]]) as u64;
        if let Ok(meta) = std::fs::metadata(file_path) {
            if declared == meta.len() {
                return Some(ContentFamily::Image);
            }
        }
    }

    None
}

fn detect_and_extract(file_path: &str) -> Option<ExtractorFn> {
    // Binary containers are identified by [`sniff_family`], which is also
    // what `extract_text` arbitrates on. Sharing it is not tidiness: these
    // two now both decide dispatch, and a second copy of the signature table
    // would eventually disagree with the first about what a file is. The
    // duplicate that used to live here had already drifted — it accepted the
    // first six bytes of SQLite's signature where the real one is sixteen,
    // and it knew nothing about images at all, so a PNG was reachable only
    // through its own extension.
    if let Some(family) = sniff_family(file_path) {
        return Some(match family {
            #[cfg(feature = "pdf")]
            ContentFamily::Pdf => extract_pdf,
            // Without the feature there is no parser, so the bytes are read
            // as text and the result says so. That finds text in an
            // uncompressed content stream and nothing in a compressed one,
            // which is to say nothing in a real PDF — the caller has to be
            // told, not left to assume a clean result means clean.
            #[cfg(not(feature = "pdf"))]
            ContentFamily::Pdf => extract_unparsed_binary,

            ContentFamily::Rtf => extract_rtf,
            ContentFamily::Zip => extract_zip_based,

            #[cfg(feature = "msg")]
            ContentFamily::Ole2 => extract_msg,
            #[cfg(feature = "archives")]
            ContentFamily::Rar => extract_rar,
            #[cfg(feature = "archives")]
            ContentFamily::SevenZ => extract_7z,
            #[cfg(feature = "data-formats")]
            ContentFamily::Parquet => extract_parquet,
            #[cfg(feature = "data-formats")]
            ContentFamily::Sqlite => extract_sqlite,
            #[cfg(feature = "barcode")]
            ContentFamily::Image => extract_barcode,

            // A container we recognised but were not built to read. Reporting
            // it as unparsed is the whole point of identifying it: the caller
            // learns that this file holds content nobody inspected, instead
            // of getting a clean read of compressed bytes.
            #[cfg(not(feature = "msg"))]
            ContentFamily::Ole2 => extract_unparsed_binary,
            #[cfg(not(feature = "archives"))]
            ContentFamily::Rar | ContentFamily::SevenZ => extract_unparsed_binary,
            #[cfg(not(feature = "data-formats"))]
            ContentFamily::Parquet | ContentFamily::Sqlite => extract_unparsed_binary,
            #[cfg(not(feature = "barcode"))]
            ContentFamily::Image => extract_unparsed_binary,
        });
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
        if (trimmed.starts_with("MIME-Version:") || trimmed.starts_with("From:"))
            && (trimmed.contains("multipart/related") || trimmed.contains("multipart/alternative"))
        {
            return Some(extract_mhtml);
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
        "fonttbl",
        "colortbl",
        "stylesheet",
        "info",
        "pict",
        "header",
        "footer",
        "footnote",
        "annotation",
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
            _ if !skip_group && depth >= 1 && ch != '\r' && ch != '\n' => {
                output.push(ch);
            }
            _ => {}
        }
    }

    output.trim().to_string()
}

/// Extract text from an EML (email) file.
///
/// Delegates the MIME walk to `siphon_core::mime` so this path and the mail
/// path cannot disagree about what a message contains.
///
/// This previously scraped six headers and appended the remaining lines as
/// plain text, with no boundary handling and no transfer-encoding decode. A
/// base64 attachment therefore reached the scanner as base64 and matched
/// nothing — a `.eml` carrying a card number in an attachment came back
/// clean. The normalizer's base64 stage does not cover it either, because
/// MUAs wrap base64 at 76 columns and per-token decoding of wrapped base64
/// produces noise.
fn extract_eml(file_path: &str) -> Result<ExtractionResult, String> {
    // Read bytes, not a String. Real mail carries 8-bit content and legacy
    // charsets in headers; `read_to_string` rejects anything non-UTF-8, which
    // turned a decodable message into a failed extraction.
    let raw = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let parsed = siphon_core::mime::parse_message(&raw);

    let mut text = String::new();
    // Headers first, so address and subject content is scannable and so a
    // keyword in the subject sits near the body it describes.
    if let Some(v) = &parsed.headers.from {
        text.push_str(&format!("from: {v}\n"));
    }
    if !parsed.headers.to.is_empty() {
        text.push_str(&format!("to: {}\n", parsed.headers.to.join(", ")));
    }
    if let Some(v) = &parsed.headers.subject {
        text.push_str(&format!("subject: {v}\n"));
    }
    if let Some(v) = &parsed.headers.date {
        text.push_str(&format!("date: {v}\n"));
    }
    text.push('\n');

    // Every decoded textual part, including text attachments, which is the
    // content the old implementation lost.
    for part in &parsed.parts {
        if let Some(t) = &part.text {
            if let Some(name) = &part.filename {
                // The filename is context for what follows it.
                text.push_str(&format!("[attachment: {name}]\n"));
            }
            text.push_str(t);
            text.push('\n');
        }
    }

    // Constructed after the attachment loop below would be cleaner, but the
    // metadata calls read better here; `text` is moved in at the end instead.
    let mut result = ExtractionResult::new(String::new(), "eml");
    if let Some(v) = &parsed.headers.from {
        result = result.with_metadata("from", v);
    }
    if !parsed.headers.to.is_empty() {
        result = result.with_metadata("to", &parsed.headers.to.join(", "));
    }
    if let Some(v) = &parsed.headers.subject {
        result = result.with_metadata("subject", v);
    }
    if let Some(v) = &parsed.headers.message_id {
        result = result.with_metadata("message_id", v);
    }
    if let Some(v) = &parsed.headers.date {
        result = result.with_metadata("date", v);
    }

    // Attachments are run through the full extractor registry, so a PDF or
    // spreadsheet attached to a message is read the same way it would be if
    // uploaded directly. Naming them without reading them — the first version
    // of this fix — still left the payload unscanned; it only made the gap
    // visible instead of invisible.
    for a in parsed.attachments() {
        let Some(bytes) = &a.data else { continue };
        let name = a.filename.as_deref().unwrap_or("attachment");
        match extract_attachment_bytes(bytes, name) {
            Ok(Some(sub)) => {
                text.push_str(&format!("\n[attachment: {name}]\n"));
                text.push_str(&sub.text);
                text.push('\n');
                for w in &sub.warnings {
                    result = result.with_warning(&format!("{name}: {w}"));
                }
            }
            // Nothing readable in it — an image with no barcode, an empty
            // container. Not an error, and not worth a warning.
            Ok(None) => {}
            Err(e) => {
                // Content exists that this pass did not read. Say so: an
                // extraction failure must not leave the message looking clean.
                result = result.with_warning(&format!(
                    "attachment not scanned: {name} ({}, {} bytes): {e}",
                    a.content_type, a.size
                ));
            }
        }
    }
    for w in &parsed.warnings {
        result = result.with_warning(w);
    }
    result.text = text;
    Ok(result)
}

/// Run one decoded attachment through the extractor registry.
///
/// Writes to a temp file because the registry dispatches on path extension
/// and every extractor reads from disk. Returns `Ok(None)` when the
/// attachment yielded no text.
///
/// Recursion is bounded by a depth counter rather than by refusing nested
/// messages: a forwarded mail carrying a spreadsheet is ordinary traffic, and
/// declining to open it would be the same class of gap this change closes. The
/// counter stops `.eml` inside `.eml` inside `.eml` from recursing without
/// end.
fn extract_attachment_bytes(bytes: &[u8], name: &str) -> Result<Option<ExtractionResult>, String> {
    use std::cell::Cell;
    thread_local! {
        static DEPTH: Cell<usize> = const { Cell::new(0) };
    }
    const MAX_ATTACHMENT_DEPTH: usize = 4;

    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_EXTRACT_SIZE {
        return Err(format!(
            "attachment is {} bytes, above the {} byte extractor limit",
            bytes.len(),
            MAX_EXTRACT_SIZE
        ));
    }

    let depth = DEPTH.with(|d| d.get());
    if depth >= MAX_ATTACHMENT_DEPTH {
        return Err(format!(
            "nested deeper than {MAX_ATTACHMENT_DEPTH} levels of attachment"
        ));
    }

    // Preserve the extension so the registry dispatches correctly; without a
    // recognised one it falls back to magic-byte sniffing, which is the same
    // path a renamed file takes.
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let dir = std::env::temp_dir().join(format!(
        "siphon-att-{}-{:x}",
        std::process::id(),
        bytes.len()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("part.{ext}"));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;

    DEPTH.with(|d| d.set(depth + 1));
    let out = extract_text(path.to_str().unwrap_or_default());
    DEPTH.with(|d| d.set(depth));

    // Best-effort cleanup; a leftover temp file must not fail a scan.
    std::fs::remove_dir_all(&dir).ok();

    match out {
        Ok(r) if r.text.trim().is_empty() => Ok(None),
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(e),
    }
}

/// Extract text from a PDF.
///
/// This was missing for the life of the extractor: the magic-byte sniffer
/// matched `%PDF` and then returned the plain-text reader, with a comment
/// saying to use the `pdf` feature for real extraction. The feature was on by
/// default and `pdf_extract` was compiled into every build, but nothing ever
/// called it.
///
/// The consequence was not cosmetic. PDF content streams are FlateDecode
/// compressed in essentially every real-world file, so reading the bytes as
/// text finds nothing that matters. Measured on a two-line PDF carrying an
/// SSN and a card number: uncompressed, three findings; compressed, one — and
/// that one was a false positive matched against the xref table, not content.
#[cfg(feature = "pdf")]
fn extract_pdf(file_path: &str) -> Result<ExtractionResult, String> {
    match pdf_extract::extract_text(file_path) {
        Ok(text) => Ok(ExtractionResult::new(text, "pdf")),
        // A PDF we could not parse is not a PDF we can call clean. Fall back
        // to the bytes so an uncompressed stream still yields something, but
        // mark the result unfaithful so a caller under a fail-closed policy
        // treats the part as uninspected rather than empty.
        Err(e) => {
            let mut r = extract_unparsed_binary(file_path)?;
            r.warnings
                .push(format!("PDF parse failed ({e}); read as raw bytes instead"));
            Ok(r)
        }
    }
}

/// Read a file whose declared format we could not parse.
///
/// The honest form of the plain-text fallback. `extract_plain_text` labels its
/// result with the file's extension, so a `.docx` that is not a zip comes back
/// as `format: "docx"` with no warning and a caller cannot tell a real parse
/// from raw bytes. This says `unparsed` and carries a warning, which is what
/// lets the mail path treat the part as uninspected instead of clean.
fn extract_unparsed_binary(file_path: &str) -> Result<ExtractionResult, String> {
    let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let declared = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("unknown")
        .to_lowercase();
    Ok(
        ExtractionResult::new(text, "unparsed").with_warning(&format!(
            "content did not match any known format; declared .{declared} was read as raw bytes, \
         so structured content in it was not inspected"
        )),
    )
}

/// Extract text from ZIP-based formats (docx, xlsx, pptx).
/// If the central directory is corrupted, falls back to raw-byte scanning
/// for printable text strings.
fn extract_zip_based(file_path: &str) -> Result<ExtractionResult, String> {
    let file = std::fs::File::open(file_path).map_err(|e| e.to_string())?;
    match zip::ZipArchive::new(file) {
        Ok(mut archive) => extract_zip_archive(&mut archive),
        Err(_) => {
            // Central directory is corrupted — fall back to raw byte scanning.
            // The payload may still be present as uncompressed or partially
            // readable data in the local file entries.
            let data = std::fs::read(file_path).map_err(|e| e.to_string())?;
            let text = extract_printable_strings(&data, 12);
            if text.is_empty() {
                return Err(
                    "ZIP central directory corrupted and no printable text recoverable".to_string(),
                );
            }
            let mut result = ExtractionResult::new(text, "zip-recovered");
            result =
                result.with_warning("ZIP central directory corrupted — extracted from raw bytes");
            Ok(result)
        }
    }
}

/// Extract from a valid ZIP archive.
fn extract_zip_archive(
    archive: &mut zip::ZipArchive<std::fs::File>,
) -> Result<ExtractionResult, String> {
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
                    "xlsx"
                        if name.starts_with("xl/worksheets/") || name.contains("sharedStrings") =>
                    {
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
            // Zip-bomb defense: reject entries whose uncompressed size
            // is more than MAX_ZIP_COMPRESSION_RATIO × the compressed
            // size. Per-entry and total-size caps still limit memory,
            // but without this check a 10,000:1 ratio file can burn
            // CPU during streaming up to those caps.
            if zip_entry_is_bomb(file.size(), file.compressed_size()) {
                tracing::warn!(
                    entry = %xml_path,
                    uncompressed = file.size(),
                    compressed = file.compressed_size(),
                    ratio_cap = MAX_ZIP_COMPRESSION_RATIO,
                    "ZIP entry exceeds compression ratio cap — skipping"
                );
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

    // Generic (non-Office) ZIP. The format detector fell through to "zip",
    // so the Office XML pass above matched nothing and `text` is still empty.
    // Walk every entry and scan the text-like files by content — the same
    // treatment `extract_rar` and `extract_7z` already give their entries.
    //
    // Without this, a sensitive file inside a plain `.zip` is never scanned:
    // `zip out.zip secrets.txt` defeats the scanner entirely, and the empty
    // extraction then surfaces to the caller as a confusing 500 rather than a
    // finding. This was a silent DLP bypass — the worst kind for this product.
    //
    // Entries are read into memory by name, never written to disk, so archive
    // path traversal ("zip slip") is not a write risk on this path; the guards
    // below are about resource exhaustion, matching the Office branch.
    let mut nested_warnings: Vec<String> = Vec::new();
    if format == "zip" {
        use std::io::Read;
        for i in 0..archive.len() {
            if entry_count >= MAX_EXTRACT_FILE_COUNT {
                break;
            }
            let Ok(mut file) = archive.by_index(i) else {
                continue;
            };
            let name = file.name().to_string();
            // A nested archive is not recursed into — deep recursion is where
            // zip-bomb amplification lives — but it must not vanish silently
            // either: a sensitive file one layer deep would otherwise scan to
            // zero findings with no signal. Surface a warning so an analyst
            // knows unscanned content is present.
            if archive_entry_is_nested_archive(&name) {
                if nested_warnings.len() < MAX_NESTED_ARCHIVE_WARNINGS {
                    nested_warnings.push(format!("nested archive not scanned: {name}"));
                }
                continue;
            }
            // An encrypted entry cannot be read without the password. Same
            // reasoning: flag it rather than skip in silence.
            if file.encrypted() {
                if nested_warnings.len() < MAX_NESTED_ARCHIVE_WARNINGS {
                    nested_warnings.push(format!("encrypted entry not scanned: {name}"));
                }
                continue;
            }
            if !archive_entry_is_text(&name) {
                continue;
            }
            let size = file.size();
            if size > MAX_EXTRACT_ENTRY_SIZE {
                continue;
            }
            if zip_entry_is_bomb(size, file.compressed_size()) {
                tracing::warn!(
                    entry = %name,
                    uncompressed = size,
                    compressed = file.compressed_size(),
                    ratio_cap = MAX_ZIP_COMPRESSION_RATIO,
                    "ZIP entry exceeds compression ratio cap — skipping"
                );
                continue;
            }
            if total_read + size > MAX_EXTRACT_TOTAL_SIZE {
                break;
            }
            // Bound the read by the per-entry cap regardless of the
            // header-declared `size`, which is attacker-controlled: a lying
            // header must not turn into an unbounded read.
            let mut buf = Vec::new();
            if (&mut file)
                .take(MAX_EXTRACT_ENTRY_SIZE)
                .read_to_end(&mut buf)
                .is_ok()
            {
                total_read += buf.len() as u64;
                entry_count += 1;
                text.push_str(&String::from_utf8_lossy(&buf));
                text.push('\n');
            }
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), format);
    for w in nested_warnings {
        result = result.with_warning(&w);
    }
    Ok(result)
}

/// Elements whose boundary is a boundary in the *document*, not just in the
/// markup: a new paragraph, row, cell, list item or line break.
///
/// This distinction is the whole point of the list. Inside a paragraph, XML
/// element boundaries are meaningless — Word splits a single word across
/// `<w:r>` runs whenever it feels like it, on nothing more than an edit or a
/// spell-check, so `<w:t>4111</w:t><w:t>111111111111</w:t>` is one card
/// number and joining the runs is the only way to see it. Between cells, the
/// opposite holds: two adjacent numeric cells are two numbers, and joining
/// them invents a card number that appears nowhere in the sheet.
///
/// Getting this wrong is not a cosmetic problem. With no separator at all —
/// which is what this stripper did — both failure modes land at once: a
/// spreadsheet's `SSN` header glued to the value below it reads as
/// `SSN219-09-9999` and matches nothing, while two unrelated 8-digit columns
/// read as a valid Luhn card and match something that is not there.
///
/// Covers OOXML (`w:`/`a:`), OpenDocument (`text:`/`table:`) and HTML, since
/// every caller of [`strip_xml_tags`] hands it one of those three.
const XML_BREAK_TAGS: &[&str] = &[
    // WordprocessingML: paragraph, table row/cell, explicit break, tab
    "w:p",
    "w:tr",
    "w:tc",
    "w:br",
    "w:tab", // SpreadsheetML: cell, row
    "c",
    "row", // DrawingML (pptx): paragraph, break
    "a:p",
    "a:br", // OpenDocument: paragraph, heading, line break, row, cell
    "text:p",
    "text:h",
    "text:line-break",
    "table:table-row",
    "table:table-cell",
    // HTML block-level elements
    "p",
    "br",
    "div",
    "tr",
    "td",
    "th",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
];

/// True when `raw` — the text between `<` and `>` — names an element from
/// [`XML_BREAK_TAGS`].
fn xml_tag_breaks(raw: &str) -> bool {
    let name = raw
        .trim_start_matches(['/', '?', '!'])
        .split([' ', '\t', '\r', '\n', '/', '>'])
        .next()
        .unwrap_or("");
    if name.is_empty() {
        return false;
    }
    XML_BREAK_TAGS
        .iter()
        .any(|t| t.eq_ignore_ascii_case(name.trim()))
}

/// Simple XML tag stripper that preserves text content.
///
/// Text inside one document block is concatenated verbatim; a block boundary
/// (see [`XML_BREAK_TAGS`]) becomes a newline. Newlines survive the
/// whitespace collapse below deliberately — a space would not be enough,
/// because most value patterns tolerate an internal space, so two adjacent
/// numeric cells joined by one would still read as a single card number.
fn strip_xml_tags(xml: &str) -> String {
    let mut output = String::new();
    let mut tag = String::new();
    let mut in_tag = false;

    for ch in xml.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                if xml_tag_breaks(&tag) {
                    output.push('\n');
                }
            }
            _ if in_tag => tag.push(ch),
            _ => output.push(ch),
        }
    }

    // Collapse runs of whitespace, but keep line structure: a run of spaces
    // becomes one space, a run of newlines becomes one newline.
    let mut result = String::new();
    let mut prev_space = false;
    let mut prev_newline = false;
    for ch in output.chars() {
        if ch == '\n' || ch == '\r' {
            if !prev_newline {
                result.push('\n');
            }
            prev_newline = true;
            prev_space = true;
        } else if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
            prev_newline = false;
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
        let value = if prop_with_params
            .to_uppercase()
            .contains("ENCODING=QUOTED-PRINTABLE")
        {
            decode_quoted_printable(raw_value)
        } else {
            raw_value.to_string()
        };

        // Extract type label if present
        let type_label = extract_vcard_type(prop_with_params);

        match prop_name.as_str() {
            "FN" => {
                text.push_str(&format!("Name: {value}\n"));
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
                text.push_str(&format!("{label}: {value}\n"));
            }
            "TEL" => {
                let label = type_label.as_deref().unwrap_or("Phone");
                text.push_str(&format!("{label}: {value}\n"));
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
                text.push_str(&format!("Birthday: {value}\n"));
            }
            "ORG" => {
                let org = value.replace(';', ", ");
                text.push_str(&format!("Organization: {org}\n"));
            }
            "TITLE" => {
                text.push_str(&format!("Title: {value}\n"));
            }
            "NOTE" => {
                text.push_str(&format!("Note: {value}\n"));
            }
            "URL" => {
                text.push_str(&format!("URL: {value}\n"));
            }
            "GENDER" => {
                text.push_str(&format!("Gender: {value}\n"));
            }
            "NICKNAME" => {
                text.push_str(&format!("Nickname: {value}\n"));
            }
            "CATEGORIES" => {
                text.push_str(&format!("Categories: {value}\n"));
            }
            "ROLE" => {
                text.push_str(&format!("Role: {value}\n"));
            }
            "GEO" => {
                text.push_str(&format!("Geo: {value}\n"));
            }
            "IMPP" | "X-JABBER" | "X-SKYPE-USERNAME" | "X-AIM" => {
                text.push_str(&format!("IM: {value}\n"));
            }
            "X-SOCIALPROFILE" => {
                text.push_str(&format!("Social: {value}\n"));
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
            let types = match part.strip_prefix("TYPE=") {
                Some(t) => t,
                None => continue,
            };
            return Some(types.replace(',', "/"));
        }
        // vCard 2.1 style: TEL;HOME;VOICE:
        if ["HOME", "WORK", "CELL", "VOICE", "FAX", "PAGER", "PREF"].contains(&part) {
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
                if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
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
        let open_tag = format!("<c:{element}>");
        let close_tag = format!("</c:{element}>");
        // Also handle without namespace prefix
        let open_tag2 = format!("<{element}>");
        let close_tag2 = format!("</{element}>");

        for (open, close) in [(&open_tag, &close_tag), (&open_tag2, &close_tag2)] {
            let mut search_from = 0;
            while let Some(start) = content[search_from..].find(open.as_str()) {
                let abs_start = search_from + start + open.len();
                if let Some(end) = content[abs_start..].find(close.as_str()) {
                    let value = content[abs_start..abs_start + end].trim();
                    if !value.is_empty() && !value.starts_with('<') {
                        text.push_str(&format!("{label}: {value}\n"));
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
                if let Ok(decoded) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                {
                    value = String::from_utf8_lossy(&decoded).to_string();
                }
            }

            // LDIF postalAddress uses $ as line separator
            if attr == "postaladdress" {
                value = value.replace('$', ", ");
            }

            if let Some(label) = pii_attrs.get(attr.as_str()) {
                if !value.is_empty() {
                    text.push_str(&format!("{label}: {value}\n"));
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
    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {e}"))?;

    let mut text = String::new();

    // jCard can be a single vcard array or an array of vcards
    let vcards = if value.is_array() {
        let arr = match value.as_array() {
            Some(a) => a,
            None => return Err("Expected JSON array for jCard".to_string()),
        };
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
            Some(arr) if arr.len() >= 2 => arr[1].as_array(),
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
                "fn" => text.push_str(&format!("Name: {value_str}\n")),
                "n" => text.push_str(&format!("Structured Name: {value_str}\n")),
                "email" => {
                    let label = type_label.as_deref().unwrap_or("Email");
                    text.push_str(&format!("{label}: {value_str}\n"));
                }
                "tel" => {
                    let label = type_label.as_deref().unwrap_or("Phone");
                    // Strip tel: URI prefix
                    let phone = value_str.strip_prefix("tel:").unwrap_or(&value_str);
                    text.push_str(&format!("{label}: {phone}\n"));
                }
                "adr" => {
                    let label = type_label.as_deref().unwrap_or("Address");
                    text.push_str(&format!("{label}: {value_str}\n"));
                }
                "bday" => text.push_str(&format!("Birthday: {value_str}\n")),
                "org" => text.push_str(&format!("Organization: {value_str}\n")),
                "title" => text.push_str(&format!("Title: {value_str}\n")),
                "note" => text.push_str(&format!("Note: {value_str}\n")),
                "url" => text.push_str(&format!("URL: {value_str}\n")),
                "gender" => text.push_str(&format!("Gender: {value_str}\n")),
                "nickname" => text.push_str(&format!("Nickname: {value_str}\n")),
                "geo" => text.push_str(&format!("Geo: {value_str}\n")),
                "impp" => text.push_str(&format!("IM: {value_str}\n")),
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
                if prop_name.as_str() == "X-WR-CALNAME" {
                    text.push_str(&format!("Calendar: {val}\n"))
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
            "SUMMARY" => text.push_str(&format!("Summary: {value}\n")),
            "DESCRIPTION" => text.push_str(&format!("Description: {value}\n")),
            "LOCATION" => text.push_str(&format!("Location: {value}\n")),
            "ORGANIZER" => {
                // ORGANIZER;CN=Name:mailto:email
                let cn = extract_ics_param(prop_with_params, "CN");
                let email = value
                    .strip_prefix("mailto:")
                    .or_else(|| value.strip_prefix("MAILTO:"))
                    .unwrap_or(value);
                if let Some(name) = cn {
                    text.push_str(&format!("Organizer: {name} <{email}>\n"));
                } else {
                    text.push_str(&format!("Organizer: {email}\n"));
                }
            }
            "ATTENDEE" => {
                let cn = extract_ics_param(prop_with_params, "CN");
                let email = value
                    .strip_prefix("mailto:")
                    .or_else(|| value.strip_prefix("MAILTO:"))
                    .unwrap_or(value);
                if let Some(name) = cn {
                    text.push_str(&format!("Attendee: {name} <{email}>\n"));
                } else {
                    text.push_str(&format!("Attendee: {email}\n"));
                }
            }
            "CONTACT" => text.push_str(&format!("Contact: {value}\n")),
            "COMMENT" => text.push_str(&format!("Comment: {value}\n")),
            "URL" => text.push_str(&format!("URL: {value}\n")),
            "GEO" => text.push_str(&format!("Geo: {value}\n")),
            "DTSTART" => text.push_str(&format!("Start: {value}\n")),
            "DTEND" => text.push_str(&format!("End: {value}\n")),
            "CATEGORIES" => text.push_str(&format!("Categories: {value}\n")),
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
                    text.push_str(&format!("{key}: {value}\n"));
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
    let boundary = content.lines().find_map(|line| {
        if line.to_lowercase().contains("boundary=") {
            let bnd = line.split("boundary=").nth(1)?;
            Some(bnd.trim_matches('"').trim_matches('\'').trim().to_string())
        } else {
            None
        }
    });

    if let Some(boundary) = boundary {
        let separator = format!("--{boundary}");
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
                        text.push_str(&format!("{key}: {value}\n"));
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
                    text.push_str(&format!(
                        "URL: {}\n",
                        line["WARC-Target-URI:".len()..].trim()
                    ));
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
            // Zip-bomb defense: reject entries whose compression ratio
            // exceeds MAX_ZIP_COMPRESSION_RATIO.
            if zip_entry_is_bomb(file.size(), file.compressed_size()) {
                tracing::warn!(
                    entry = %xml_name,
                    uncompressed = file.size(),
                    compressed = file.compressed_size(),
                    ratio_cap = MAX_ZIP_COMPRESSION_RATIO,
                    "ODT entry exceeds compression ratio cap — skipping"
                );
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
    let mut comp = cfb::CompoundFile::open(file).map_err(|e| format!("Invalid MSG file: {e}"))?;
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
        let path = format!("/{stream_name}");
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
                    text.push_str(&format!("{label}: {content}\n"));
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
        .map_err(|e| format!("Failed to open RAR: {e}"))?;

    let mut file_names = Vec::new();
    for entry in archive.flatten() {
        file_count += 1;
        file_names.push(entry.filename.to_string_lossy().to_string());
    }

    text.push_str(&format!("RAR Archive ({file_count} files):\n"));
    for name in &file_names {
        text.push_str(&format!("  {name}\n"));
    }

    // Extract and read text content from small text files
    // Shared with the ZIP walker via ARCHIVE_TEXT_EXTENSIONS so the three
    // archive extractors cannot drift apart on what counts as scannable text.
    let text_extensions = ARCHIVE_TEXT_EXTENSIONS;

    let tmp_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;

    // Use process mode to extract each file
    let archive = unrar::Archive::new(file_path)
        .open_for_processing()
        .map_err(|e| format!("Failed to open RAR for processing: {e}"))?;

    let mut cursor = archive;
    let mut total_extracted_size: u64 = 0;
    let mut extracted_count: usize = 0;
    while let Ok(Some(header)) = cursor.read_header() {
        let entry = header.entry();
        let name = entry.filename.to_string_lossy().to_string();

        // Check file count limit
        if extracted_count >= MAX_EXTRACT_FILE_COUNT {
            match header.skip() {
                Ok(next) => {
                    cursor = next;
                    continue;
                }
                Err(_) => break,
            }
        }

        // Validate entry name for path traversal BEFORE extraction
        let name_path = std::path::Path::new(&name);
        let has_traversal = name_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
            || name_path.is_absolute();
        if has_traversal {
            match header.skip() {
                Ok(next) => {
                    cursor = next;
                    continue;
                }
                Err(_) => break,
            }
        }

        // Check total extracted size limit
        if total_extracted_size + entry.unpacked_size > MAX_EXTRACT_TOTAL_SIZE {
            match header.skip() {
                Ok(next) => {
                    cursor = next;
                    continue;
                }
                Err(_) => break,
            }
        }

        let ext = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if text_extensions.contains(&ext.as_str()) && entry.unpacked_size < 1_048_576 {
            // Validate path BEFORE extraction to prevent TOCTOU
            if sanitize_archive_path(tmp_dir.path(), &name).is_none() {
                match header.skip() {
                    Ok(next) => {
                        cursor = next;
                        continue;
                    }
                    Err(_) => break,
                }
            }
            total_extracted_size += entry.unpacked_size;
            extracted_count += 1;
            match header.extract_to(tmp_dir.path()) {
                Ok(next) => {
                    cursor = next;
                    // Re-validate after extraction (defense in depth)
                    if let Some(dest) = sanitize_archive_path(tmp_dir.path(), &name) {
                        if let Ok(content) = std::fs::read_to_string(&dest) {
                            text.push_str(&format!("\n--- {name} ---\n"));
                            let content: String = content.chars().take(100_000).collect();
                            text.push_str(&content);
                            text.push('\n');
                        }
                    }
                }
                Err(e) => {
                    // Try to continue despite error
                    text.push_str(&format!("\n--- {name} (extraction error: {e}) ---\n"));
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
    // Nested archives inside the RAR are not recursed (bomb-amplification
    // risk); warn so they are not a silent gap, matching the ZIP/7z walkers.
    let mut nested_seen = 0usize;
    for name in &file_names {
        if archive_entry_is_nested_archive(name) {
            if nested_seen < MAX_NESTED_ARCHIVE_WARNINGS {
                result = result.with_warning(&format!("nested archive not scanned: {name}"));
            }
            nested_seen += 1;
        }
    }
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

    // Check source file size first to catch obvious bombs.
    // A 100:1 compression ratio is the maximum we'll tolerate.
    let src_meta = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    let max_decompressed =
        std::cmp::min(src_meta.len().saturating_mul(100), MAX_EXTRACT_TOTAL_SIZE);

    // Extract entry-by-entry rather than via `sevenz_rust::decompress_file`,
    // which is unsafe here on two counts.
    //
    // Path traversal: its `default_entry_extract_fn` builds the output path as
    // `dest.join(entry.name())` with no sanitisation at all, so an entry named
    // `../../../etc/cron.d/x` escapes the temp directory and an absolute name
    // discards the base entirely — `Path::join` on an absolute path returns
    // that path. Every entry name here goes through `sanitize_archive_path`,
    // the same guard the RAR extractor already uses.
    //
    // Decompression bombs: the size ceiling used to be checked *after*
    // `decompress_file` returned, by which point the archive was already on
    // disk. A 2 MB 7z expanding to 50 GB filled the disk and was then politely
    // rejected. The budget is now enforced as entries are written, so the
    // extraction aborts partway through rather than after the damage.
    let mut running_total: u64 = 0;
    let mut traversal_blocked = 0u32;
    let dest_root = tmp_dir.path().to_path_buf();

    sevenz_rust::decompress_file_with_extract_fn(file_path, &dest_root, |entry, reader, _| {
        if entry.is_directory() {
            return Ok(true);
        }
        let Some(safe_path) = sanitize_archive_path(&dest_root, entry.name()) else {
            // Refuse the entry and keep going: a hostile name should not stop
            // us scanning the legitimate contents alongside it.
            traversal_blocked += 1;
            return Ok(true);
        };

        running_total = running_total.saturating_add(entry.size());
        if running_total > max_decompressed {
            return Err(sevenz_rust::Error::other(format!(
                "7z archive exceeds maximum extracted size: {running_total} bytes \
                 (max {max_decompressed} bytes)"
            )));
        }

        if let Some(parent) = safe_path.parent() {
            std::fs::create_dir_all(parent).map_err(sevenz_rust::Error::io)?;
        }
        let mut out = std::io::BufWriter::new(
            std::fs::File::create(&safe_path).map_err(sevenz_rust::Error::io)?,
        );
        // Cap the copy itself too. `entry.size()` is attacker-supplied header
        // metadata, so a lying header must not become an unbounded read.
        let budget = max_decompressed
            .saturating_sub(running_total)
            .saturating_add(1);
        let mut limited = std::io::Read::take(&mut *reader, budget);
        let written = std::io::copy(&mut limited, &mut out).map_err(sevenz_rust::Error::io)?;
        if written >= budget {
            return Err(sevenz_rust::Error::other(
                "7z entry exceeded the declared extraction budget".to_string(),
            ));
        }
        Ok(true)
    })
    .map_err(|e| format!("Failed to extract 7z: {e}"))?;

    if traversal_blocked > 0 {
        tracing::warn!(
            blocked = traversal_blocked,
            file = %file_path,
            "7z entries rejected for path traversal"
        );
    }

    let mut file_count = 0u32;
    // Shared with the ZIP walker via ARCHIVE_TEXT_EXTENSIONS so the three
    // archive extractors cannot drift apart on what counts as scannable text.
    let text_extensions = ARCHIVE_TEXT_EXTENSIONS;

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
    let canonical_base = tmp_dir
        .path()
        .canonicalize()
        .unwrap_or_else(|_| tmp_dir.path().to_path_buf());

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
    if total_size > max_decompressed {
        // Clean up immediately before returning error
        drop(files);
        drop(tmp_dir);
        return Err(format!(
            "7z archive exceeds maximum extracted size: {total_size} bytes (max {max_decompressed} bytes). \
             Possible zip bomb (compression ratio > 100:1)."
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
        if let Ok(rel) = f.strip_prefix(tmp_dir.path()) {
            text.push_str(&format!("  {}\n", rel.display()));
        }
        file_count += 1;
    }

    // Extract text from small text files (with path traversal guard)
    let mut nested_warnings: Vec<String> = Vec::new();
    for f in &files {
        // Ensure file is actually under the temp dir using canonicalize
        if let Ok(canonical) = f.canonicalize() {
            if !canonical.starts_with(&canonical_base) {
                continue;
            }
        } else {
            continue;
        }

        let ext = f
            .extension()
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
        } else if NESTED_ARCHIVE_EXTENSIONS.contains(&ext.as_str())
            && nested_warnings.len() < MAX_NESTED_ARCHIVE_WARNINGS
        {
            // Nested archive: not recursed (bomb-amplification risk), but
            // surfaced as a warning so it is not a silent gap. Matches the
            // ZIP/RAR walkers.
            let rel = f.strip_prefix(tmp_dir.path()).unwrap_or(f);
            nested_warnings.push(format!("nested archive not scanned: {}", rel.display()));
        }
    }

    let mut result = ExtractionResult::new(text.trim().to_string(), "7z");
    result = result.with_metadata("file_count", &file_count.to_string());
    for w in nested_warnings {
        result = result.with_warning(&w);
    }
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
    let reader =
        SerializedFileReader::new(file).map_err(|e| format!("Invalid Parquet file: {e}"))?;

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
            .map(|(_, field)| format!("{field}"))
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
    .map_err(|e| format!("Failed to open SQLite database: {e}"))?;

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

        text.push_str(&format!("--- Table: {table} ---\n"));

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
                .map(|i| row.get::<_, String>(i).unwrap_or_default())
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
// QR Code / Barcode Decoding (requires `barcode` feature)
// ---------------------------------------------------------------------------

/// Decode QR codes, barcodes (UPC, EAN, Data Matrix, Aztec, PDF417, etc.)
/// from image files and return the decoded text for scanning.
/// Maximum image file size for barcode decoding (20 MB).
#[cfg(feature = "barcode")]
const MAX_BARCODE_IMAGE_SIZE: u64 = 20 * 1024 * 1024;

/// Maximum number of barcodes to decode per image.
#[cfg(feature = "barcode")]
const MAX_BARCODES_PER_IMAGE: usize = 100;

/// Maximum decoded text length per barcode (4 KB).
#[cfg(feature = "barcode")]
const MAX_BARCODE_TEXT_LEN: usize = 4096;

#[cfg(feature = "barcode")]
pub fn extract_barcode(file_path: &str) -> Result<ExtractionResult, String> {
    use rxing::BarcodeFormat;

    // Pre-check image file size to prevent decompression bombs
    let meta = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_BARCODE_IMAGE_SIZE {
        return Err(format!(
            "Image too large for barcode decoding: {} bytes (max {})",
            meta.len(),
            MAX_BARCODE_IMAGE_SIZE
        ));
    }

    // rxing reports "this image decoded fine and carries no barcode" as
    // `Err(NotFoundException)`, not as an empty result vector. Those two
    // outcomes have to be told apart here, because they mean opposite things
    // to a caller that fails closed: an image we could not read is content
    // nobody inspected, while an image with no barcode is fully inspected and
    // carries no text. Collapsing both into an error made every photo look
    // like an unread attachment — enough, in the mail path, to defer every
    // message carrying one.
    // Decoded from bytes, not from the path. rxing's file helper hands the
    // path to `image::open`, which picks a decoder from the *file extension*
    // — so a PNG named `.txt` fails with "extension was not recognized as an
    // image format" even once dispatch has correctly identified it as an
    // image. That is the same misplaced trust in the filename that
    // `extract_text` arbitrates away, one layer further down, and it has to
    // be closed here too or closing it above buys nothing.
    let bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let image = image::load_from_memory(&bytes)
        .map_err(|e| format!("Barcode decode failed: could not decode image: {e}"))?;

    let results = match rxing::helpers::detect_multiple_in_image(image) {
        Ok(r) => r,
        Err(rxing::Exceptions::NotFoundException(_)) => Vec::new(),
        Err(e) => return Err(format!("Barcode decode failed: {e}")),
    };

    if results.is_empty() {
        // Read in full; there was simply nothing encoded in it. Not a
        // warning — a warning here would be indistinguishable from the
        // unreadable-image case above, which is the one worth reporting.
        return Ok(ExtractionResult::new(String::new(), "barcode"));
    }

    let mut text_parts = Vec::new();
    let mut formats_found = Vec::new();

    for result in results.iter().take(MAX_BARCODES_PER_IMAGE) {
        let format_name = match result.getBarcodeFormat() {
            BarcodeFormat::QR_CODE => "QR Code",
            BarcodeFormat::DATA_MATRIX => "Data Matrix",
            BarcodeFormat::AZTEC => "Aztec",
            BarcodeFormat::PDF_417 => "PDF417",
            BarcodeFormat::UPC_A => "UPC-A",
            BarcodeFormat::UPC_E => "UPC-E",
            BarcodeFormat::EAN_8 => "EAN-8",
            BarcodeFormat::EAN_13 => "EAN-13",
            BarcodeFormat::CODE_39 => "Code 39",
            BarcodeFormat::CODE_128 => "Code 128",
            BarcodeFormat::ITF => "ITF",
            BarcodeFormat::CODABAR => "Codabar",
            _ => "Unknown",
        };
        formats_found.push(format_name);
        // Cap decoded text length to prevent memory exhaustion from malicious barcodes
        let decoded = result.getText();
        if decoded.len() <= MAX_BARCODE_TEXT_LEN {
            text_parts.push(decoded.to_string());
        } else {
            text_parts.push(decoded[..MAX_BARCODE_TEXT_LEN].to_string());
        }
    }

    let text = text_parts.join("\n");
    let mut result = ExtractionResult::new(text, "barcode");
    result = result.with_metadata("barcode_count", &results.len().to_string());
    result = result.with_metadata("formats", &formats_found.join(", "));
    Ok(result)
}

// ---------------------------------------------------------------------------
// CAB (Microsoft Cabinet) Archive Extraction
// ---------------------------------------------------------------------------

/// Extract text content from CAB (Microsoft Cabinet) archive files.
/// CAB files are treated as ZIP-like archives; we extract and concatenate
/// the text content of any readable entries.
pub fn extract_cab(file_path: &str) -> Result<ExtractionResult, String> {
    let metadata = std::fs::metadata(file_path).map_err(|e| e.to_string())?;
    if metadata.len() as usize > MAX_EXTRACT_SIZE {
        return Err(format!("CAB file too large: {} bytes", metadata.len()));
    }

    let data = std::fs::read(file_path).map_err(|e| e.to_string())?;

    if data.len() < 4 || &data[0..4] != b"MSCF" {
        return Err("Not a valid CAB file (missing MSCF header)".to_string());
    }

    // Extract printable text segments (capped at MAX_PRINTABLE_OUTPUT)
    let text = extract_printable_strings(&data, 8);
    let mut result = ExtractionResult::new(text, "cab");
    result = result.with_metadata("file_size", &data.len().to_string());
    Ok(result)
}

/// Extract text content from .DAT files.
/// DAT files are generic data files; we scan for printable text segments.
pub fn extract_dat(file_path: &str) -> Result<ExtractionResult, String> {
    let data = std::fs::read(file_path).map_err(|e| e.to_string())?;

    if data.len() > MAX_EXTRACT_SIZE {
        return Err(format!("DAT file too large: {} bytes", data.len()));
    }

    // Try UTF-8 first (many DAT files are plain text)
    if let Ok(text) = std::str::from_utf8(&data) {
        return Ok(ExtractionResult::new(text.to_string(), "dat"));
    }

    // Fallback: extract printable strings from binary data
    let text = extract_printable_strings(&data, 8);
    let mut result = ExtractionResult::new(text, "dat");
    result = result.with_warning("Binary DAT file — extracted printable strings only");
    Ok(result)
}

/// Maximum extracted text output from binary string extraction (10 MB).
const MAX_PRINTABLE_OUTPUT: usize = 10 * 1024 * 1024;

/// Public API: extract printable ASCII strings from binary data.
/// Used by the pipeline as a last-resort fallback for binary files.
pub fn extract_printable_strings_public(data: &[u8], min_length: usize) -> String {
    extract_printable_strings(data, min_length)
}

/// Extract printable ASCII strings from binary data.
/// Only includes runs of at least `min_length` printable characters.
/// Output is capped at [`MAX_PRINTABLE_OUTPUT`] bytes to prevent memory exhaustion.
fn extract_printable_strings(data: &[u8], min_length: usize) -> String {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut total_len: usize = 0;

    for &byte in data {
        // ASCII printable range + common whitespace (explicit parentheses for clarity)
        if (0x20..0x7f).contains(&byte) || byte == b'\n' || byte == b'\r' || byte == b'\t' {
            // Safe: all accepted bytes are valid single-byte ASCII/UTF-8
            current.push(byte as char);
        } else {
            if current.len() >= min_length {
                total_len += current.len() + 1; // +1 for join separator
                if total_len > MAX_PRINTABLE_OUTPUT {
                    break;
                }
                strings.push(std::mem::take(&mut current));
            }
            current.clear();
        }
    }
    if current.len() >= min_length && total_len + current.len() <= MAX_PRINTABLE_OUTPUT {
        strings.push(current);
    }

    strings.join("\n")
}

// ---------------------------------------------------------------------------
// File Type Blocking
// ---------------------------------------------------------------------------

/// File extensions that are blocked by default because they contain
/// cryptographic material that should never be transmitted or stored
/// unprotected.
pub const DEFAULT_BLOCKED_EXTENSIONS: &[&str] = &[
    // Cryptographic certificates and keys
    "der", "p12", "pfx", "p7b", "p7c", "p7m", "p7s", "p8",  // PKCS#8 private keys
    "ppk", // PuTTY private keys
    "jks", "keystore", "bks", // Encrypted/signed containers
    "smime", "gpg", "pgp", "asc", // Binary certificate formats
    "sst", "stl", "spc", "pvk",
];

/// File extensions that indicate encrypted content which cannot be
/// meaningfully scanned.
pub const ENCRYPTED_EXTENSIONS: &[&str] = &[
    "gpg", "pgp", "enc", "aes", "p7m", "smime", "kdbx", "kdb", // KeePass databases
    "tc", "hc",  // TrueCrypt / VeraCrypt volumes
    "dmg", // macOS encrypted disk images (may be encrypted)
];

/// File extensions that are known binary formats with no text to extract.
pub const OPAQUE_BINARY_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "bin", "o", "obj", "a", "lib", "class", "pyc", "pyo", "wasm",
    "ico", "cur", "ani", "ttf", "otf", "woff", "woff2", "eot", "mp3", "mp4", "avi", "mkv", "mov",
    "wmv", "flv", "webm", "wav", "flac", "ogg", "aac", "m4a", "swf", "fla",
];

/// Check if a file extension is in the blocked list.
pub fn is_blocked_extension(ext: &str, blocked: &[&str]) -> bool {
    let lower = ext.to_lowercase();
    let trimmed = lower.trim_start_matches('.');
    blocked.contains(&trimmed)
}

/// Check if any extension in a file path (including double extensions) is blocked.
/// For example, `secret.der.txt` checks both "txt" and "der".
/// Empty segments and empty blocked entries are ignored.
pub fn is_path_blocked(file_path: &str, blocked: &[&str]) -> bool {
    let name = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    for segment in name.split('.').skip(1) {
        if segment.is_empty() {
            continue;
        }
        let lower = segment.to_lowercase();
        if blocked.iter().any(|&b| !b.is_empty() && b == lower) {
            return true;
        }
    }
    false
}

/// Check if a file extension is an unreadable/opaque binary type.
pub fn is_unreadable_extension(ext: &str) -> bool {
    let lower = ext.to_lowercase();
    let trimmed = lower.trim_start_matches('.');
    OPAQUE_BINARY_EXTENSIONS.contains(&trimmed) || ENCRYPTED_EXTENSIONS.contains(&trimmed)
}

/// Check if a file appears to be encrypted based on extension or entropy.
pub fn is_likely_encrypted(file_path: &str) -> bool {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let lower = ext.to_lowercase();
    ENCRYPTED_EXTENSIONS.contains(&lower.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    /// A file whose name contradicts its content is refused under the
    /// `Reject` policy, and read-by-content under `Flag`.
    ///
    /// Both directions are asserted here because the interesting mistake is
    /// asymmetric: a policy that only ever rejects is a policy nobody can
    /// switch on, and one that never rejects is not a policy at all.
    #[test]
    fn a_lying_extension_obeys_the_configured_policy() {
        use std::io::Write;

        // A deflated ZIP, so its payload is not incidentally readable as
        // text — the whole point is that the plain-text reader finds nothing.
        let zip_bytes = {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut z = zip::ZipWriter::new(&mut buf);
                z.start_file::<_, ()>(
                    "secrets.txt",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
                z.write_all(b"primary card 4111111111111111\n").unwrap();
                z.finish().unwrap();
            }
            buf.into_inner()
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, &zip_bytes).unwrap();
        let path = path.to_str().unwrap();

        let flagged = super::extract_text_with_policy(path, super::OnFormatMismatch::Flag)
            .expect("flag policy reads the file");
        assert_eq!(flagged.format, "zip", "content decides the reader");
        assert!(
            flagged.text.contains("4111111111111111"),
            "the payload must be read: reading it by name found nothing at all"
        );
        assert_eq!(
            flagged.metadata.get("format_mismatch").map(String::as_str),
            Some("declared .txt, content is zip"),
            "the contradiction is the most interesting fact about this file"
        );

        let rejected = super::extract_text_with_policy(path, super::OnFormatMismatch::Reject);
        assert!(
            rejected.is_err(),
            "the reject policy must refuse the file, not read it"
        );

        let ignored = super::extract_text_with_policy(path, super::OnFormatMismatch::Ignore)
            .expect("ignore policy reads the file");
        assert!(
            ignored.text.contains("4111111111111111"),
            "ignore suppresses the report, never the scan — the bypass stays closed"
        );
        assert!(
            ignored.metadata.get("format_mismatch").is_none(),
            "ignore records nothing"
        );
    }

    /// An honestly named file must never be reported as contradicting itself.
    #[test]
    fn an_honest_extension_records_no_contradiction() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();

        // A CSV whose first two bytes are "BM" — BMP's entire signature.
        // Accepting that alone would send this to an image decoder.
        let path = dir.path().join("rows.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"BMW,model,notes\nX5,2024,card 4111111111111111\n")
            .unwrap();
        drop(f);

        let r =
            super::extract_text_with_policy(path.to_str().unwrap(), super::OnFormatMismatch::Flag)
                .unwrap();
        assert!(
            r.metadata.get("format_mismatch").is_none(),
            "a signature weak enough to fire here fires on ordinary documents: {:?}",
            r.metadata
        );
        assert!(r.text.contains("4111111111111111"));
    }

    /// An image that decodes cleanly and carries no barcode is *inspected*,
    /// and must not be reported as content we failed to read.
    ///
    /// rxing signals "decoded fine, nothing encoded in it" as
    /// `Err(NotFoundException)` rather than as an empty result vector, so the
    /// obvious `?` collapsed it into the same outcome as a corrupt image. Any
    /// caller that fails closed on unread content then treats every photo as
    /// an unread attachment: in the mail path that deferred every message
    /// carrying one. The two outcomes are told apart in `extract_barcode`,
    /// and this is the test that says so.
    #[cfg(feature = "barcode")]
    #[test]
    fn an_image_with_no_barcode_reads_clean_not_unreadable() {
        use base64::Engine as _;
        use std::io::Write;

        // A real 32x32 greyscale PNG. It has to actually decode: a plausible
        // header plus filler fails inside the image decoder, which is the
        // unreadable case and would pass this test for the wrong reason.
        const PNG_B64: &str =
            "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAAxUlEQVR42oXMkQLCAABF0\
                               QuDIBgMgsEgCAaDQTAIgkEQBINBEAwGg0EQBEEQBEEQBEEQBEEQBEEQBEEQBEEQBEEQ9\
                               AnvfMCBgllyKl61FjajdpJ1+8PxdL5cb/fH8/X+fH8xipZddv2g3mjFnTTvDUaT2WK12\
                               R1Ol9vj9fnJABEYiKCACIqIwEQEFiIoIQIbETiIoIwIKojARQQeIvARQRURBIighgjqi\
                               CBEBA1E0EQELUQQIYIYEbQRQQcRJIggRQQZIsj/vPL4ECN9bh0AAAAASUVORK5CYII=";

        let png = base64::engine::general_purpose::STANDARD
            .decode(PNG_B64)
            .expect("fixture is valid base64");
        let mut tmp = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        tmp.write_all(&png).unwrap();
        tmp.flush().unwrap();

        let r = super::extract_barcode(tmp.path().to_str().unwrap())
            .expect("a decodable image with no barcode is not an extraction failure");
        assert!(r.text.is_empty(), "nothing was encoded in it");
        assert!(
            r.warnings.is_empty(),
            "a warning here is indistinguishable from an unreadable image, \
             which is the case actually worth reporting: {:?}",
            r.warnings
        );
    }

    /// A `.eml` whose attachment is base64 was a live bypass: the payload
    /// reached the scanner still encoded, matched nothing, and the file came
    /// back clean. Wrapped at 76 columns, as MUAs emit it — unwrapped base64
    /// is decoded incidentally by the normalizer, so only the wrapped form
    /// A binary attachment must be run through the extractor registry, not
    /// merely named. The first version of this fix listed attachments in a
    /// warning, which made the gap visible without closing it — the payload
    /// was still never scanned.
    #[test]
    fn eml_zip_attachment_is_extracted_and_scanned() {
        use std::io::Write;

        // A ZIP holding a text file with a card number: exercises
        // eml -> attachment -> archive extractor -> text.
        let zip_bytes = {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut z = zip::ZipWriter::new(&mut buf);
                z.start_file::<_, ()>("cards.txt", zip::write::SimpleFileOptions::default())
                    .unwrap();
                z.write_all(b"primary card 4111111111111111\n").unwrap();
                z.finish().unwrap();
            }
            buf.into_inner()
        };
        let b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&zip_bytes)
        };
        let wrapped = b64
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n");

        let eml = format!(
            "From: a@example.com\r\nSubject: archive\r\n\
             Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
             --B\r\nContent-Type: text/plain\r\n\r\nsee zip\r\n\
             --B\r\nContent-Type: application/zip; name=\"cards.zip\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{wrapped}\r\n--B--\r\n"
        );

        let dir = std::env::temp_dir().join(format!("siphon-emlzip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.eml");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(eml.as_bytes())
            .unwrap();

        let r = extract_text(path.to_str().unwrap()).expect("eml should extract");
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            r.text.contains("4111111111111111"),
            "a ZIP attached to a message must be extracted and scanned, not \
             just named; extracted: {:?}",
            r.text
        );
    }

    /// Attachment recursion must terminate. A message attached to a message
    /// attached to a message is legitimate traffic, so the guard is a depth
    /// bound rather than a refusal to open nested mail.
    #[test]
    fn eml_nested_attachments_terminate() {
        use std::io::Write;

        // Build .eml nested 8 deep, past MAX_ATTACHMENT_DEPTH.
        let mut inner =
            String::from("Content-Type: text/plain\r\n\r\ndeep card 4111111111111111\r\n");
        for _ in 0..8 {
            let b64 = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(inner.as_bytes())
            };
            let wrapped = b64
                .as_bytes()
                .chunks(76)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join("\r\n");
            inner = format!(
                "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                 --B\r\nContent-Type: message/rfc822; name=\"n.eml\"\r\n\
                 Content-Transfer-Encoding: base64\r\n\r\n{wrapped}\r\n--B--\r\n"
            );
        }

        let dir = std::env::temp_dir().join(format!("siphon-emldeep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("deep.eml");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(inner.as_bytes())
            .unwrap();

        // The assertion is that this returns at all rather than recursing
        // without end or exhausting the stack.
        let r = extract_text(path.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            r.is_ok(),
            "deeply nested attachments must terminate cleanly"
        );
    }

    /// exercised the gap.
    #[test]
    fn eml_base64_attachment_reaches_the_scanner_decoded() {
        use std::io::Write;

        let payload = b"acct,card\nprimary,4111111111111111\n";
        let b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(payload)
        };
        let wrapped = b64
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n");

        let eml = format!(
            "From: a@example.com\r\nTo: b@example.com\r\nSubject: Q3\r\n\
             Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n\
             --BND\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
             --BND\r\nContent-Type: text/csv; name=\"cards.csv\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{wrapped}\r\n--BND--\r\n"
        );

        let dir = std::env::temp_dir().join(format!("siphon-eml-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.eml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(eml.as_bytes()).unwrap();
        drop(f);

        let r = extract_text(path.to_str().unwrap()).expect("eml should extract");
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            r.text.contains("4111111111111111"),
            "base64 attachment must be decoded before the scanner sees it; \
             extracted text was: {:?}",
            r.text
        );
    }

    /// Real mail carries 8-bit bodies and legacy charsets. Reading the file as
    /// a UTF-8 String turned a decodable message into a failed extraction.
    #[test]
    fn eml_with_non_utf8_bytes_still_extracts() {
        use std::io::Write;

        let mut eml: Vec<u8> = b"From: a@example.com\r\nSubject: caf\xe9\r\n\
                                 Content-Type: text/plain\r\n\r\n"
            .to_vec();
        // A latin-1 byte in the body, invalid as UTF-8.
        eml.extend_from_slice(b"card 4111111111111111 caf\xe9\r\n");

        let dir = std::env::temp_dir().join(format!("siphon-eml8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe8.eml");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&eml)
            .unwrap();

        let r = extract_text(path.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();

        let r = r.expect("non-UTF-8 mail must not fail extraction outright");
        assert!(
            r.text.contains("4111111111111111"),
            "content beside a non-UTF-8 byte must still be extracted: {:?}",
            r.text
        );
    }
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
    fn test_zip_entry_is_bomb() {
        // Normal text XML: 10:1 ratio, safe
        assert!(!zip_entry_is_bomb(10_000, 1_000));
        // Exactly at the cap (100:1), safe
        assert!(!zip_entry_is_bomb(100_000, 1_000));
        // Just over the cap (>100:1), bomb
        assert!(zip_entry_is_bomb(101_000, 1_000));
        // Classic zip bomb (10,000:1), bomb
        assert!(zip_entry_is_bomb(10_000_000, 1_000));
        // Extreme 1,000,000:1, bomb
        assert!(zip_entry_is_bomb(1_000_000_000, 1_000));
        // Directory / stored header (compressed_size == 0): safe, nothing
        // to expand
        assert!(!zip_entry_is_bomb(0, 0));
        assert!(!zip_entry_is_bomb(42, 0));
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
        let f = write_temp(
            "vcf",
            "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;John;;Mr.;\r\nFN:Mr. John Doe\r\nEND:VCARD\r\n",
        );
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
        assert!(result
            .text
            .contains("A Very Long Name That GetsFolded Across Lines"));
    }

    #[test]
    fn test_extract_vcard_birthday() {
        let f = write_temp(
            "vcf",
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane\r\nBDAY:1990-05-15\r\nEND:VCARD\r\n",
        );
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
        let f = write_temp(
            "json",
            r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text","John Doe"],["email",{},"text","john@example.com"],["tel",{},"uri","tel:+1-555-123-4567"]]]"#,
        );
        let result = extract_jcard(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
        assert!(result.text.contains("+1-555-123-4567"));
    }

    #[test]
    fn test_extract_jcard_array() {
        let f = write_temp(
            "json",
            r#"[["vcard",[["version",{},"text","4.0"],["fn",{},"text","Alice"]]],["vcard",[["version",{},"text","4.0"],["fn",{},"text","Bob"]]]]"#,
        );
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
            zip.write_all(b"application/vnd.oasis.opendocument.text")
                .unwrap();

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
        assert_eq!(extract_ics_param("ORGANIZER;CN=Test", "ROLE"), None);
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

    #[test]
    fn test_extract_printable_strings_basic() {
        let data = b"Hello World\x00\x01\x02Secret Data\x00abc";
        let result = extract_printable_strings(data, 5);
        assert!(result.contains("Hello World"));
        assert!(result.contains("Secret Data"));
        assert!(!result.contains("abc")); // 3 chars < min_length 5
    }

    #[test]
    fn test_extract_printable_strings_min_length() {
        let data = b"ab\x00cdefghij\x00xy";
        let result = extract_printable_strings(data, 8);
        assert!(result.contains("cdefghij"));
        assert!(!result.contains("ab"));
        assert!(!result.contains("xy"));
    }

    #[test]
    fn test_extract_printable_strings_whitespace() {
        let data = b"line1\nline2\ttab\rreturn";
        let result = extract_printable_strings(data, 3);
        assert!(result.contains("line1\nline2\ttab\rreturn"));
    }

    #[test]
    fn test_extract_printable_strings_output_cap() {
        // Create data that would produce > MAX_PRINTABLE_OUTPUT
        let big = vec![b'A'; MAX_PRINTABLE_OUTPUT + 1000];
        let result = extract_printable_strings(&big, 1);
        assert!(result.len() <= MAX_PRINTABLE_OUTPUT + 100); // allow some slack for join
    }

    #[test]
    fn test_is_blocked_extension() {
        let blocked = &["der", "p12", "pfx"];
        assert!(is_blocked_extension("der", blocked));
        assert!(is_blocked_extension("DER", blocked));
        assert!(is_blocked_extension(".der", blocked));
        assert!(!is_blocked_extension("txt", blocked));
        assert!(!is_blocked_extension("pem", blocked));
    }

    #[test]
    fn test_is_path_blocked_double_extension() {
        let blocked = &["der", "p12", "pfx"];
        assert!(is_path_blocked("secret.der.txt", blocked));
        assert!(is_path_blocked("file.p12.bak", blocked));
        assert!(is_path_blocked("archive.tar.pfx", blocked));
        assert!(!is_path_blocked("readme.txt", blocked));
        assert!(!is_path_blocked("notes.md", blocked));
    }

    #[test]
    fn test_is_path_blocked_case_insensitive() {
        let blocked = &["der", "p12"];
        assert!(is_path_blocked("file.DER", blocked));
        assert!(is_path_blocked("file.Der.txt", blocked));
        assert!(is_path_blocked("FILE.P12", blocked));
    }

    #[test]
    fn test_is_unreadable_extension() {
        assert!(is_unreadable_extension("exe"));
        assert!(is_unreadable_extension("dll"));
        assert!(is_unreadable_extension("gpg"));
        assert!(is_unreadable_extension("kdbx"));
        assert!(!is_unreadable_extension("txt"));
        assert!(!is_unreadable_extension("json"));
    }

    #[test]
    fn test_is_likely_encrypted() {
        assert!(is_likely_encrypted("secrets.gpg"));
        assert!(is_likely_encrypted("database.kdbx"));
        assert!(is_likely_encrypted("backup.enc"));
        assert!(!is_likely_encrypted("readme.txt"));
        assert!(!is_likely_encrypted("data.csv"));
    }

    #[test]
    fn test_default_blocked_extensions_coverage() {
        // Verify critical cert formats are blocked
        for ext in &["der", "p12", "pfx", "p7b", "p7m", "jks", "gpg", "pgp"] {
            assert!(
                DEFAULT_BLOCKED_EXTENSIONS.contains(ext),
                "{ext} should be in DEFAULT_BLOCKED_EXTENSIONS"
            );
        }
    }

    #[test]
    fn test_extract_cab_invalid_header() {
        let f = write_temp("cab", "NOT A CAB FILE");
        let result = extract_cab(f.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MSCF"));
    }

    #[test]
    fn test_extract_cab_valid_header() {
        let mut data = b"MSCF".to_vec();
        data.extend_from_slice(b"\x00\x00\x00\x00"); // padding
        data.extend_from_slice(b"embedded secret text here for testing");
        let f = tempfile::Builder::new().suffix(".cab").tempfile().unwrap();
        std::fs::write(f.path(), &data).unwrap();
        let result = extract_cab(f.path().to_str().unwrap()).unwrap();
        assert_eq!(result.format, "cab");
        assert!(result
            .text
            .contains("embedded secret text here for testing"));
    }

    #[test]
    fn test_extract_dat_utf8() {
        let f = write_temp("dat", "SSN: 123-45-6789\nEmail: test@example.com");
        let result = extract_dat(f.path().to_str().unwrap()).unwrap();
        assert_eq!(result.format, "dat");
        assert!(result.text.contains("123-45-6789"));
    }

    #[test]
    fn test_extract_dat_binary_fallback() {
        let mut data = vec![0u8; 20];
        data.extend_from_slice(b"hidden credit card 4532015112830366 inside binary");
        data.extend_from_slice(&[0xFF; 20]);
        let f = tempfile::Builder::new().suffix(".dat").tempfile().unwrap();
        std::fs::write(f.path(), &data).unwrap();
        let result = extract_dat(f.path().to_str().unwrap()).unwrap();
        assert!(result.text.contains("4532015112830366"));
        assert!(result.warnings.iter().any(|w| w.contains("Binary")));
    }
}
