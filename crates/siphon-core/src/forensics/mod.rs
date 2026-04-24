//! Forensic metadata extraction and author attribution.
//!
//! Reads document-level metadata (author, tool, creation date, revision
//! IDs, machine fingerprints) from PDF and OOXML (docx / xlsx / pptx)
//! files and computes pairwise attribution scores between documents.
//!
//! The goal is **investigator-grade evidence**: if two files in a leak
//! share the same `w:rsidRoot` in their revision history, they were
//! authored on the same Office installation, even if the visible
//! content and filenames have been scrubbed. That's the signal the
//! `compare` function below surfaces.
//!
//! This module is gated behind the `forensics` Cargo feature so
//! minimal builds that only need scanning don't pull `zip`,
//! `quick-xml`, or `lopdf`.

#![cfg(feature = "forensics")]

mod attribution;
mod legacy_office;
mod office;
mod pdf;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use attribution::{compare, AttributionScore, AttributionSignal, SignalKind};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error variants for forensic metadata extraction.
///
/// All variants wrap a string so the caller doesn't have to match
/// on the underlying `zip::Error` / `lopdf::Error` families — the
/// message already carries the source context. Manual
/// `Display` + `Error` impls keep siphon-core free of a
/// `thiserror` dependency.
#[derive(Debug)]
pub enum ForensicsError {
    Io(std::io::Error),
    UnknownKind(String),
    Malformed(String),
}

impl std::fmt::Display for ForensicsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForensicsError::Io(e) => write!(f, "io: {e}"),
            ForensicsError::UnknownKind(ext) => {
                write!(f, "unknown file kind — extension '{ext}' is not supported")
            }
            ForensicsError::Malformed(msg) => write!(f, "malformed document: {msg}"),
        }
    }
}

impl std::error::Error for ForensicsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ForensicsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ForensicsError {
    fn from(e: std::io::Error) -> Self {
        ForensicsError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Document family. Drives the extractor picked in
/// [`extract_metadata`] and colors which fields a consumer should
/// expect populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Pdf,
    // Modern OOXML
    Docx,
    Xlsx,
    Pptx,
    // Legacy OLE Compound File — pre-2007 Office
    Doc,
    Xls,
    Ppt,
    /// Anything else — extension preserved for the CLI to display.
    Other(String),
}

impl FileKind {
    /// Derive kind from the path extension. Case-insensitive.
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("pdf") => FileKind::Pdf,
            Some("docx") => FileKind::Docx,
            Some("xlsx") => FileKind::Xlsx,
            Some("pptx") => FileKind::Pptx,
            Some("doc") => FileKind::Doc,
            Some("xls") => FileKind::Xls,
            Some("ppt") => FileKind::Ppt,
            Some(other) => FileKind::Other(other.to_string()),
            None => FileKind::Other(String::new()),
        }
    }
}

/// Forensic metadata extracted from a single document.
///
/// Most fields are `Option<String>` because different producers
/// populate different subsets. `raw` carries anything the extractor
/// found but didn't promote to a first-class field — useful for
/// manual inspection via the CLI's `--json` output.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileMetadata {
    /// SHA-256 of the file bytes, hex-lowercased. Lets investigators
    /// pin a metadata record to an exact file even after rename.
    pub content_hash: String,
    pub kind: FileKind,
    pub path: String,
    pub size_bytes: u64,

    // --- Authoring ----------------------------------------------------------
    /// Creator (original author) — `dc:creator` in OOXML, `/Author`
    /// in a PDF Info dictionary.
    pub creator: Option<String>,
    /// Last editor — OOXML `cp:lastModifiedBy`. PDFs don't carry
    /// this by convention, so None for Pdf.
    pub last_modified_by: Option<String>,
    pub title: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,

    // --- Temporal -----------------------------------------------------------
    pub created_at: Option<String>,
    pub modified_at: Option<String>,

    // --- Tool / machine fingerprint ----------------------------------------
    /// Producer application — `xmp:CreatorTool` / `pdf:Producer` /
    /// OOXML `<Application>`. "Microsoft Office Word", "LibreOffice
    /// 7.6.2.1", "Adobe InDesign 19.4", etc.
    pub application: Option<String>,
    /// OOXML `<Company>` — only populated when the Office install
    /// was domain-joined at document creation. Gold for attribution.
    pub company: Option<String>,

    // --- Identifiers --------------------------------------------------------
    /// OOXML DOCX revision-session IDs (`w:rsid` values from
    /// word/settings.xml). Every "edit session" records a new
    /// 32-bit ID; the **first** ID is the document's `rsidRoot`,
    /// and two docs sharing an rsidRoot were authored on the same
    /// machine / Word install. Investigators lean on this heavily.
    pub rsids: Vec<String>,
    /// PDF document ID — a pair of hex strings from the trailer's
    /// `/ID` entry. The first is the original ID at creation; the
    /// second changes on every save.
    pub pdf_doc_id: Option<(String, String)>,

    // --- Overflow -----------------------------------------------------------
    /// Anything else the extractor pulled out, keyed by its canonical
    /// tag name (e.g. "dc:description", "pdf:Producer").
    pub raw: BTreeMap<String, String>,
}

impl Default for FileKind {
    fn default() -> Self {
        FileKind::Other(String::new())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Read a file, derive its kind from the extension, and hand off to
/// the matching extractor.
///
/// The returned [`FileMetadata::content_hash`] is computed over the
/// raw bytes so the same file under different names still produces
/// identical records — useful for grouping findings across a
/// directory scan.
pub fn extract_metadata(path: &Path) -> Result<FileMetadata, ForensicsError> {
    let bytes = fs::read(path)?;
    let kind = FileKind::from_path(path);

    let mut meta = match &kind {
        FileKind::Pdf => pdf::extract(&bytes)?,
        FileKind::Docx | FileKind::Xlsx | FileKind::Pptx => office::extract(&bytes, &kind)?,
        FileKind::Doc | FileKind::Xls | FileKind::Ppt => legacy_office::extract(&bytes)?,
        FileKind::Other(ext) => {
            return Err(ForensicsError::UnknownKind(ext.clone()));
        }
    };

    meta.kind = kind;
    meta.path = path.display().to_string();
    meta.size_bytes = bytes.len() as u64;
    meta.content_hash = hash_bytes(&bytes);
    Ok(meta)
}

/// SHA-256 hex over bytes. Small helper so pdf/office extractors
/// share one canonical hash implementation.
fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}
