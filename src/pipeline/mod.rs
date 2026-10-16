//! Pipeline for batch file scanning with rayon parallelism.

use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::allowlist::Allowlist;
use crate::models::Match;
use crate::scanner::{self, ScanConfig};
use siphon_core::{Inspection, Unread};

/// Default maximum file size (100 MB).
pub const DEFAULT_MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// A file to be processed by the pipeline.
#[derive(Debug, Clone)]
pub struct FileJob {
    /// Path to the file.
    pub file_path: PathBuf,
    /// Categories to scan.
    pub categories: Option<HashSet<String>>,
    /// Only report matches with context.
    pub require_context: bool,
    /// Maximum matches for this file.
    pub max_matches: usize,
}

impl FileJob {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: path.into(),
            categories: None,
            require_context: false,
            max_matches: 50_000,
        }
    }
}

/// Result from processing a single file.
///
/// `#[non_exhaustive]` because this struct grows: `file_entropy` and
/// `entropy_classification` were added after it shipped, `warnings` after
/// those, and `inspection` after that. Each addition was a struct-literal
/// break for anyone outside this crate building one by hand. Marking it takes
/// that break once and makes every later field free.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct PipelineResult {
    pub file_path: String,
    pub matches: Vec<Match>,
    pub format_detected: String,
    pub duration_ms: f64,
    pub error: Option<String>,
    pub file_size_bytes: u64,
    pub extracted_text_length: usize,
    /// File-level Shannon entropy (0.0-8.0 bits/byte). High values
    /// indicate encrypted or compressed content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_entropy: Option<f64>,
    /// Entropy classification: "normal", "suspicious_for_format",
    /// "compressed_or_encrypted", "likely_encrypted".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_classification: Option<String>,
    /// What `matches` covers.
    ///
    /// `Complete` only when every unit of the file was read and matched to
    /// the end. Anything less — an encrypted archive entry, an attachment the
    /// extractor could not open, a format whose parser gave up and read raw
    /// bytes instead, a match cap that stopped the scanner early, a file whose
    /// bytes contradict its name — is `Incomplete`, with a typed reason for
    /// each gap. Zero `matches` with an incomplete inspection is not a clean
    /// file; it is a file nobody finished reading, and until this field
    /// existed `siphon scan` printed the same `Matches: 0` for both.
    ///
    /// Serialises as `{"status": "complete"}` or
    /// `{"status": "incomplete", "unread": [{"kind": ...}, ...]}`.
    pub inspection: Inspection,
    /// `inspection.describe()`: one line per reason, for readers still on
    /// strings. Always derived from `inspection`, never written separately.
    /// Goes away with step 6 of `docs/architecture/inspection-outcome.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl PipelineResult {
    /// A result with no matches and a complete inspection, to be qualified.
    fn blank(file_path: String, format: &str, duration_ms: f64, file_size: u64) -> Self {
        Self {
            file_path,
            matches: vec![],
            format_detected: format.to_string(),
            duration_ms,
            error: None,
            file_size_bytes: file_size,
            extracted_text_length: 0,
            file_entropy: None,
            entropy_classification: None,
            inspection: Inspection::new(),
            warnings: vec![],
        }
    }

    fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    /// Record content that was not read; `warnings` follows.
    fn with_unread(mut self, reason: Unread) -> Self {
        self.inspection.unread(reason);
        self.warnings = self.inspection.describe();
        self
    }

    /// Fold an inspection in (an extractor's, the scanner's); `warnings`
    /// follows.
    fn with_inspection(mut self, inspection: Inspection) -> Self {
        self.inspection.merge(inspection);
        self.warnings = self.inspection.describe();
        self
    }

    /// Create an error result with no matches.
    pub fn error_result(
        file_path: String,
        format: &str,
        error: String,
        elapsed_secs: f64,
        file_size: u64,
    ) -> Self {
        Self::blank(file_path, format, elapsed_secs * 1000.0, file_size).with_error(error)
    }

    pub fn success(&self) -> bool {
        self.error.is_none()
    }

    pub fn match_count(&self) -> usize {
        self.matches.len()
    }
}

/// Parallel file scanning pipeline.
pub struct Pipeline {
    /// Maximum file size to process.
    max_file_size: usize,
    /// Categories to scan.
    categories: Option<HashSet<String>>,
    /// Require context keywords.
    require_context: bool,
    /// Minimum confidence threshold.
    min_confidence: f64,
    /// Whether to deduplicate matches.
    deduplicate: bool,
    /// Allowlist for suppression.
    allowlist: Option<Allowlist>,
    /// File extensions to block (flagged and skipped).
    blocked_extensions: Vec<String>,
    /// When true, block unknown/opaque binary and encrypted file types.
    block_unreadable: bool,
}

impl Pipeline {
    /// Create a new pipeline with default settings.
    pub fn new() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            categories: None,
            require_context: false,
            min_confidence: 0.0,
            deduplicate: true,
            allowlist: None,
            blocked_extensions: crate::extractors::DEFAULT_BLOCKED_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            block_unreadable: false,
        }
    }

    /// Set maximum file size.
    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    /// Set categories to scan.
    pub fn with_categories(mut self, categories: HashSet<String>) -> Self {
        self.categories = Some(categories);
        self
    }

    /// Set context requirement.
    pub fn with_require_context(mut self, require: bool) -> Self {
        self.require_context = require;
        self
    }

    /// Set minimum confidence.
    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Set blocked file extensions.
    pub fn with_blocked_extensions(mut self, extensions: Vec<String>) -> Self {
        self.blocked_extensions = extensions;
        self
    }

    /// Block unknown/opaque binary and encrypted file types.
    pub fn with_block_unreadable(mut self, block: bool) -> Self {
        self.block_unreadable = block;
        self
    }

    /// Process a single file.
    pub fn process_file(&self, path: &Path) -> PipelineResult {
        let start = Instant::now();
        let ms = |start: &Instant| start.elapsed().as_secs_f64() * 1000.0;
        // Resolve symlinks before blocking check to prevent bypass via safe-named symlinks
        let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let file_path = path.display().to_string();

        // Check blocked extensions on RESOLVED path (checks ALL extensions, not just last)
        //
        // Every refusal below carries both an `error` (the CLI exits 1 on it,
        // as it always has) and a typed reason in `inspection`: a file the
        // pipeline declined to open is a file it did not read, whatever the
        // policy that declined it.
        {
            let resolved_str = resolved.display().to_string();
            let blocked_refs: Vec<&str> =
                self.blocked_extensions.iter().map(|s| s.as_str()).collect();
            if crate::extractors::is_path_blocked(&resolved_str, &blocked_refs) {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_lowercase();
                return PipelineResult::blank(file_path, "blocked", ms(&start), 0)
                    .with_unread(Unread::Unsupported {
                        unit: format!("file (blocked type .{ext})"),
                    })
                    .with_error(format!("Blocked file type in path: {ext}"));
            }
            if self.block_unreadable {
                if let Some(ext) = resolved.extension().and_then(|e| e.to_str()) {
                    if crate::extractors::is_unreadable_extension(ext) {
                        let ext = ext.to_lowercase();
                        return PipelineResult::blank(file_path, "blocked", ms(&start), 0)
                            .with_unread(Unread::Unsupported {
                                unit: format!("file (unreadable or encrypted type .{ext})"),
                            })
                            .with_error(format!("Unreadable/encrypted file type: .{ext}"));
                    }
                }
            }
        }

        // Check file size
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return PipelineResult::blank(file_path, "unknown", ms(&start), 0)
                    .with_unread(Unread::ReadError {
                        unit: "file".into(),
                        detail: e.to_string(),
                    })
                    .with_error(format!("Cannot read file: {e}"));
            }
        };

        // Hardening: refuse anything that is not a regular file.
        // Character devices (/dev/zero, /dev/urandom), block devices,
        // FIFOs, and sockets will happily report metadata.len() == 0
        // and then stream forever when read, defeating the size cap
        // below. fs::metadata follows symlinks, so a symlink pointing
        // at /dev/zero is also caught here.
        if !metadata.file_type().is_file() {
            return PipelineResult::blank(file_path, "unknown", ms(&start), 0)
                .with_unread(Unread::Unsupported {
                    unit: "non-regular file".into(),
                })
                .with_error("Not a regular file".into());
        }

        if metadata.len() as usize > self.max_file_size {
            return PipelineResult::blank(file_path, "unknown", ms(&start), metadata.len())
                .with_unread(Unread::Oversize {
                    unit: "file".into(),
                    limit: Some(self.max_file_size as u64),
                })
                .with_error(format!(
                    "File too large: {} bytes (max {})",
                    metadata.len(),
                    self.max_file_size
                ));
        }

        // Try the extractor first (DOCX, XLSX, PDF, EML, ...). What it could
        // not read travels in `result.inspection`; the pipeline carries that
        // forward instead of reading `warnings` and dropping the rest.
        let file_path_str = path.display().to_string();
        let mut inspection = Inspection::new();
        let (text, format) = match crate::extractors::extract_text(&file_path_str) {
            Ok(result) => {
                inspection.merge(result.inspection);
                (result.text, result.format)
            }
            Err(e) => {
                // Under `SIPHON_ON_FORMAT_MISMATCH=reject` the extractor
                // refused the file because its bytes contradict its name. That
                // is the operator's instruction not to read it, so nothing
                // below runs: no raw-byte pass, no matches, and a verdict that
                // says why it covers nothing.
                if crate::extractors::OnFormatMismatch::from_env()
                    == crate::extractors::OnFormatMismatch::Reject
                {
                    if let Some((declared, detected)) =
                        crate::extractors::format_mismatch(&file_path_str)
                    {
                        return PipelineResult::blank(
                            file_path,
                            "refused",
                            ms(&start),
                            metadata.len(),
                        )
                        .with_unread(Unread::FormatMismatch { declared, detected });
                    }
                }

                // The extractor tried and failed. This used to fall through to
                // `read_to_string` and report whatever that found as a
                // faithful read of the file — the exact shape of bug the
                // audit log in docs/architecture/inspection-outcome.md lists
                // twelve times over. The bytes are still scanned below, as a
                // last resort for a value that survives in them, but the
                // verdict now says it covers only what that pass could see.
                inspection.unread(Unread::ReadError {
                    unit: "file".into(),
                    detail: e,
                });
                match fs::read_to_string(path) {
                    Ok(t) => (t, detect_format(path)),
                    Err(_) => {
                        // UTF-8 read failed (binary file). Last resort: extract
                        // printable ASCII strings from raw bytes. This catches
                        // sensitive data embedded in binary formats with unknown
                        // or corrupted extensions.
                        match fs::read(path) {
                            Ok(bytes) if bytes.len() <= self.max_file_size => {
                                let text =
                                    crate::extractors::extract_printable_strings_public(&bytes, 12);
                                if text.is_empty() {
                                    return PipelineResult::blank(
                                        file_path,
                                        "binary",
                                        ms(&start),
                                        metadata.len(),
                                    )
                                    .with_inspection(inspection)
                                    .with_error("Binary file with no extractable text".into());
                                }
                                (text, "binary-strings".into())
                            }
                            _ => {
                                return PipelineResult::blank(
                                    file_path,
                                    "binary",
                                    ms(&start),
                                    metadata.len(),
                                )
                                .with_inspection(inspection)
                                .with_error("Cannot read binary file".into());
                            }
                        }
                    }
                }
            }
        };

        let text_len = text.len();

        // Prepend filename as context for keyword matching.
        // This ensures that filenames like "sin.txt", "ssn_report.csv", or
        // "credit-cards.xlsx" provide context keywords to the scanner.
        let filename_context = {
            let name = resolved.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Extract words from filename (split on non-alphanumeric)
            let words: Vec<&str> = name
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .collect();
            words.join(" ")
        };
        let text_with_context = if !filename_context.is_empty() {
            format!("{filename_context}\n{text}")
        } else {
            text
        };

        let config = ScanConfig {
            categories: self.categories.clone(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            deduplicate: self.deduplicate,
            ..Default::default()
        };

        // Scan with filename context prepended. `scan_text_inspected` reports
        // a match cap the same way the extractor reports an unread entry, so
        // a "redacted" output that stopped early says so.
        let context_offset = if !filename_context.is_empty() {
            filename_context.len() + 1 // +1 for the \n separator
        } else {
            0
        };
        let mut matches = match scanner::scan_text_inspected(&text_with_context, &config) {
            Ok(outcome) => {
                inspection.merge(outcome.inspection);
                outcome.matches
            }
            Err(e) => {
                let mut r = PipelineResult::blank(file_path, &format, ms(&start), metadata.len())
                    .with_inspection(inspection)
                    .with_unread(Unread::ReadError {
                        unit: "text".into(),
                        detail: format!("scan error: {e}"),
                    })
                    .with_error(format!("Scan error: {e}"));
                r.extracted_text_length = text_len;
                return r;
            }
        };

        // Filter out matches from the filename preamble and adjust spans
        if context_offset > 0 {
            matches.retain(|m| m.span.1 > context_offset);
            for m in &mut matches {
                m.span.0 = m.span.0.saturating_sub(context_offset);
                m.span.1 = m.span.1.saturating_sub(context_offset);
            }
        }

        // Apply allowlist
        if let Some(ref allowlist) = self.allowlist {
            matches.retain(|m| !allowlist.is_suppressed(m));
        }

        // File-level entropy analysis (detect encrypted/compressed content)
        let (file_entropy, entropy_classification) = {
            let analyzer = crate::entropy::EntropyAnalyzer::default();
            match analyzer.analyze_file(&resolved.display().to_string()) {
                Ok(result) => (Some(result.entropy), Some(result.classification)),
                Err(_) => (None, None),
            }
        };

        let warnings = inspection.describe();
        PipelineResult {
            file_path,
            matches,
            format_detected: format,
            duration_ms: ms(&start),
            error: None,
            file_size_bytes: metadata.len(),
            extracted_text_length: text_len,
            file_entropy,
            entropy_classification,
            inspection,
            warnings,
        }
    }

    /// Process multiple files in parallel using rayon.
    pub fn process_files(&self, paths: &[PathBuf]) -> Vec<PipelineResult> {
        paths
            .par_iter()
            .filter(|p| {
                if let Some(ref al) = self.allowlist {
                    !al.should_skip_path(&p.display().to_string())
                } else {
                    true
                }
            })
            .map(|p| self.process_file(p))
            .collect()
    }

    /// Process all files in a directory recursively.
    pub fn process_directory(&self, dir: &Path, recursive: bool) -> Vec<PipelineResult> {
        let paths = collect_files(dir, recursive);
        self.process_files(&paths)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect file format from extension.
fn detect_format(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("txt") | Some("log") | Some("csv") => "text".into(),
        Some("json") => "json".into(),
        Some("xml") | Some("html") | Some("htm") => "xml".into(),
        Some("pdf") => "pdf".into(),
        Some("docx") => "docx".into(),
        Some("xlsx") => "xlsx".into(),
        Some("pptx") => "pptx".into(),
        Some("eml") | Some("msg") => "email".into(),
        Some("py") | Some("rs") | Some("js") | Some("ts") | Some("go") | Some("java") => {
            "source_code".into()
        }
        Some(ext) => ext.to_string(),
        None => "unknown".into(),
    }
}

/// Maximum files the pipeline will collect from a directory tree.
const MAX_PIPELINE_FILES: usize = 100_000;

/// Collect all text files in a directory, bounded to [`MAX_PIPELINE_FILES`].
fn collect_files(dir: &Path, recursive: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_bounded(dir, recursive, &mut files);
    files
}

fn collect_files_bounded(dir: &Path, recursive: bool, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if files.len() >= MAX_PIPELINE_FILES {
            tracing::warn!(
                "Pipeline file limit ({}) reached, skipping remaining files",
                MAX_PIPELINE_FILES
            );
            return;
        }

        let path = entry.path();

        if path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false)
        {
            continue; // Skip hidden files
        }

        if path.is_dir() {
            if recursive {
                collect_files_bounded(&path, true, files);
            }
        } else if path.is_file() {
            files.push(path);
        }
    }
}

/// Export results as JSON.
pub fn results_to_json(results: &[PipelineResult], pretty: bool) -> crate::Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(results)?)
    } else {
        Ok(serde_json::to_string(results)?)
    }
}

fn escape_csv_field(field: &str) -> String {
    // Formula injection (CWE-1236): a spreadsheet evaluates any cell that
    // begins with =, +, -, @, TAB or CR as a formula. RFC-4180 quoting does
    // NOT stop this — the app strips the quotes before evaluating — so the
    // previous quote-only guard here detected the danger but did not defuse it.
    // Prefix a single quote to force the cell to text, then quote for
    // delimiters. (file_path and error can both carry attacker-influenced text,
    // e.g. a filename that starts with `=`.)
    let dangerous_lead = field
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let neutralized;
    let body: &str = if dangerous_lead {
        neutralized = format!("'{field}");
        &neutralized
    } else {
        field
    };
    if body.contains(',') || body.contains('"') || body.contains('\n') || body.contains('\r') {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body.to_string()
    }
}

/// Export results as CSV.
pub fn results_to_csv(results: &[PipelineResult]) -> String {
    let mut output = String::from("file_path,match_count,format,duration_ms,error\n");
    for r in results {
        output.push_str(&format!(
            "{},{},{},{:.2},{}\n",
            escape_csv_field(&r.file_path),
            r.match_count(),
            escape_csv_field(&r.format_detected),
            r.duration_ms,
            escape_csv_field(r.error.as_deref().unwrap_or(""))
        ));
    }
    output
}

#[cfg(test)]
mod csv_escape_tests {
    use super::escape_csv_field;

    #[test]
    fn formula_leads_are_forced_to_text() {
        // Quoting alone does not stop a spreadsheet evaluating these; the
        // leading apostrophe does. Regression for a quote-only guard that
        // detected the danger but left the payload live.
        for p in ["=1+1", "+1", "-2+3", "@SUM(A1)"] {
            let out = escape_csv_field(p);
            assert!(
                out.starts_with('\'') || out.starts_with("\"'"),
                "{p:?} not neutralized -> {out:?}"
            );
        }
    }

    #[test]
    fn ordinary_and_delimited_values() {
        assert_eq!(escape_csv_field("report.pdf"), "report.pdf");
        assert_eq!(escape_csv_field("a,b"), "\"a,b\"");
    }
}
