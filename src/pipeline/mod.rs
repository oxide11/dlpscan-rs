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
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResult {
    pub file_path: String,
    pub matches: Vec<Match>,
    pub format_detected: String,
    pub duration_ms: f64,
    pub error: Option<String>,
    pub file_size_bytes: u64,
    pub extracted_text_length: usize,
}

impl PipelineResult {
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

    /// Process a single file.
    pub fn process_file(&self, path: &Path) -> PipelineResult {
        let start = Instant::now();
        let file_path = path.display().to_string();

        // Check file size
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return PipelineResult {
                    file_path,
                    matches: vec![],
                    format_detected: "unknown".into(),
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                    error: Some(format!("Cannot read file: {e}")),
                    file_size_bytes: 0,
                    extracted_text_length: 0,
                };
            }
        };

        if metadata.len() as usize > self.max_file_size {
            return PipelineResult {
                file_path,
                matches: vec![],
                format_detected: "unknown".into(),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!(
                    "File too large: {} bytes (max {})",
                    metadata.len(),
                    self.max_file_size
                )),
                file_size_bytes: metadata.len(),
                extracted_text_length: 0,
            };
        }

        // Try extractor first (handles DOCX, XLSX, PDF, EML, etc.), fall back to plain text
        let file_path_str = path.display().to_string();
        let (text, format) = match crate::extractors::extract_text(&file_path_str) {
            Ok(result) => (result.text, result.format),
            Err(_) => {
                // Extractor failed, try reading as plain text
                match fs::read_to_string(path) {
                    Ok(t) => (t, detect_format(path)),
                    Err(e) => {
                        return PipelineResult {
                            file_path,
                            matches: vec![],
                            format_detected: "binary".into(),
                            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                            error: Some(format!("Cannot read file: {e}")),
                            file_size_bytes: metadata.len(),
                            extracted_text_length: 0,
                        };
                    }
                }
            }
        };

        let text_len = text.len();

        let config = ScanConfig {
            categories: self.categories.clone(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            deduplicate: self.deduplicate,
            ..Default::default()
        };

        let mut matches = match scanner::scan_text_with_config(&text, &config) {
            Ok(m) => m,
            Err(e) => {
                return PipelineResult {
                    file_path,
                    matches: vec![],
                    format_detected: format,
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                    error: Some(format!("Scan error: {e}")),
                    file_size_bytes: metadata.len(),
                    extracted_text_length: text_len,
                };
            }
        };

        // Apply allowlist
        if let Some(ref allowlist) = self.allowlist {
            matches.retain(|m| !allowlist.is_suppressed(m));
        }

        PipelineResult {
            file_path,
            matches,
            format_detected: format,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: None,
            file_size_bytes: metadata.len(),
            extracted_text_length: text_len,
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

/// Collect all text files in a directory.
fn collect_files(dir: &Path, recursive: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return files,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.file_name().map(|n| n.to_string_lossy().starts_with('.')).unwrap_or(false) {
            continue; // Skip hidden files
        }

        if path.is_dir() {
            if recursive {
                files.extend(collect_files(&path, true));
            }
        } else if path.is_file() {
            files.push(path);
        }
    }

    files
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
    let needs_quoting = field.contains(',') || field.contains('"') || field.contains('\n')
        || field.contains('\r')
        || field.starts_with('=') || field.starts_with('+')
        || field.starts_with('-') || field.starts_with('@');
    if needs_quoting {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
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
