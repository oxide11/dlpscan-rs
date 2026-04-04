//! Shannon entropy analysis and recursive archive extraction.
//!
//! Detects encrypted/compressed data by computing entropy of byte sequences
//! and classifies results against format-specific thresholds.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of entropy analysis on a byte sequence or file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub entropy: f64,
    pub is_suspicious: bool,
    pub classification: String,
    pub file_path: Option<String>,
    pub file_size: u64,
    pub format_hint: Option<String>,
}

impl EntropyResult {
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "entropy": (self.entropy * 10000.0).round() / 10000.0,
            "is_suspicious": self.is_suspicious,
            "classification": self.classification,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "format_hint": self.format_hint,
        })
    }
}

/// An item extracted from a (possibly nested) archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedItem {
    pub path: String,
    pub original_name: String,
    pub depth: usize,
    pub entropy: f64,
    pub classification: String,
    pub is_suspicious: bool,
    pub size: u64,
    pub parent_archive: Option<String>,
}

impl ExtractedItem {
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path,
            "original_name": self.original_name,
            "depth": self.depth,
            "entropy": (self.entropy * 10000.0).round() / 10000.0,
            "classification": self.classification,
            "is_suspicious": self.is_suspicious,
            "size": self.size,
            "parent_archive": self.parent_archive,
        })
    }
}

// ---------------------------------------------------------------------------
// Format-specific entropy ranges: (low, high)
// ---------------------------------------------------------------------------

fn format_entropy_ranges() -> HashMap<&'static str, (f64, f64)> {
    let mut m = HashMap::new();
    // Text
    for ext in &[".txt", ".csv", ".json", ".xml", ".html", ".py", ".js", ".log", ".md", ".rs", ".toml", ".yaml"] {
        m.insert(*ext, (3.0, 5.5));
    }
    // PDF
    m.insert(".pdf", (5.0, 7.8));
    // Office (zip-based)
    for ext in &[".docx", ".xlsx", ".pptx"] {
        m.insert(*ext, (7.0, 8.0));
    }
    // Archives
    m.insert(".zip", (7.5, 8.0));
    m.insert(".gz", (7.5, 8.0));
    m.insert(".tar", (4.0, 7.0));
    // Images
    m.insert(".png", (6.0, 8.0));
    m.insert(".jpg", (7.0, 8.0));
    m.insert(".jpeg", (7.0, 8.0));
    m
}

// ---------------------------------------------------------------------------
// EntropyAnalyzer
// ---------------------------------------------------------------------------

/// Computes Shannon entropy and classifies byte sequences.
pub struct EntropyAnalyzer {
    threshold: f64,
    sample_size: usize,
}

impl EntropyAnalyzer {
    /// Create a new analyzer with configurable threshold and sample size.
    pub fn new(threshold: f64, sample_size: usize) -> Self {
        Self {
            threshold,
            sample_size,
        }
    }

    /// Compute Shannon entropy of a byte sequence (0.0 to 8.0 bits/byte).
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &f in &freq {
            if f > 0 {
                let p = f as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Analyze a byte sequence.
    pub fn analyze_bytes(&self, data: &[u8], format_hint: Option<&str>) -> EntropyResult {
        let entropy = Self::shannon_entropy(data);
        let classification = self.classify(entropy, format_hint);
        let is_suspicious = self.is_suspicious(entropy, format_hint);

        EntropyResult {
            entropy,
            is_suspicious,
            classification,
            file_path: None,
            file_size: data.len() as u64,
            format_hint: format_hint.map(|s| s.to_string()),
        }
    }

    /// Analyze a file (reads first `sample_size` bytes).
    pub fn analyze_file(&self, path: &str) -> std::io::Result<EntropyResult> {
        let p = Path::new(path);
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e.to_lowercase()));
        let file_size = std::fs::metadata(path)?.len();

        let mut file = std::fs::File::open(path)?;
        let mut buf = vec![0u8; self.sample_size];
        let n = file.read(&mut buf)?;
        buf.truncate(n);

        let mut result = self.analyze_bytes(&buf, ext.as_deref());
        result.file_path = Some(path.to_string());
        result.file_size = file_size;
        Ok(result)
    }

    fn classify(&self, entropy: f64, format_hint: Option<&str>) -> String {
        if entropy >= 7.9 {
            return "likely_encrypted".to_string();
        }
        if entropy >= 7.5 {
            return "compressed_or_encrypted".to_string();
        }
        if let Some(ext) = format_hint {
            let ranges = format_entropy_ranges();
            if let Some(&(_, high)) = ranges.get(ext) {
                if entropy > high {
                    return "suspicious_for_format".to_string();
                }
            }
        }
        if entropy >= 6.0 {
            return "moderately_random".to_string();
        }
        "normal".to_string()
    }

    fn is_suspicious(&self, entropy: f64, format_hint: Option<&str>) -> bool {
        if entropy >= self.threshold {
            return true;
        }
        if let Some(ext) = format_hint {
            let ranges = format_entropy_ranges();
            if let Some(&(_, high)) = ranges.get(ext) {
                if entropy > high + 0.5 {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new(7.5, 8192)
    }
}

// ---------------------------------------------------------------------------
// RecursiveExtractor
// ---------------------------------------------------------------------------

/// Recursively extracts archives and analyzes entropy of contents.
pub struct RecursiveExtractor {
    max_depth: usize,
    max_total_size: u64,
    analyzer: EntropyAnalyzer,
    temp_dirs: Vec<PathBuf>,
    _temp_dir_guards: Vec<tempfile::TempDir>,
    total_extracted: u64,
}

impl RecursiveExtractor {
    pub fn new(max_depth: usize, max_total_size: u64, entropy_threshold: f64) -> Self {
        Self {
            max_depth,
            max_total_size,
            analyzer: EntropyAnalyzer::new(entropy_threshold, 8192),
            temp_dirs: Vec::new(),
            _temp_dir_guards: Vec::new(),
            total_extracted: 0,
        }
    }

    /// Recursively extract and analyze a file.
    pub fn extract(&mut self, path: &str) -> Vec<ExtractedItem> {
        self.total_extracted = 0;
        self.extract_recursive(path, 0, None)
    }

    fn extract_recursive(
        &mut self,
        path: &str,
        depth: usize,
        parent: Option<&str>,
    ) -> Vec<ExtractedItem> {
        if depth > self.max_depth {
            tracing::warn!("Max extraction depth {} exceeded", self.max_depth);
            return vec![];
        }
        if self.total_extracted > self.max_total_size {
            tracing::warn!("Max total extraction size exceeded");
            return vec![];
        }

        let mut results = Vec::new();

        // Analyze current file
        let result = match self.analyzer.analyze_file(path) {
            Ok(r) => r,
            Err(_) => return results,
        };

        let basename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let item = ExtractedItem {
            path: path.to_string(),
            original_name: basename,
            depth,
            entropy: result.entropy,
            classification: result.classification,
            is_suspicious: result.is_suspicious,
            size: result.file_size,
            parent_archive: parent.map(|s| s.to_string()),
        };
        self.total_extracted += result.file_size;
        results.push(item);

        // Try to extract as ZIP archive
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(_) = zip::ZipArchive::new(file) {
                if let Ok(mut items) = self.extract_zip(path, depth, parent.unwrap_or(path)) {
                    results.append(&mut items);
                }
            }
        }

        results
    }

    fn extract_zip(
        &mut self,
        path: &str,
        depth: usize,
        parent: &str,
    ) -> Result<Vec<ExtractedItem>, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

        // Check for zip bomb
        let mut total_uncompressed: u64 = 0;
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index(i) {
                total_uncompressed += f.size();
            }
        }

        if total_uncompressed > self.max_total_size {
            tracing::warn!("Potential zip bomb detected: {} bytes uncompressed", total_uncompressed);
            return Ok(vec![ExtractedItem {
                path: path.to_string(),
                original_name: "SUSPICIOUS_ARCHIVE".to_string(),
                depth,
                entropy: 8.0,
                classification: "likely_encrypted".to_string(),
                is_suspicious: true,
                size: total_uncompressed,
                parent_archive: Some(parent.to_string()),
            }]);
        }

        let tmpdir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let tmpdir_path = tmpdir.path().to_path_buf();

        let mut results = Vec::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
            if entry.is_dir() {
                continue;
            }

            let safe_name = Path::new(entry.name())
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            if safe_name.is_empty() {
                continue;
            }

            let out_path = tmpdir_path.join(&safe_name);
            let mut outfile = std::fs::File::create(&out_path).map_err(|e| e.to_string())?;
            std::io::copy(&mut entry, &mut outfile).map_err(|e| e.to_string())?;

            let out_str = out_path.to_str().unwrap_or("");
            let mut items = self.extract_recursive(out_str, depth + 1, Some(parent));
            results.append(&mut items);
        }

        self.temp_dirs.push(tmpdir_path);
        // Keep tmpdir alive via RAII guard (cleaned up when RecursiveExtractor is dropped)
        self._temp_dir_guards.push(tmpdir);

        Ok(results)
    }

    /// Clean up temporary directories.
    pub fn cleanup(&mut self) {
        for dir in self.temp_dirs.drain(..) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Drop for RecursiveExtractor {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl Default for RecursiveExtractor {
    fn default() -> Self {
        Self::new(5, 500 * 1024 * 1024, 7.5)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(EntropyAnalyzer::shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same byte — entropy should be 0
        let data = vec![0u8; 1000];
        assert_eq!(EntropyAnalyzer::shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_random() {
        // All 256 byte values equally — entropy should be ~8.0
        let mut data = Vec::new();
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = EntropyAnalyzer::shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_text() {
        let data = b"Hello, this is a test of the entropy analyzer. It should produce moderate entropy for normal English text content.";
        let entropy = EntropyAnalyzer::shannon_entropy(data);
        assert!(entropy > 3.0 && entropy < 6.0);
    }

    #[test]
    fn test_classify_normal() {
        let analyzer = EntropyAnalyzer::default();
        let result = analyzer.analyze_bytes(b"Hello world. Simple text.", Some(".txt"));
        assert_eq!(result.classification, "normal");
        assert!(!result.is_suspicious);
    }

    #[test]
    fn test_classify_high_entropy() {
        let analyzer = EntropyAnalyzer::default();
        // Generate high-entropy data
        let mut data = Vec::new();
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let result = analyzer.analyze_bytes(&data, None);
        assert!(result.entropy > 7.5);
        assert!(result.is_suspicious);
    }

    #[test]
    fn test_analyze_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "Hello, world! This is a test file with some content for entropy analysis.").unwrap();

        let analyzer = EntropyAnalyzer::default();
        let result = analyzer.analyze_file(path.to_str().unwrap()).unwrap();
        assert!(result.entropy > 0.0);
        assert_eq!(result.classification, "normal");
        assert!(!result.is_suspicious);
    }

    #[test]
    fn test_suspicious_for_format() {
        let analyzer = EntropyAnalyzer::default();
        // High-ish entropy for a text file
        let mut data = Vec::new();
        for _ in 0..500 {
            for b in 0..=200u8 {
                data.push(b);
            }
        }
        let result = analyzer.analyze_bytes(&data, Some(".txt"));
        // Text files normally 3.0-5.5, this should be higher
        assert!(result.entropy > 5.5);
    }
}
