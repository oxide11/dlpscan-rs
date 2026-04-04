//! Batch scanning — CSV, JSON/JSONL, and parallel text scanning.
//!
//! Process multiple texts or files in parallel with progress callbacks
//! and aggregated reporting.

use std::collections::HashMap;

use rayon::prelude::*;
use serde::Serialize;

use crate::guard::{InputGuard, ScanResult};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const TEXT_TRUNCATE_LENGTH: usize = 200;

/// Result of scanning a single item in a batch.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub source_id: String,
    pub text: String, // truncated to 200 chars
    pub scan_result: Option<ScanResult>,
    pub error: Option<String>,
}

/// Aggregated summary of a batch scan.
#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub total_items: usize,
    pub items_with_findings: usize,
    pub total_findings: usize,
    pub categories_summary: HashMap<String, usize>,
    pub duration_seconds: f64,
    pub results: Vec<BatchResult>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        text.to_string()
    } else {
        let truncated: String = text.chars().take(max_chars).collect();
        format!("{}...", truncated)
    }
}

// ---------------------------------------------------------------------------
// BatchScanner
// ---------------------------------------------------------------------------

/// Parallel batch scanner.
pub struct BatchScanner {
    guard: InputGuard,
}

impl BatchScanner {
    /// Create a new BatchScanner with the given InputGuard.
    pub fn new(guard: InputGuard) -> Self {
        Self { guard }
    }

    /// Create with default InputGuard.
    pub fn default_guard() -> Self {
        Self {
            guard: InputGuard::new(),
        }
    }

    /// Scan multiple texts in parallel.
    pub fn scan_texts(
        &self,
        texts: &[(&str, &str)], // (source_id, text) pairs
    ) -> Vec<BatchResult> {
        texts
            .par_iter()
            .map(|(source_id, text)| self.scan_one(source_id, text))
            .collect()
    }

    /// Scan a CSV file, concatenating selected columns per row.
    pub fn scan_csv(
        &self,
        path: &str,
        columns: Option<&[&str]>,
        delimiter: u8,
    ) -> Result<Vec<BatchResult>, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let mut lines = content.lines();

        // Parse header
        let header_line = lines.next().ok_or("Empty CSV file")?;
        let headers: Vec<&str> = header_line.split(delimiter as char).collect();

        // Determine which column indices to scan
        let col_indices: Vec<usize> = match columns {
            Some(cols) => cols
                .iter()
                .filter_map(|c| headers.iter().position(|h| h.trim() == *c))
                .collect(),
            None => (0..headers.len()).collect(),
        };

        for (row_num, line) in lines.enumerate() {
            let fields: Vec<&str> = line.split(delimiter as char).collect();
            let text: String = col_indices
                .iter()
                .filter_map(|&i| fields.get(i).map(|s| s.trim()))
                .collect::<Vec<_>>()
                .join(" ");

            if text.is_empty() {
                continue;
            }

            let source_id = format!("{}:row:{}", path, row_num + 1);
            results.push(self.scan_one(&source_id, &text));
        }

        Ok(results)
    }

    /// Scan a JSON or JSONL file.
    pub fn scan_json(
        &self,
        path: &str,
        fields: Option<&[&str]>,
    ) -> Result<Vec<BatchResult>, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut results = Vec::new();

        // Try parsing as JSON array or object first
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            let records: Vec<&serde_json::Value> = if let Some(arr) = value.as_array() {
                arr.iter().collect()
            } else if value.is_object() {
                vec![&value]
            } else {
                return Err("Expected JSON array or object".to_string());
            };

            for (idx, record) in records.iter().enumerate() {
                let text = extract_json_fields(record, fields);
                if text.is_empty() {
                    continue;
                }
                let source_id = format!("{}:record:{}", path, idx);
                results.push(self.scan_one(&source_id, &text));
            }
        } else {
            // Try JSONL
            for (idx, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                    let text = extract_json_fields(&record, fields);
                    if text.is_empty() {
                        continue;
                    }
                    let source_id = format!("{}:record:{}", path, idx);
                    results.push(self.scan_one(&source_id, &text));
                }
            }
        }

        Ok(results)
    }

    /// Summarize batch results into a report.
    pub fn summarize(results: Vec<BatchResult>, duration_seconds: f64) -> BatchReport {
        let total_items = results.len();
        let mut items_with_findings = 0;
        let mut total_findings = 0;
        let mut categories_summary: HashMap<String, usize> = HashMap::new();

        for r in &results {
            if let Some(ref scan_result) = r.scan_result {
                if !scan_result.is_clean {
                    items_with_findings += 1;
                }
                total_findings += scan_result.findings.len();
                for cat in &scan_result.categories_found {
                    *categories_summary.entry(cat.clone()).or_default() += 1;
                }
            }
        }

        BatchReport {
            total_items,
            items_with_findings,
            total_findings,
            categories_summary,
            duration_seconds,
            results,
        }
    }

    fn scan_one(&self, source_id: &str, text: &str) -> BatchResult {
        match self.guard.scan(text) {
            Ok(scan_result) => BatchResult {
                source_id: source_id.to_string(),
                text: truncate(text, TEXT_TRUNCATE_LENGTH),
                scan_result: Some(scan_result),
                error: None,
            },
            Err(e) => BatchResult {
                source_id: source_id.to_string(),
                text: truncate(text, TEXT_TRUNCATE_LENGTH),
                scan_result: None,
                error: Some(e.to_string()),
            },
        }
    }
}

fn extract_json_fields(record: &serde_json::Value, fields: Option<&[&str]>) -> String {
    if let Some(obj) = record.as_object() {
        let values: Vec<String> = match fields {
            Some(field_names) => field_names
                .iter()
                .filter_map(|f| obj.get(*f))
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            None => obj
                .values()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        };
        values.join(" ")
    } else if let Some(s) = record.as_str() {
        s.to_string()
    } else {
        record.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world this is long", 10), "hello worl...");
    }

    #[test]
    fn test_scan_texts() {
        let scanner = BatchScanner::default_guard();
        let texts = vec![
            ("item1", "No sensitive data here"),
            ("item2", "Call me at 555-123-4567"),
        ];
        let results = scanner.scan_texts(&texts);
        assert_eq!(results.len(), 2);
        assert!(results[0].error.is_none());
        assert!(results[1].error.is_none());
    }

    #[test]
    fn test_scan_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv_path = dir.path().join("test.csv");
        std::fs::write(
            &csv_path,
            "name,email,notes\nJohn,john@example.com,test\nJane,jane@test.org,hello\n",
        )
        .unwrap();

        let scanner = BatchScanner::default_guard();
        let results = scanner
            .scan_csv(csv_path.to_str().unwrap(), Some(&["email"]), b',')
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_scan_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("test.json");
        std::fs::write(
            &json_path,
            r#"[{"name": "John", "email": "john@example.com"}, {"name": "Jane", "email": "jane@test.org"}]"#,
        )
        .unwrap();

        let scanner = BatchScanner::default_guard();
        let results = scanner
            .scan_json(json_path.to_str().unwrap(), Some(&["email"]))
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_scan_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("test.jsonl");
        std::fs::write(
            &jsonl_path,
            "{\"text\": \"My SSN is 123-45-6789\"}\n{\"text\": \"No data here\"}\n",
        )
        .unwrap();

        let scanner = BatchScanner::default_guard();
        let results = scanner
            .scan_json(jsonl_path.to_str().unwrap(), Some(&["text"]))
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_summarize() {
        let scanner = BatchScanner::default_guard();
        let texts = vec![("a", "hello"), ("b", "world")];
        let results = scanner.scan_texts(&texts);
        let report = BatchScanner::summarize(results, 0.1);
        assert_eq!(report.total_items, 2);
    }
}
