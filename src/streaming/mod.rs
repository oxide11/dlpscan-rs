//! Streaming scanner for processing data in chunks.

use std::sync::Mutex;

use crate::models::Match;
use crate::scanner::{self, ScanConfig};

/// Stream scanner that processes text in buffered chunks.
pub struct StreamScanner {
    buffer: Mutex<String>,
    buffer_size: usize,
    overlap: usize,
    config: ScanConfig,
}

impl StreamScanner {
    /// Create a new stream scanner.
    pub fn new(buffer_size: usize, overlap: usize) -> Self {
        let buffer_size = buffer_size.min(100 * 1024 * 1024); // Cap at 100MB
        let buffer_size = buffer_size.max(1024); // At least 1KB
        let overlap = overlap.min(buffer_size / 2); // Overlap can't exceed half buffer
        Self {
            buffer: Mutex::new(String::with_capacity(buffer_size + overlap)),
            buffer_size,
            overlap,
            config: ScanConfig::default(),
        }
    }

    /// Create with custom scan config.
    pub fn with_config(mut self, config: ScanConfig) -> Self {
        self.config = config;
        self
    }

    /// Feed a chunk of text. Returns matches if the buffer is full.
    pub fn feed(&self, chunk: &str) -> Vec<Match> {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        buf.push_str(chunk);

        if buf.len() >= self.buffer_size {
            let text = buf.clone();
            // Keep overlap for cross-boundary matches
            if text.len() > self.overlap {
                *buf = text[text.len() - self.overlap..].to_string();
            } else {
                buf.clear();
            }

            match scanner::scan_text_with_config(&text, &self.config) {
                Ok(matches) => matches,
                Err(e) => {
                    tracing::error!(error = %e, "Streaming scan failed on buffer flush");
                    vec![]
                }
            }
        } else {
            vec![]
        }
    }

    /// Flush remaining buffer and return any matches.
    pub fn flush(&self) -> Vec<Match> {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        if buf.is_empty() {
            return vec![];
        }

        let text = std::mem::take(&mut *buf);
        match scanner::scan_text_with_config(&text, &self.config) {
            Ok(matches) => matches,
            Err(e) => {
                tracing::error!(error = %e, "Streaming scan failed on final flush");
                vec![]
            }
        }
    }

    /// Reset the scanner state.
    pub fn reset(&self) {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        buf.clear();
    }
}

impl Default for StreamScanner {
    fn default() -> Self {
        Self::new(4096, 256)
    }
}
