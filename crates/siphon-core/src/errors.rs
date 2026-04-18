//! Error types for dlpscan.

use std::fmt;

/// Result type alias using DlpError.
pub type Result<T> = std::result::Result<T, DlpError>;

/// All possible errors from dlpscan operations.
#[derive(Debug)]
pub enum DlpError {
    /// Input text is empty.
    EmptyInput,
    /// Input text exceeds maximum size.
    InputTooLarge { size: usize, max: usize },
    /// Invalid card number for Luhn validation.
    InvalidCardNumber(String),
    /// Regex compilation error.
    RegexError(regex::Error),
    /// I/O error during file operations.
    IoError(std::io::Error),
    /// Serialization/deserialization error.
    SerdeError(serde_json::Error),
    /// TOML parsing error.
    TomlError(toml::de::Error),
    /// Scan timeout exceeded.
    ScanTimeout { seconds: u64 },
    /// Pattern not found.
    PatternNotFound(String),
    /// Sensitive data detected (used by InputGuard in REJECT mode).
    SensitiveDataDetected {
        finding_count: usize,
        categories: Vec<String>,
    },
    /// Generic error with message.
    Other(String),
}

impl fmt::Display for DlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "Input text cannot be empty"),
            Self::InputTooLarge { size, max } => {
                write!(f, "Input text ({size} bytes) exceeds maximum ({max} bytes)")
            }
            Self::InvalidCardNumber(msg) => write!(f, "Invalid card number: {msg}"),
            Self::RegexError(e) => write!(f, "Regex error: {e}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::SerdeError(e) => write!(f, "Serialization error: {e}"),
            Self::TomlError(e) => write!(f, "TOML error: {e}"),
            Self::ScanTimeout { seconds } => write!(f, "Scan timeout after {seconds}s"),
            Self::PatternNotFound(name) => write!(f, "Pattern not found: {name}"),
            Self::SensitiveDataDetected {
                finding_count,
                categories,
            } => write!(
                f,
                "Sensitive data detected: {finding_count} findings in categories: {}",
                categories.join(", ")
            ),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DlpError {}

impl From<regex::Error> for DlpError {
    fn from(e: regex::Error) -> Self {
        Self::RegexError(e)
    }
}

impl From<std::io::Error> for DlpError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_json::Error> for DlpError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeError(e)
    }
}

impl From<toml::de::Error> for DlpError {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlError(e)
    }
}
