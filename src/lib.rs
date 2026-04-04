//! dlpscan — High-performance DLP scanner for detecting, redacting, and protecting sensitive data.
//!
//! This is a Rust port of the Python dlpscan library, designed for maximum throughput
//! using RegexSet two-phase matching, zero-copy scanning, and rayon parallelism.

pub mod allowlist;
pub mod api;
pub mod audit;
pub mod batch;
pub mod cache;
pub mod compliance;
pub mod config;
pub mod context;
pub mod edm;
pub mod entropy;
pub mod errors;
pub mod extractors;
pub mod guard;
pub mod lsh;
pub mod metrics;
pub mod models;
pub mod normalize;
pub mod patterns;
pub mod pipeline;
pub mod plugins;
pub mod policy;
pub mod profiles;
pub mod scanner;
pub mod scoring;
pub mod siem;
pub mod streaming;
pub mod validation;
pub mod webhooks;

// Re-exports for ergonomic API
pub use errors::{DlpError, Result};
pub use guard::{Action, InputGuard, Mode, Preset, ScanResult};
pub use models::{Match, PatternDef};
pub use pipeline::{FileJob, Pipeline, PipelineResult};
pub use scanner::{scan_text, ScanConfig};
pub use streaming::StreamScanner;

// Module re-exports
pub use audit::{AuditEvent, AuditLogger};
pub use batch::{BatchReport, BatchResult, BatchScanner};
pub use cache::ScanCache;
pub use compliance::{ComplianceReport, ComplianceReporter};
pub use config::Config;
pub use edm::ExactDataMatcher;
pub use entropy::{EntropyAnalyzer, EntropyResult};
pub use extractors::{extract_text, ExtractionResult};
pub use lsh::DocumentVault;
pub use metrics::{MetricsCollector, ScanMetrics};
pub use policy::{Policy, PolicyEngine};
pub use profiles::{MaskingProfile, ProfileRegistry};
pub use webhooks::WebhookNotifier;
