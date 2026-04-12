//! Polygon Siphon — High-performance DLP scanner for detecting, redacting, and protecting sensitive data.
//!
//! Designed for maximum throughput using RegexSet two-phase matching, zero-copy
//! scanning, and rayon parallelism.

// Re-export siphon-core modules so existing `crate::models`, `crate::scanner`, etc.
// references in this crate keep compiling unchanged.
pub use siphon_core::context;
pub use siphon_core::edm;
pub use siphon_core::errors;
pub use siphon_core::lsh;
pub use siphon_core::models;
pub use siphon_core::normalize;
pub use siphon_core::patterns;
pub use siphon_core::scanner;
pub use siphon_core::scoring;
pub use siphon_core::validation;

pub mod allowlist;
pub mod api;
pub mod audit;
pub mod batch;
pub use siphon_core::bin_lookup;
pub mod cache;
pub mod compliance;
pub mod config;
pub mod entropy;
pub mod extractors;
pub mod guard;
pub mod http_util;
pub mod metrics;
pub mod pipeline;
pub mod plugins;
pub mod policy;
pub mod profiles;
pub mod rbac;
#[cfg(feature = "redis-rate-limit")]
pub mod redis_rate_limit;
#[cfg(feature = "siem")]
pub mod siem;
pub mod streaming;
pub mod tui;
#[cfg(feature = "webhooks")]
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
#[cfg(feature = "webhooks")]
pub use webhooks::WebhookNotifier;
