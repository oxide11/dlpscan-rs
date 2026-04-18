//! Polygon Siphon scanner engine.
//!
//! The detection core used by every Siphon pod. Contains patterns,
//! validators, normalization, context matching, scoring, and the
//! primary scan entry points. No file I/O or format-specific
//! dependencies — operates on `&str` input.
//!
//! Ingestion pods (siphon-fs, siphon-api, siphon-ds, siphon-gw)
//! depend on this crate for detection logic.

pub mod audit;
pub mod bin_lookup;
pub mod classification;
pub mod context;
pub mod edm;
pub mod errors;
pub mod lsh;
pub mod models;
pub mod normalize;
pub mod patterns;
pub mod scanner;
pub mod scoring;
pub mod validation;

pub use errors::DlpError;
pub use models::{Match, PatternDef};

pub type Result<T> = std::result::Result<T, errors::DlpError>;
