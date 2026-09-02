//! Polygon Siphon scanner engine.
//!
//! The detection core used by every Siphon pod. Contains patterns,
//! validators, normalization, context matching, scoring, and the
//! primary scan entry points. No file I/O or format-specific
//! dependencies — operates on `&str` input.
//!
//! Ingestion pods (siphon-fs, siphon-api, siphon-ds, siphon-gw)
//! depend on this crate for detection logic.

// Rust 1.98's clippy added `chunks_exact_to_as_chunks`, which suggests
// rewriting `chunks_exact(N)` as `as_chunks::<N>().0`. We keep
// `chunks_exact`: the call sites are the morse-digit decoders in
// `normalize` and the OLE string reader in `forensics::legacy_office`,
// and `as_chunks` yields `&[u8; N]` rather than `&[u8]`. That breaks the
// `*code == chunk` comparisons against `MORSE_DIGITS: &[(&[u8], u8)]`
// and would mean editing evasion-critical decode paths for a style
// preference. The existing form is correct and clearer here.
#![allow(clippy::chunks_exact_to_as_chunks)]

pub mod audit;
pub mod bin_lookup;
pub mod classification;
pub mod context;
pub mod edm;
pub mod errors;
pub mod findings_ring;
pub mod lsh;
pub mod models;
pub mod normalize;
pub mod overrides;
pub mod path_guard;
pub mod patterns;
pub mod scanner;
pub mod scoring;
pub mod validation;

#[cfg(feature = "forensics")]
pub mod forensics;

pub use errors::DlpError;
pub use models::{Match, PatternDef};

/// Crate version as declared in Cargo.toml, baked in at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type Result<T> = std::result::Result<T, errors::DlpError>;
