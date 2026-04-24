//! Pairwise author-attribution scoring.
//!
//! Given two `FileMetadata` records, compute a signed-confidence
//! score describing how likely they share an authoring origin. The
//! output is driven by a set of **signals**, each weighted by
//! historical reliability:
//!
//! | Signal | Weight | Notes |
//! |--------|--------|-------|
//! | RSID root match | 0.50 | The single strongest OOXML signal — two docs sharing `w:rsidRoot` came off the same Word install. |
//! | RSID overlap (non-root) | up to 0.25 | More shared session IDs = stronger correlation. Scaled by Jaccard. |
//! | PDF doc-ID first-token match | 0.40 | Stable across edits; shared first ID ≈ "same original doc". |
//! | Creator match | 0.20 | High false-positive rate for common first names; kept moderate. |
//! | Producer (Application) match | 0.10 | "Microsoft Office Word" matches every Office doc on earth, so the contribution is capped. |
//! | Company match | 0.15 | Rarer than creator, stronger signal when present. |
//!
//! The weights are **capped** at 1.0 in total — stacking every
//! signal doesn't multiply past certainty. A hit on RSID root
//! alone already yields 0.50; add an exact creator + producer and
//! you're around 0.80. Investigators should treat > 0.60 as
//! "strong correlation, worth a manual look".

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::FileMetadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    RsidRootMatch,
    RsidOverlap,
    PdfDocIdMatch,
    CreatorMatch,
    ApplicationMatch,
    CompanyMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionSignal {
    pub kind: SignalKind,
    /// Weight contribution to the total score, post-scaling. Sum
    /// of all weights is capped at 1.0.
    pub weight: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionScore {
    /// Overall confidence 0.0..=1.0. Higher means "more likely
    /// shared origin". See module docs for thresholds.
    pub total: f64,
    pub signals: Vec<AttributionSignal>,
}

/// Compute an `AttributionScore` between two documents. Order-
/// independent — `compare(a, b)` and `compare(b, a)` produce the
/// same score.
pub fn compare(a: &FileMetadata, b: &FileMetadata) -> AttributionScore {
    let mut signals = Vec::new();

    // --- RSID root + overlap ---------------------------------------------
    if !a.rsids.is_empty() && !b.rsids.is_empty() {
        // Convention: first entry is `rsidRoot`.
        if a.rsids[0] == b.rsids[0] {
            signals.push(AttributionSignal {
                kind: SignalKind::RsidRootMatch,
                weight: 0.50,
                detail: format!("shared rsidRoot = {}", a.rsids[0]),
            });
        }

        let set_a: HashSet<&String> = a.rsids.iter().skip(1).collect();
        let set_b: HashSet<&String> = b.rsids.iter().skip(1).collect();
        let inter = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if inter > 0 && union > 0 {
            let jaccard = inter as f64 / union as f64;
            signals.push(AttributionSignal {
                kind: SignalKind::RsidOverlap,
                weight: 0.25 * jaccard,
                detail: format!(
                    "{inter}/{union} session IDs overlap (Jaccard {:.2})",
                    jaccard
                ),
            });
        }
    }

    // --- PDF doc-ID first token -----------------------------------------
    if let (Some((a0, _)), Some((b0, _))) = (&a.pdf_doc_id, &b.pdf_doc_id) {
        if a0 == b0 && !a0.is_empty() {
            signals.push(AttributionSignal {
                kind: SignalKind::PdfDocIdMatch,
                weight: 0.40,
                detail: format!("shared PDF /ID creation token = {a0}"),
            });
        }
    }

    // --- Creator ---------------------------------------------------------
    if let (Some(ca), Some(cb)) = (&a.creator, &b.creator) {
        if eq_ci(ca, cb) && !ca.trim().is_empty() {
            signals.push(AttributionSignal {
                kind: SignalKind::CreatorMatch,
                weight: 0.20,
                detail: format!("creator = \"{ca}\""),
            });
        }
    }

    // --- Application / producer -----------------------------------------
    if let (Some(aa), Some(ab)) = (&a.application, &b.application) {
        if eq_ci(aa, ab) && !aa.trim().is_empty() {
            // Generic producer strings ("Microsoft Office Word")
            // match too broadly to earn the full weight. A rough
            // guard: producers containing a version digit (e.g.
            // "Word 2021" or "Acrobat 11") are more distinctive.
            let specific = aa.chars().any(|c| c.is_ascii_digit());
            let w = if specific { 0.10 } else { 0.04 };
            signals.push(AttributionSignal {
                kind: SignalKind::ApplicationMatch,
                weight: w,
                detail: format!("application = \"{aa}\""),
            });
        }
    }

    // --- Company ---------------------------------------------------------
    if let (Some(ca), Some(cb)) = (&a.company, &b.company) {
        if eq_ci(ca, cb) && !ca.trim().is_empty() {
            signals.push(AttributionSignal {
                kind: SignalKind::CompanyMatch,
                weight: 0.15,
                detail: format!("company = \"{ca}\""),
            });
        }
    }

    // --- Sum with cap ----------------------------------------------------
    let total = signals.iter().map(|s| s.weight).sum::<f64>().min(1.0);

    AttributionScore { total, signals }
}

/// Case-insensitive string equality with whitespace trimming.
fn eq_ci(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}
