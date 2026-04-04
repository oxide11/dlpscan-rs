//! Confidence scoring and overlap deduplication.

use crate::models::{pattern_specificity, Match};

/// Compute a 0.0–1.0 confidence score for a match.
///
/// Factors:
/// - Base specificity of the pattern (how unique the regex is)
/// - Context keyword presence (boosts by 0.20)
/// - Context required but missing (caps at base * 0.3)
pub fn compute_confidence(sub_category: &str, has_context: bool, context_required: bool) -> f64 {
    let base = pattern_specificity(sub_category);

    let confidence = if has_context {
        (base + 0.20).min(1.0)
    } else if context_required {
        base * 0.3
    } else {
        base
    };

    (confidence * 100.0).round() / 100.0
}

/// Remove overlapping matches, keeping the highest-confidence one.
/// When two matches overlap in byte span, keep the one with higher confidence.
/// If tied, prefer the longer match.
pub fn deduplicate_overlapping(matches: &mut Vec<Match>) {
    if matches.is_empty() {
        return;
    }

    // Sort by start position, then by length descending.
    matches.sort_by(|a, b| {
        a.span
            .0
            .cmp(&b.span.0)
            .then_with(|| {
                let a_len = a.span.1 - a.span.0;
                let b_len = b.span.1 - b.span.0;
                b_len.cmp(&a_len)
            })
    });

    let mut result: Vec<Match> = Vec::with_capacity(matches.len());

    for m in matches.drain(..) {
        if let Some(prev) = result.last_mut() {
            if m.span.0 < prev.span.1 {
                // Overlapping — keep higher confidence, or longer if tied
                if m.confidence > prev.confidence {
                    *prev = m;
                } else if (m.confidence - prev.confidence).abs() < f64::EPSILON {
                    let m_len = m.span.1 - m.span.0;
                    let prev_len = prev.span.1 - prev.span.0;
                    if m_len > prev_len {
                        *prev = m;
                    }
                }
                continue;
            }
        }
        result.push(m);
    }

    *matches = result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_with_context() {
        let c = compute_confidence("Visa", true, false);
        assert!((c - 1.0).abs() < 0.01); // 0.90 + 0.20 = 1.10, capped to 1.0
    }

    #[test]
    fn test_confidence_no_context() {
        let c = compute_confidence("Visa", false, false);
        assert!((c - 0.90).abs() < 0.01);
    }

    #[test]
    fn test_confidence_context_required_missing() {
        let c = compute_confidence("Check Number", false, true);
        assert!(c < 0.10); // 0.15 * 0.3 = 0.045
    }

    #[test]
    fn test_dedup_no_overlap() {
        let mut matches = vec![
            Match::new("aaa".into(), "C".into(), "S".into(), false, 0.8, (0, 3), false),
            Match::new("bbb".into(), "C".into(), "S".into(), false, 0.8, (5, 8), false),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_dedup_overlap_keeps_higher() {
        let mut matches = vec![
            Match::new("aaa".into(), "C".into(), "S".into(), false, 0.5, (0, 5), false),
            Match::new("bbb".into(), "C".into(), "S".into(), false, 0.9, (3, 8), false),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        assert!((matches[0].confidence - 0.9).abs() < 0.01);
    }
}
