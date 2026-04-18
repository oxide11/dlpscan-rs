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
///
/// Tiebreakers, in order:
///   1. Higher confidence wins.
///   2. If confidence is tied (e.g. both patterns hit 1.0 after a
///      context boost), prefer the pattern with higher base
///      specificity. This is what keeps `JWT Token` (0.95) from being
///      silently swallowed by a nested `Bearer Token` (0.80) match
///      when the JWT sits inside an `Authorization: Bearer …` header:
///      both match the same span with context, both clamp to 1.0
///      confidence, and without the specificity tiebreaker the
///      longer Bearer span would win even though the JWT is the
///      more informative finding.
///   3. If specificity is also tied, prefer the longer match.
pub fn deduplicate_overlapping(matches: &mut Vec<Match>) {
    if matches.is_empty() {
        return;
    }

    // Sort by start position, then by length descending.
    matches.sort_by(|a, b| {
        a.span.0.cmp(&b.span.0).then_with(|| {
            let a_len = a.span.1 - a.span.0;
            let b_len = b.span.1 - b.span.0;
            b_len.cmp(&a_len)
        })
    });

    let mut result: Vec<Match> = Vec::with_capacity(matches.len());

    for m in matches.drain(..) {
        if let Some(prev) = result.last_mut() {
            if m.span.0 < prev.span.1 {
                // Overlapping — apply the three-step tiebreaker.
                if m.confidence > prev.confidence {
                    *prev = m;
                } else if (m.confidence - prev.confidence).abs() < f64::EPSILON {
                    let m_spec = pattern_specificity(&m.sub_category);
                    let prev_spec = pattern_specificity(&prev.sub_category);
                    if m_spec > prev_spec {
                        *prev = m;
                    } else if (m_spec - prev_spec).abs() < f64::EPSILON {
                        let m_len = m.span.1 - m.span.0;
                        let prev_len = prev.span.1 - prev.span.0;
                        if m_len > prev_len {
                            *prev = m;
                        }
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
            Match::new(
                "aaa".into(),
                "C".into(),
                "S".into(),
                false,
                0.8,
                (0, 3),
                false,
            ),
            Match::new(
                "bbb".into(),
                "C".into(),
                "S".into(),
                false,
                0.8,
                (5, 8),
                false,
            ),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_dedup_overlap_keeps_higher() {
        let mut matches = vec![
            Match::new(
                "aaa".into(),
                "C".into(),
                "S".into(),
                false,
                0.5,
                (0, 5),
                false,
            ),
            Match::new(
                "bbb".into(),
                "C".into(),
                "S".into(),
                false,
                0.9,
                (3, 8),
                false,
            ),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        assert!((matches[0].confidence - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_dedup_specificity_tiebreaker_jwt_beats_bearer() {
        // Regression: when a JWT sits inside an Authorization: Bearer
        // header, both patterns fire, both end up at confidence 1.0
        // after the context boost, and both span the same tail. The
        // old tiebreaker preferred the LONGER match, which meant the
        // bigger Bearer Token span (which includes the `Bearer ` prefix)
        // always won over the nested JWT Token — silently dropping
        // the more informative finding. Dedup now prefers higher
        // pattern specificity on confidence ties: JWT Token's base
        // specificity of 0.95 beats Bearer Token's 0.80, so JWT
        // survives and Bearer is dropped.
        //
        // We use the real sub_category names here (not placeholders)
        // so the test also pins the base specificity values the
        // tiebreaker depends on.
        let bearer_len = "Bearer <jwt>".len();
        let jwt_len = "<jwt>".len();
        assert!(bearer_len > jwt_len, "bearer must be the longer span");

        let mut matches = vec![
            // Bearer: starts earlier (92), longer (including prefix),
            // same confidence after context boost.
            Match::new(
                "Bearer <jwt>".into(),
                "Generic Secrets".into(),
                "Bearer Token".into(),
                true, // has_context
                1.0,
                (92, 92 + bearer_len),
                false,
            ),
            // JWT: starts 7 bytes later (after "Bearer "), shorter
            // span, same confidence.
            Match::new(
                "<jwt>".into(),
                "Generic Secrets".into(),
                "JWT Token".into(),
                true, // has_context
                1.0,
                (99, 92 + bearer_len),
                false,
            ),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].sub_category, "JWT Token");
    }

    #[test]
    fn test_dedup_specificity_tied_falls_through_to_length() {
        // Counter-test for the length-tiebreaker fallback: if
        // confidence AND specificity are both tied, the longer match
        // should still win. Use the same sub_category name so
        // specificity is identical.
        let mut matches = vec![
            Match::new(
                "short".into(),
                "Generic Secrets".into(),
                "Bearer Token".into(),
                false,
                0.8,
                (0, 5),
                false,
            ),
            Match::new(
                "longer match".into(),
                "Generic Secrets".into(),
                "Bearer Token".into(),
                false,
                0.8,
                (3, 15),
                false,
            ),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "longer match");
    }
}
