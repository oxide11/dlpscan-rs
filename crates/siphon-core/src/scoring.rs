//! Confidence scoring and overlap deduplication.

use crate::models::{pattern_specificity, Match};

/// Compute a 0.0–1.0 confidence score for a match using the
/// compile-time specificity for `sub_category`. Equivalent to
/// `compute_confidence_with(pattern_specificity(sub_category), ...)`.
///
/// Factors:
/// - Base specificity of the pattern (how unique the regex is)
/// - Context keyword presence (boosts by 0.20)
/// - Context required but missing (caps at base * 0.3)
pub fn compute_confidence(sub_category: &str, has_context: bool, context_required: bool) -> f64 {
    compute_confidence_with(
        pattern_specificity(sub_category),
        has_context,
        context_required,
    )
}

/// Where a context keyword was found, relative to the match.
///
/// Proximity is the evidence. A keyword sitting beside the match says this
/// number is described as an SSN; the same keyword somewhere in a covering
/// email says only that the message mentions SSNs somewhere. Both open a
/// context gate, but crediting them equally would let one mention of "SSN" in
/// a body promote every 9-digit number in every attachment to full
/// confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSource {
    /// No context keyword found.
    None,
    /// Keyword found within `context_distance` of the match, in the scanned
    /// text. The strong signal.
    Local,
    /// Keyword found only in the surrounding material supplied via
    /// `ScanConfig::context_envelope` — a different MIME part, the subject, a
    /// filename. Real evidence, but positionally unanchored.
    Envelope,
}

/// Confidence boost for a keyword found beside the match.
const LOCAL_CONTEXT_BOOST: f64 = 0.20;

/// Boost for a keyword found only in the envelope.
///
/// Half of local. The gate opens either way; the difference is how much the
/// finding is trusted, which is what a reviewer's min_confidence threshold
/// filters on. Chosen so an envelope-only hit on a mid-specificity pattern
/// lands below a typical 0.6 review threshold while a local hit clears it.
const ENVELOPE_CONTEXT_BOOST: f64 = 0.10;

/// Scoring that distinguishes where the context keyword was found.
///
/// `compute_confidence_with` is this with `Local`/`None`, preserved so the
/// existing callers and their scores are untouched.
pub fn compute_confidence_from_source(
    specificity: f64,
    source: ContextSource,
    context_required: bool,
) -> f64 {
    let confidence = match source {
        ContextSource::Local => (specificity + LOCAL_CONTEXT_BOOST).min(1.0),
        ContextSource::Envelope => (specificity + ENVELOPE_CONTEXT_BOOST).min(1.0),
        // Unchanged: a gated pattern with no context at all is heavily
        // discounted rather than dropped, so it can still surface to a
        // reviewer who lowers the threshold.
        ContextSource::None if context_required => specificity * 0.3,
        ContextSource::None => specificity,
    };

    (confidence * 100.0).round() / 100.0
}

/// Same scoring formula as `compute_confidence`, but the caller
/// supplies the base specificity. Used by the scanner when
/// PatternOverrides has bumped a pattern's specificity at runtime.
pub fn compute_confidence_with(specificity: f64, has_context: bool, context_required: bool) -> f64 {
    let confidence = if has_context {
        (specificity + 0.20).min(1.0)
    } else if context_required {
        specificity * 0.3
    } else {
        specificity
    };

    (confidence * 100.0).round() / 100.0
}

/// Region prefixes of the national-identifier categories
/// (`North America - Canada`, `Asia-Pacific - India`, …).
const NATIONAL_REGIONS: &[&str] = &[
    "Africa - ",
    "Asia-Pacific - ",
    "Europe - ",
    "Latin America - ",
    "Middle East - ",
    "North America - ",
];

fn is_national(category: &str) -> bool {
    NATIONAL_REGIONS.iter().any(|r| category.starts_with(r))
}

/// Both categories are national identifiers, and of different countries.
fn is_cross_border_collision(a: &str, b: &str) -> bool {
    a != b && is_national(a) && is_national(b)
}

/// Remove overlapping matches, keeping the highest-confidence one.
///
/// Before the tiebreakers: two national identifiers from *different
/// countries* matching the identical characters are a format collision —
/// a 12-digit run is a Newfoundland MCP number and an Indian Aadhaar
/// number alike — and the prose naming one country is the only evidence
/// that tells them apart. When exactly one of the two has its context
/// keyword nearby, it wins. Confidence cannot decide this: it ranks how
/// distinctive each *format* is, which says nothing about which country
/// this value is from, so `MCP number 987654321012` reported an Aadhaar
/// (0.65) over the health card (0.60) the text named. Scoped to national
/// categories (`<Region> - <Country>`) so a card brand, a secret type or
/// any other overlap keeps the tiebreakers below.
///
/// Tiebreakers, in order:
///   1. Higher confidence wins.
///   2. A context-gated match with its context satisfied beats an
///      ungated one at equal confidence. Rationale: when an analyst
///      writes `carte assurance maladie TREM85120123`, the Quebec HC
///      pattern (spec 0.55, ctx-gated) boosts to 0.75 with context
///      and ties ISIN's raw 0.75. The gated match is strictly more
///      informative — it says "the surrounding prose corroborates
///      this is a RAMQ card". Without this tiebreaker, the ungated
///      ISIN would silently shadow every Quebec HC on the same span.
///   3. If tied on confidence + gated-state, prefer the pattern with
///      higher base specificity. This keeps `JWT Token` (0.95) from
///      being silently swallowed by a nested `Bearer Token` (0.80)
///      when both clamp to 1.0 confidence in an Authorization
///      header.
///   4. If specificity is also tied, prefer the longer match.
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
                if m.span == prev.span
                    && m.has_context != prev.has_context
                    && is_cross_border_collision(&m.category, &prev.category)
                {
                    if m.has_context {
                        *prev = m;
                    }
                    continue;
                }
                // Overlapping — apply the four-step tiebreaker.
                if m.confidence > prev.confidence {
                    *prev = m;
                } else if (m.confidence - prev.confidence).abs() < f64::EPSILON {
                    let m_gated = m.context_required && m.has_context;
                    let prev_gated = prev.context_required && prev.has_context;
                    if m_gated && !prev_gated {
                        *prev = m;
                    } else if m_gated == prev_gated {
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

    fn same_span(category: &str, sub: &str, has_context: bool, confidence: f64) -> Match {
        Match::new(
            "987654321012".into(),
            category.into(),
            sub.into(),
            has_context,
            confidence,
            (10, 22),
            false,
        )
    }

    fn winner(mut matches: Vec<Match>) -> String {
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        matches.remove(0).sub_category
    }

    #[test]
    fn test_dedup_cross_border_collision_goes_to_the_named_country() {
        // `MCP number 987654321012`: Aadhaar 0.65 bare vs NL HC 0.60 with
        // its keyword. Either order of arrival.
        let aadhaar = || same_span("Asia-Pacific - India", "India Aadhaar", false, 0.65);
        let nl = || same_span("North America - Canada", "Newfoundland HC", true, 0.60);
        assert_eq!(winner(vec![aadhaar(), nl()]), "Newfoundland HC");
        assert_eq!(winner(vec![nl(), aadhaar()]), "Newfoundland HC");
        // Neither named: confidence decides, as before.
        let nl_bare = || same_span("North America - Canada", "Newfoundland HC", false, 0.60);
        assert_eq!(winner(vec![aadhaar(), nl_bare()]), "India Aadhaar");
    }

    #[test]
    fn test_dedup_keyword_rule_is_only_for_national_ids() {
        // `account number 4532…`: PAN (0.60 + keyword) must not take a
        // Visa (0.95) just because the prose said "account number".
        let visa = || same_span("Credit Card Numbers", "Visa", false, 0.95);
        let pan = || same_span("Primary Account Numbers", "PAN", true, 0.80);
        assert_eq!(winner(vec![visa(), pan()]), "Visa");
        assert_eq!(winner(vec![pan(), visa()]), "Visa");
        // Same country is not a cross-border collision either.
        let on = || same_span("North America - Canada", "Ontario DL", false, 0.70);
        let qc = || same_span("North America - Canada", "Quebec DL", true, 0.60);
        assert_eq!(winner(vec![on(), qc()]), "Ontario DL");
    }

    #[test]
    fn test_dedup_partial_overlap_ignores_keyword_rule() {
        let mut matches = vec![
            Match::new(
                "a".into(),
                "Asia-Pacific - India".into(),
                "Bare".into(),
                false,
                0.70,
                (0, 12),
                false,
            ),
            Match::new(
                "b".into(),
                "North America - Canada".into(),
                "Described".into(),
                true,
                0.50,
                (5, 17),
                false,
            ),
        ];
        deduplicate_overlapping(&mut matches);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].sub_category, "Bare");
    }
}
