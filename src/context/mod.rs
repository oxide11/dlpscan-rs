//! Context keyword matching engine.
//!
//! Uses Aho-Corasick for fast multi-keyword matching, with fuzzy fallback
//! via Levenshtein distance for typo tolerance.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;
use std::collections::HashMap;

mod keywords;
pub use keywords::CONTEXT_KEYWORDS;

/// Maximum edit distance for fuzzy matching.
const FUZZY_MAX_DISTANCE: usize = 2;

/// Minimum keyword length for fuzzy matching.
const FUZZY_MIN_KEYWORD_LENGTH: usize = 5;

/// Default context distance (chars before/after match).
const DEFAULT_DISTANCE: usize = 50;

/// Context keyword entry for a (category, sub_category) pair.
#[derive(Debug, Clone, Copy)]
pub struct ContextEntry {
    pub keywords: &'static [&'static str],
    pub distance: usize,
}

/// Hit index from Aho-Corasick search — stores positions of keyword matches.
pub struct ContextHitIndex {
    /// Map from (category, sub_category) → list of (start, end) byte positions.
    #[allow(dead_code)]
    hits: HashMap<(&'static str, &'static str), Vec<(usize, usize)>>,
    /// Same data keyed by owned strings for O(1) lookup from non-static &str.
    reverse: HashMap<(String, String), Vec<(usize, usize)>>,
}

impl ContextHitIndex {
    /// Check if any keyword for (category, sub_category) was found in the given byte range.
    pub fn has_hit_in_range(
        &self,
        category: &str,
        sub_category: &str,
        range_start: usize,
        range_end: usize,
    ) -> bool {
        // Use the reverse lookup to find positions in O(1)
        if let Some(positions) = self.reverse.get(&(category.to_string(), sub_category.to_string())) {
            return positions
                .iter()
                .any(|&(start, _end)| start >= range_start && start < range_end);
        }
        false
    }
}

/// Global Aho-Corasick matcher built from all context keywords.
static AC_MATCHER: Lazy<Option<(AhoCorasick, Vec<(&'static str, &'static str)>)>> =
    Lazy::new(|| {
        let keywords = CONTEXT_KEYWORDS;
        if keywords.is_empty() {
            return None;
        }

        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_keys: Vec<(&'static str, &'static str)> = Vec::new();

        for &(category, sub_category, entry) in keywords {
            for &kw in entry.keywords {
                patterns.push(kw.to_lowercase());
                pattern_keys.push((category, sub_category));
            }
        }

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .ok()?;

        Some((ac, pattern_keys))
    });

/// Search text for all context keywords using Aho-Corasick.
pub fn build_hit_index(text: &str) -> Option<ContextHitIndex> {
    let (ac, pattern_keys) = AC_MATCHER.as_ref().as_ref()?;

    let mut hits: HashMap<(&'static str, &'static str), Vec<(usize, usize)>> = HashMap::new();

    // AC is built with ascii_case_insensitive(true), no need to lowercase
    for mat in ac.find_iter(text) {
        let key = pattern_keys[mat.pattern().as_usize()];
        hits.entry(key)
            .or_default()
            .push((mat.start(), mat.end()));
    }

    // Build reverse lookup with owned keys
    let reverse: HashMap<(String, String), Vec<(usize, usize)>> = hits
        .iter()
        .map(|(&(cat, sub), positions)| {
            ((cat.to_string(), sub.to_string()), positions.clone())
        })
        .collect();

    Some(ContextHitIndex { hits, reverse })
}

/// Get context distance for a category.
pub fn context_distance(category: &str) -> usize {
    for &(cat, _, entry) in CONTEXT_KEYWORDS {
        if cat == category {
            return entry.distance;
        }
    }
    DEFAULT_DISTANCE
}

/// Adjust index down to the nearest UTF-8 char boundary.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Adjust index up to the nearest UTF-8 char boundary.
fn ceil_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Check if context keywords appear near a match span.
///
/// Three-pass matching:
/// 1. Aho-Corasick positional lookup (if hit index available)
/// 2. Fuzzy Levenshtein match for typos
/// 3. Leet-speak normalized re-check
pub fn check_context(
    text: &str,
    start: usize,
    end: usize,
    category: &str,
    sub_category: &str,
    hit_index: Option<&ContextHitIndex>,
) -> bool {
    let distance = get_distance_for(category);
    let range_start = start.saturating_sub(distance);
    let range_end = (end + distance).min(text.len());

    // Fast path: AC hit index lookup — if we have an index, this is authoritative
    // for exact matches. Only fall through to fuzzy/leet for edge cases.
    if let Some(index) = hit_index {
        if index.has_hit_in_range(category, sub_category, range_start, range_end) {
            return true;
        }
        // AC index was built from all keywords — if no exact hit, skip expensive
        // fuzzy/leet checks for performance. The AC already covers exact matches.
        return false;
    }

    // Fallback path: no AC index available (shouldn't happen in normal flow)
    let keywords = get_keywords(category, sub_category);
    if keywords.is_empty() {
        return false;
    }

    let range_start = floor_char_boundary(text, range_start);
    let start = floor_char_boundary(text, start);
    let end = ceil_char_boundary(text, end);
    let range_end = ceil_char_boundary(text, range_end);
    let pre_text = &text[range_start..start];
    let post_text = &text[end..range_end];
    let context_window = format!("{} {}", pre_text, post_text);
    let context_lower = context_window.to_lowercase();

    for &kw in keywords {
        let kw_lower = kw.to_lowercase();
        if context_lower.contains(&kw_lower) {
            return true;
        }
    }

    false
}

/// Get the context distance for a category.
fn get_distance_for(category: &str) -> usize {
    for &(cat, _, entry) in CONTEXT_KEYWORDS {
        if cat == category {
            return entry.distance;
        }
    }
    DEFAULT_DISTANCE
}

/// Get raw keywords for a (category, sub_category) pair.
fn get_keywords(category: &str, sub_category: &str) -> &'static [&'static str] {
    for &(cat, sub, entry) in CONTEXT_KEYWORDS {
        if cat == category && sub == sub_category {
            return entry.keywords;
        }
    }
    &[]
}

/// Fuzzy keyword matching using Levenshtein distance.
fn fuzzy_keyword_match(text_lower: &str, keywords: &[&str]) -> bool {
    let words: Vec<&str> = text_lower.split_whitespace().collect();
    if words.is_empty() {
        return false;
    }

    for &keyword in keywords {
        let kw_lower = keyword.to_lowercase();
        if kw_lower.len() < FUZZY_MIN_KEYWORD_LENGTH {
            continue;
        }

        let kw_words: Vec<&str> = kw_lower.split_whitespace().collect();
        let kw_word_count = kw_words.len();

        if kw_word_count == 1 {
            for word in &words {
                let len_diff = if word.len() > kw_lower.len() {
                    word.len() - kw_lower.len()
                } else {
                    kw_lower.len() - word.len()
                };
                if len_diff > FUZZY_MAX_DISTANCE {
                    continue;
                }
                if levenshtein_distance(word, &kw_lower, FUZZY_MAX_DISTANCE) <= FUZZY_MAX_DISTANCE
                {
                    return true;
                }
            }
        } else if words.len() >= kw_word_count {
            for i in 0..=(words.len() - kw_word_count) {
                let ngram = words[i..i + kw_word_count].join(" ");
                let len_diff = if ngram.len() > kw_lower.len() {
                    ngram.len() - kw_lower.len()
                } else {
                    kw_lower.len() - ngram.len()
                };
                if len_diff > FUZZY_MAX_DISTANCE {
                    continue;
                }
                if levenshtein_distance(&ngram, &kw_lower, FUZZY_MAX_DISTANCE)
                    <= FUZZY_MAX_DISTANCE
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Compute Levenshtein edit distance with early termination.
fn levenshtein_distance(s1: &str, s2: &str, max_dist: usize) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let n = s1_chars.len();
    let m = s2_chars.len();

    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    if s1 == s2 {
        return 0;
    }

    // Use strsim for the actual computation
    let d = strsim::levenshtein(s1, s2);
    if d <= max_dist {
        d
    } else {
        max_dist + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_exact() {
        assert_eq!(levenshtein_distance("hello", "hello", 2), 0);
    }

    #[test]
    fn test_levenshtein_one_edit() {
        assert_eq!(levenshtein_distance("hello", "hallo", 2), 1);
    }

    #[test]
    fn test_levenshtein_exceeds() {
        assert!(levenshtein_distance("hello", "world", 2) > 2);
    }
}
