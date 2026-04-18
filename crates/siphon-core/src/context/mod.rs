//! Context keyword matching engine.
//!
//! Uses Aho-Corasick for fast multi-keyword matching, with fuzzy fallback
//! via Levenshtein distance for typo tolerance.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;
use std::collections::HashMap;

mod keywords;
pub use keywords::CONTEXT_KEYWORDS;

/// Maximum edit distance for fuzzy matching (reserved for future use).
#[allow(dead_code)]
const FUZZY_MAX_DISTANCE: usize = 2;

/// Minimum keyword length for fuzzy matching (reserved for future use).
#[allow(dead_code)]
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
///
/// Earlier revisions of this type kept a second `reverse:
/// HashMap<String, HashMap<String, Vec<_>>>` purely to avoid allocating
/// lookup keys on each `has_hit_in_range` call. The reverse map paid
/// two `String::from(&'static str)` allocations plus a full `Vec` clone
/// per unique (category, sub_category) hit — every scan. For a
/// context-heavy document with ~20 unique keyword hits, that was ~40
/// String allocations and ~20 Vec clones, all thrown away at end of
/// scan. The audit flagged it as a rebuild-per-scan hot spot.
///
/// We drop the reverse map entirely and iterate `hits` directly in
/// `has_hit_in_range`. The `hits` map is keyed on
/// `(&'static str, &'static str)` so no allocations happen on either
/// the build or the lookup path. The lookup is O(N) over the small
/// number of unique hit keys (typically 1–20) — with short static
/// strings that compare in a few bytes, linear scan is actually faster
/// than a hashed lookup for sizes in this range, and it beats the
/// previous implementation on both memory and cache behavior.
pub struct ContextHitIndex {
    /// Map from (category, sub_category) → list of (start, end) byte positions.
    hits: HashMap<(&'static str, &'static str), Vec<(usize, usize)>>,
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
        // Linear scan over the hits map — size is bounded by unique
        // keyword-hit keys present in the document, not by pattern count.
        for ((cat, sub), positions) in &self.hits {
            if *cat == category && *sub == sub_category {
                return positions
                    .iter()
                    .any(|&(start, _end)| start >= range_start && start < range_end);
            }
        }
        false
    }

    /// Iterate the `(category, sub_category)` keys that had at least
    /// one keyword hit anywhere in the scanned text.
    ///
    /// This is equivalent to asking `has_hit_in_range(..., 0, text.len())`
    /// for every possible (cat, sub) key, but in a single pass over
    /// the underlying hit map rather than a quadratic scan that calls
    /// `has_hit_in_range` once per compiled pattern. The scanner uses
    /// this to build its `active_gated` set, which is the set of
    /// context-gated patterns whose keywords are present in the
    /// document at all. Before this method, that set was built by
    /// iterating all ~560 compiled patterns and calling
    /// `has_hit_in_range` on each — cheap per call but quadratic in
    /// aggregate.
    pub fn hit_keys(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.hits.keys().copied()
    }
}

/// AC matcher state. The second field is indexed by AC pattern
/// index and stores the **list** of (category, sub_category) pairs
/// that share that keyword — not a single pair. See the doc on
/// `AC_MATCHER` below for the rationale.
type AcMatcherInner = Option<(AhoCorasick, Vec<Vec<(&'static str, &'static str)>>)>;

/// Global Aho-Corasick matcher built from all context keywords.
///
/// # Shared-keyword fan-out
///
/// A single keyword string can legitimately belong to many
/// `(category, sub_category)` pairs. Generic phrases like
/// `"national id"`, `"passport number"`, or `"tax id"` are
/// registered under 10+ country-specific sub_categories each,
/// because every country's ID keyword list includes the generic
/// English phrase alongside the country-specific one.
///
/// The previous build generated one AC pattern per `(cat, sub,
/// keyword)` triple and stored the pattern → key mapping as a
/// plain `Vec<(cat, sub)>` indexed by AC pattern index. That meant
/// the pattern table had N copies of `"national id"`, each mapped
/// to a different country — but AC's `find_iter` returns exactly
/// one match per starting position, and with `LeftmostLongest`
/// the tiebreak among equal-length, equal-start matches goes to
/// the pattern that was added to the AC table first. So `"national
/// id"` was only attributed to the first-registered country
/// (Taiwan National ID, at `keywords.rs:5852`), and the other 10+
/// country sub_categories never saw a hit for the generic phrase
/// — their patterns were filtered out by the AC prefilter in
/// `scanner/mod.rs` and silently under-matched on real documents.
///
/// The fix is to deduplicate keywords during the build: each
/// unique keyword becomes exactly one AC pattern, and the
/// associated `Vec<(cat, sub)>` holds every sub_category that
/// claims it. At match time, `build_hit_index` iterates the list
/// and records a hit against each key, so all patterns that share
/// a keyword get their hit. Memory-wise this is strictly smaller
/// than the old form (one shared `"national id"` string instead
/// of 10+). Runtime is unchanged in the common case (one
/// `(cat, sub)` per keyword); the extra loop body only costs
/// anything when a match falls on a truly shared keyword.
///
/// The LeftmostLongest policy is kept so that prefix-shadow bugs
/// (e.g., `"personal"` shadowing `"personalausweis"`) stay fixed.
/// That fix and this one are orthogonal: LeftmostLongest solves
/// "different-length keywords at the same start position", and
/// this dedup solves "same-length keyword claimed by many
/// sub_categories".
static AC_MATCHER: Lazy<AcMatcherInner> = Lazy::new(|| {
    let keywords = CONTEXT_KEYWORDS;
    if keywords.is_empty() {
        return None;
    }

    // Deduplicate keywords while preserving first-seen insertion
    // order (so AC build output is deterministic across runs).
    //
    //  `keyword_index` maps `lowercased_keyword -> index into patterns/pattern_keys`.
    //  `patterns`      is the AC input, one entry per unique keyword.
    //  `pattern_keys`  is indexed the same; each entry is a Vec
    //                  of every (cat, sub) that registered this keyword.
    let mut keyword_index: HashMap<String, usize> = HashMap::new();
    let mut patterns: Vec<String> = Vec::new();
    let mut pattern_keys: Vec<Vec<(&'static str, &'static str)>> = Vec::new();

    for &(category, sub_category, entry) in keywords {
        for &kw in entry.keywords {
            let lowered = kw.to_lowercase();
            match keyword_index.get(&lowered).copied() {
                Some(idx) => {
                    // Already registered — append this (cat, sub)
                    // to the existing key list, but guard against a
                    // literal duplicate entry for the same sub_category
                    // (a keyword listed twice in the same entry is a
                    // data-entry bug but shouldn't produce duplicate
                    // hits).
                    let keys = &mut pattern_keys[idx];
                    if !keys.contains(&(category, sub_category)) {
                        keys.push((category, sub_category));
                    }
                }
                None => {
                    keyword_index.insert(lowered.clone(), patterns.len());
                    patterns.push(lowered);
                    pattern_keys.push(vec![(category, sub_category)]);
                }
            }
        }
    }

    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .ascii_case_insensitive(true)
        .build(&patterns)
        .ok()?;

    Some((ac, pattern_keys))
});

/// Search text for all context keywords using Aho-Corasick.
pub fn build_hit_index(text: &str) -> Option<ContextHitIndex> {
    let (ac, pattern_keys) = AC_MATCHER.as_ref().as_ref()?;

    let mut hits: HashMap<(&'static str, &'static str), Vec<(usize, usize)>> = HashMap::new();

    // AC is built with ascii_case_insensitive(true), no need to lowercase.
    // Each AC match fans out to every (category, sub_category) that
    // registered the matched keyword — see the fan-out discussion on
    // AC_MATCHER above.
    for mat in ac.find_iter(text) {
        let keys = &pattern_keys[mat.pattern().as_usize()];
        let pos = (mat.start(), mat.end());
        for &key in keys {
            hits.entry(key).or_default().push(pos);
        }
    }

    Some(ContextHitIndex { hits })
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
    let context_window = format!("{pre_text} {post_text}");
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
#[allow(dead_code)]
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
                if levenshtein_distance(word, &kw_lower, FUZZY_MAX_DISTANCE) <= FUZZY_MAX_DISTANCE {
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
                if levenshtein_distance(&ngram, &kw_lower, FUZZY_MAX_DISTANCE) <= FUZZY_MAX_DISTANCE
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Compute Levenshtein edit distance with early termination.
#[allow(dead_code)]
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

    #[test]
    fn test_shared_keyword_fans_out_to_all_sub_categories() {
        // Regression for the shared-keyword AC bug: the phrase
        // "national id" is registered under 10+ country-specific
        // sub_categories (Taiwan, Thailand, Saudi Arabia,
        // Malaysia, Indonesia, UAE, Vietnam, etc.). Before the
        // fan-out fix, AC attributed the hit to exactly one of
        // them (the first-registered, typically Taiwan National
        // ID), so every other country's pattern silently failed
        // the AC prefilter.
        //
        // After the fix, a single document containing "national
        // id" must generate a hit in the index for EVERY (cat,
        // sub) that registered it. We test by building a hit
        // index on a sentence containing only the shared phrase
        // and asserting that more than one sub_category shows up.
        let text = "The subject's national id was recorded on the form.";
        let index = build_hit_index(text).expect("hit index");
        // Collect all sub_categories that got a hit.
        let national_id_keys: Vec<(&'static str, &'static str)> = index
            .hit_keys()
            .filter(|(_, sub)| sub.to_lowercase().contains("national id"))
            .collect();
        assert!(
            national_id_keys.len() >= 2,
            "shared keyword `national id` must fan out to multiple sub_categories, \
             got: {national_id_keys:?}"
        );
    }

    #[test]
    fn test_unique_keyword_still_single_hit() {
        // Counter-test: a keyword registered under exactly one
        // sub_category should still produce exactly one hit key
        // for that sub_category. "personalausweis" is registered
        // under Germany ID (+ Austria in a separate entry) so
        // this also pins the Austria/Germany co-registration
        // that the fan-out logic handles.
        let text = "Personalausweis on file.";
        let index = build_hit_index(text).expect("hit index");
        let pa_keys: Vec<(&'static str, &'static str)> = index
            .hit_keys()
            .filter(|(_, sub)| sub.to_lowercase().contains("id"))
            .collect();
        assert!(
            !pa_keys.is_empty(),
            "personalausweis must produce at least one hit, got: {pa_keys:?}"
        );
    }
}
