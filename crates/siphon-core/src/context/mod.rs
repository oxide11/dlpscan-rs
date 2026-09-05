//! Context keyword matching engine.
//!
//! Uses Aho-Corasick for fast multi-keyword matching, with fuzzy fallback
//! via Levenshtein distance for typo tolerance.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;

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
/// Keyed by pattern ID (u32) interned from the CONTEXT_KEYWORDS table.
pub struct ContextHitIndex {
    /// Map from pattern ID → sorted list of start positions.
    /// Pattern ID is the index into CONTEXT_KEYWORDS, which is stable and
    /// allows zero-allocation lookups via direct indexing.
    hits: Vec<Vec<u32>>,
    /// Byte length of the text this was built from, so the index can answer
    /// "outside this range" without the caller passing a length it might get
    /// wrong.
    text_len: u32,
}

/// Is any position outside `[excl.0, excl.1)`?
///
/// `positions` is sorted, so this is two comparisons rather than a scan: if
/// anything precedes the range the first element does, and if anything
/// follows it the last does.
fn any_position_outside(positions: &[u32], excl: (u32, u32)) -> bool {
    positions.first().is_some_and(|&p| p < excl.0) || positions.last().is_some_and(|&p| p >= excl.1)
}

impl ContextHitIndex {
    /// Iterate all (category, sub_category) pairs that have at least one
    /// hit. Used by the scanner to build the active_gated set for the
    /// AC prefilter — only patterns whose keywords appeared at least once
    /// in the document need to run.
    pub fn hit_keys(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.hits
            .iter()
            .enumerate()
            .filter(|(_, positions)| !positions.is_empty())
            .filter_map(|(pid, _)| CONTEXT_KEYWORDS.get(pid).map(|&(cat, sub, _)| (cat, sub)))
    }

    /// Byte length of the indexed text.
    pub fn text_len(&self) -> usize {
        self.text_len as usize
    }

    /// Like [`Self::hit_keys`], but ignoring hits inside `excl`.
    ///
    /// Used when one index serves several scanned units — the excluded range
    /// is the unit being scanned, whose own keywords must not reach it as
    /// envelope evidence.
    pub fn hit_keys_outside(
        &self,
        excl: (u32, u32),
    ) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.hits
            .iter()
            .enumerate()
            .filter(move |(_, positions)| any_position_outside(positions, excl))
            .filter_map(|(pid, _)| CONTEXT_KEYWORDS.get(pid).map(|&(cat, sub, _)| (cat, sub)))
    }

    /// Is there a hit for (category, sub_category) anywhere outside `excl`?
    pub fn has_hit_outside(&self, category: &str, sub_category: &str, excl: (u32, u32)) -> bool {
        let Some(pattern_id) = lookup_pattern_id(category, sub_category) else {
            return false;
        };
        let Some(positions) = self.hits.get(pattern_id) else {
            return false;
        };
        any_position_outside(positions, excl)
    }

    /// Check if any keyword for (category, sub_category) was found in the given byte range.
    pub fn has_hit_in_range(
        &self,
        category: &str,
        sub_category: &str,
        range_start: usize,
        range_end: usize,
    ) -> bool {
        // Look up the pattern ID for this (category, sub_category)
        let Some(pattern_id) = lookup_pattern_id(category, sub_category) else {
            return false;
        };
        let Some(positions) = self.hits.get(pattern_id) else {
            return false;
        };
        // Binary search for the first position >= range_start
        let start_u32 = range_start.min(u32::MAX as usize) as u32;
        let end_u32 = range_end.min(u32::MAX as usize) as u32;
        match positions.binary_search(&start_u32) {
            Ok(_) => true,
            Err(idx) => positions.get(idx).is_some_and(|&p| p < end_u32),
        }
    }
}

/// Look up the index of a (category, sub_category) pair in CONTEXT_KEYWORDS.
/// Uses a lazy-initialized HashMap for O(1) lookup.
fn lookup_pattern_id(category: &str, sub_category: &str) -> Option<usize> {
    static LOOKUP: Lazy<HashMap<(&'static str, &'static str), usize>> = Lazy::new(|| {
        CONTEXT_KEYWORDS
            .iter()
            .enumerate()
            .map(|(i, &(cat, sub, _))| ((cat, sub), i))
            .collect()
    });
    LOOKUP.get(&(category, sub_category)).copied().or_else(|| {
        // Fallback: linear scan with owned string comparison (rare path)
        CONTEXT_KEYWORDS
            .iter()
            .position(|&(cat, sub, _)| cat == category && sub == sub_category)
    })
}

/// Deduplicated AC matcher: stores unique keywords once, maps each to the
/// set of pattern IDs it belongs to.
type AcMatcherInner = Option<(AhoCorasick, Vec<Vec<u32>>)>;

/// Global Aho-Corasick matcher built from all context keywords.
/// Deduplicates identical keywords across patterns to shrink the automaton
/// and map each unique keyword to all pattern IDs it serves.
static AC_MATCHER: Lazy<AcMatcherInner> = Lazy::new(|| {
    let keywords = CONTEXT_KEYWORDS;
    if keywords.is_empty() {
        return None;
    }

    // Deduplicate keywords: map each lowercase keyword to the list of
    // pattern IDs (indices into CONTEXT_KEYWORDS) that use it.
    let mut kw_to_pids: HashMap<String, Vec<u32>> = HashMap::new();
    for (pattern_id, &(_cat, _sub, entry)) in keywords.iter().enumerate() {
        for &kw in entry.keywords {
            let kw_lower = kw.to_lowercase();
            kw_to_pids
                .entry(kw_lower)
                .or_default()
                .push(pattern_id as u32);
        }
    }

    let mut patterns: Vec<String> = Vec::with_capacity(kw_to_pids.len());
    let mut pattern_to_pids: Vec<Vec<u32>> = Vec::with_capacity(kw_to_pids.len());
    for (kw, pids) in kw_to_pids {
        patterns.push(kw);
        pattern_to_pids.push(pids);
    }

    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .ascii_case_insensitive(true)
        .build(&patterns)
        .ok()?;

    Some((ac, pattern_to_pids))
});

/// Search text for all context keywords using Aho-Corasick.
/// Returns a ContextHitIndex with per-pattern-ID sorted position lists.
pub fn build_hit_index(text: &str) -> Option<ContextHitIndex> {
    let (ac, pattern_to_pids) = AC_MATCHER.as_ref().as_ref()?;

    // Pre-allocate per-pattern-ID vectors (one per CONTEXT_KEYWORDS entry)
    let mut hits: Vec<Vec<u32>> = vec![Vec::new(); CONTEXT_KEYWORDS.len()];

    for mat in ac.find_iter(text) {
        // Aho-Corasick matches substrings, so without this an ordinary word
        // containing a short keyword activates the pattern it gates. 294
        // keywords are three characters or fewer and fourteen are two, which
        // made this constant rather than occasional: "Mexi(co)" fired Czech
        // ICO, "a(cc)ount" fired Colombia Cedula, and "Offi(ce)" fired Peru
        // Carnet Extranjeria. Those spurious activations are what produced
        // ~250 findings on a Canadian contact directory that contains no
        // foreign identifiers at all.
        if !is_word_bounded(text, mat.start(), mat.end()) {
            continue;
        }
        let ac_pattern_idx = mat.pattern().as_usize();
        let start = mat.start().min(u32::MAX as usize) as u32;
        // Each AC pattern maps to 1+ pattern IDs (because of keyword dedup)
        if let Some(pids) = pattern_to_pids.get(ac_pattern_idx) {
            for &pid in pids {
                hits[pid as usize].push(start);
            }
        }
    }

    // Sort each pattern's positions so binary_search works in has_hit_in_range
    for positions in &mut hits {
        if positions.len() > 1 {
            positions.sort_unstable();
        }
    }

    Some(ContextHitIndex {
        hits,
        text_len: text.len().min(u32::MAX as usize) as u32,
    })
}

/// Is the match at `start..end` a whole word rather than part of a longer one?
///
/// The boundary requirement applies per edge, and only where the keyword's own
/// edge character is alphanumeric. That matters because keywords are not all
/// bare words: `mc:` and `tlp:` end in punctuation and are routinely followed
/// by a digit, while `/mc` begins with one. Demanding a non-alphanumeric
/// neighbour on those edges would reject exactly the matches they exist to
/// catch.
///
/// Character classification is Unicode-aware rather than ASCII-only, so an
/// accented letter still counts as part of a word — `nif` inside `nifté` is a
/// substring hit, not a keyword.
fn is_word_bounded(text: &str, start: usize, end: usize) -> bool {
    let kw = &text[start..end];

    // Left edge is always required. This is the rule that does the work:
    // "Mexi(co)", "a(cc)ount" and "Offi(ce)" all fail here because the keyword
    // begins mid-word, which is what makes them coincidences rather than
    // mentions.
    if kw.chars().next().is_some_and(char::is_alphanumeric)
        && text[..start]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric)
    {
        return false;
    }

    // The right edge is only required for very short keywords. Longer ones are
    // deliberately allowed to match a word's prefix, because inflection and
    // compounding extend words at the end and the keyword lists are stems:
    // German writes "Steuerliche Identifikationsnummer", and demanding a right
    // boundary would stop `steuer` matching it. That is not hypothetical — it
    // cost two labelled findings when this check was first written without the
    // length exemption.
    //
    // Short keywords get no such latitude, since a two- or three-character
    // prefix lands inside ordinary words constantly: `ce` would match
    // "certain", `sin` would match "since", `run` would match "running".
    const PREFIX_MATCH_MIN_LEN: usize = 4;
    if kw.chars().count() < PREFIX_MATCH_MIN_LEN
        && kw.chars().last().is_some_and(char::is_alphanumeric)
        && text[end..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
    {
        return false;
    }
    true
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

/// Whether the envelope contains any context keyword for this pattern.
///
/// Deliberately position-blind, unlike [`check_context`]. The envelope is
/// separate material — a covering email body, a subject line, a filename —
/// so "distance from the match" has no meaning across that boundary. The
/// question is only whether the surrounding document discusses this kind of
/// data at all.
///
/// This is why an envelope hit is scored below a local one
/// ([`crate::scoring::ContextSource`]): it opens the gate on weaker evidence,
/// and treating it as equal would let a single mention of "SSN" in a body
/// promote every 9-digit number in every attachment.
pub fn envelope_has_context(
    envelope_index: Option<&ContextHitIndex>,
    envelope_len: usize,
    category: &str,
    sub_category: &str,
) -> bool {
    let Some(index) = envelope_index else {
        return false;
    };
    // Whole-envelope range: any hit anywhere counts.
    index.has_hit_in_range(category, sub_category, 0, envelope_len)
}

/// An envelope indexed **once** and shared by every unit scanned against it.
///
/// # Why this exists
///
/// Scanning a message part in isolation hides the rest of the message from
/// context gating, so each part is scanned with an envelope built from the
/// others. Correctness requires "the others": a part supplying its own
/// context would promote a local keyword to envelope evidence and score it as
/// though it came from elsewhere.
///
/// Implementing that by rebuilding the envelope per part made a message cost
/// `O(parts × message bytes)` — the string was rebuilt and re-indexed once per
/// part. Measured, a `multipart/mixed` of 400 inline text parts took 41
/// seconds, and the parser's own 1000-part ceiling projected past four
/// minutes. That is ordinary, legal MIME, and under a fail-closed mail policy
/// a message that occupies a worker for minutes is an availability problem,
/// not a latency one.
///
/// So the envelope is built and indexed once for the whole message, recording
/// each unit's byte range, and "exclude this unit" becomes a range filter at
/// query time — the same shape of question proximity gating already asks.
/// One `O(message)` pass, then `O(1)` per part.
pub struct EnvelopeIndex {
    text: String,
    index: Option<ContextHitIndex>,
    /// Byte range each keyed unit occupies in `text`.
    ranges: HashMap<String, (u32, u32)>,
}

impl EnvelopeIndex {
    /// The concatenated envelope text.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// A view of this envelope for scanning the unit `key`, with that unit's
    /// own bytes excluded.
    ///
    /// An unknown key excludes nothing, which is the honest answer: a unit
    /// that contributed no text has none to withhold.
    pub fn for_key(self: &Arc<Self>, key: &str) -> SharedEnvelope {
        SharedEnvelope {
            index: Arc::clone(self),
            exclude: self.ranges.get(key).copied().unwrap_or(EXCLUDE_NOTHING),
        }
    }

    /// A view excluding nothing — for scanning something that is not itself
    /// part of the envelope.
    pub fn whole(self: &Arc<Self>) -> SharedEnvelope {
        SharedEnvelope {
            index: Arc::clone(self),
            exclude: EXCLUDE_NOTHING,
        }
    }
}

/// An empty range past the end of any text: nothing falls inside it, so every
/// hit is "outside".
const EXCLUDE_NOTHING: (u32, u32) = (u32::MAX, u32::MAX);

/// One part's view of a shared [`EnvelopeIndex`]. Cheap to clone — an `Arc`
/// bump and a range.
#[derive(Clone)]
pub struct SharedEnvelope {
    index: Arc<EnvelopeIndex>,
    exclude: (u32, u32),
}

impl SharedEnvelope {
    pub(crate) fn hit_index(&self) -> Option<&ContextHitIndex> {
        self.index.index.as_ref()
    }

    pub(crate) fn exclude(&self) -> (u32, u32) {
        self.exclude
    }

    /// The envelope text visible to this view, for diagnostics. Not used on
    /// the scan path — the whole point is that the text is never re-walked
    /// per part.
    pub fn envelope_text(&self) -> &str {
        self.index.text()
    }
}

/// Accumulates envelope sections, then indexes the result once.
#[derive(Default)]
pub struct EnvelopeBuilder {
    text: String,
    ranges: HashMap<String, (u32, u32)>,
}

impl EnvelopeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Text belonging to no scanned unit — a subject line, say. Never excluded.
    pub fn push_shared(&mut self, text: &str) {
        self.push_section(None, text);
    }

    /// Text belonging to unit `key`, excluded when that unit is scanned.
    ///
    /// Calling this twice for one key extends its range to cover both, so a
    /// part contributing a filename and a body still excludes both — but only
    /// if the two are pushed consecutively, which is why callers append a
    /// unit's material in one place.
    pub fn push_keyed(&mut self, key: &str, text: &str) {
        self.push_section(Some(key), text);
    }

    fn push_section(&mut self, key: Option<&str>, text: &str) {
        if text.is_empty() {
            return;
        }
        let start = self.text.len().min(u32::MAX as usize) as u32;
        self.text.push_str(text);
        // Section separator. Not cosmetic: Aho-Corasick would otherwise match
        // a keyword straddling two sections, and that hit's position would be
        // attributed to whichever section it started in — letting a unit
        // contribute context to itself through its neighbour's range.
        // A newline cannot appear inside a keyword, so it cannot be straddled.
        self.text.push('\n');
        let end = self.text.len().min(u32::MAX as usize) as u32;

        if let Some(key) = key {
            self.ranges
                .entry(key.to_string())
                .and_modify(|r| {
                    r.0 = r.0.min(start);
                    r.1 = r.1.max(end);
                })
                .or_insert((start, end));
        }
    }

    /// Index the accumulated text once.
    pub fn build(self) -> Arc<EnvelopeIndex> {
        let index = build_hit_index(&self.text);
        Arc::new(EnvelopeIndex {
            text: self.text,
            index,
            ranges: self.ranges,
        })
    }
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
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    fn activates(text: &str, category: &str, sub: &str) -> bool {
        build_hit_index(text)
            .map(|ix| ix.hit_keys().any(|(c, s)| c == category && s == sub))
            .unwrap_or(false)
    }

    /// Short keywords landing inside ordinary words were the dominant source of
    /// spurious pattern activation: 294 keywords are three characters or fewer.
    #[test]
    fn short_keyword_inside_a_word_does_not_activate() {
        // `ico` gates Czech ICO, and lives inside "Mexico".
        assert!(!activates(
            "Mexico office records",
            "Europe - Czech Republic",
            "Czech ICO"
        ));
        // `cc` gates Colombia Cedula, and lives inside "account".
        assert!(!activates(
            "account totals for the year",
            "Latin America - Colombia",
            "Colombia Cedula"
        ));
    }

    /// Short keywords must not prefix-match either, or `ce` would fire on
    /// "certain" and `sin` on "since".
    #[test]
    fn short_keyword_as_a_word_prefix_does_not_activate() {
        assert!(!activates(
            "certain conditions apply",
            "Latin America - Peru",
            "Peru Carnet Extranjeria"
        ));
    }

    /// The genuine mention still activates, which is the whole point.
    #[test]
    fn standalone_short_keyword_activates() {
        assert!(activates(
            "Czech ICO: 12345678",
            "Europe - Czech Republic",
            "Czech ICO"
        ));
        assert!(activates(
            "Cedula CC for the applicant",
            "Latin America - Colombia",
            "Colombia Cedula"
        ));
    }

    /// Longer keywords keep prefix matching, because inflection and compounding
    /// extend words at the end and the keyword lists hold stems. German writes
    /// "Steuerliche Identifikationsnummer"; requiring a right boundary here
    /// cost two labelled corpus findings when this check was first written.
    #[test]
    fn long_keyword_may_match_a_word_prefix() {
        assert!(activates(
            "Steuerliche Identifikationsnummer 65929970489",
            "Europe - Germany",
            "Germany Tax ID"
        ));
    }

    /// Keywords whose own edge is punctuation get no boundary requirement on
    /// that edge — `mc:` is routinely followed immediately by a digit.
    #[test]
    fn punctuation_edged_keyword_still_matches_against_a_digit() {
        assert!(is_word_bounded("mc:5425233430109903", 0, 3));
    }
}
