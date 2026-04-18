# Context Matching

> **Entry point:** `crates/siphon-core/src/context/mod.rs`
>
> The Aho-Corasick keyword engine that determines which patterns' context
> keywords appear in a document, where they appear, and whether a given
> match is near one.

## How context matching works

The scanner uses context keywords to answer two questions:

1. **Prefilter (stage E):** "Is this pattern's keyword anywhere in the
   document?" If no, skip the pattern's regex entirely. This is the AC
   prefilter — it drops ~80% of patterns on keyword-free text.

2. **Per-match gate (stage F.3):** "Is a keyword for this pattern
   within N characters of *this specific match*?" If the pattern has
   `context_required = true` and no keyword is in range, the match is
   dropped.

Both questions are answered by a single data structure: the
**`ContextHitIndex`**, built once per scan.

## The hit index

**Build:** `build_hit_index` (line ~190) runs an Aho-Corasick
multi-pattern search over the normalized text using the global
`AC_MATCHER` singleton. Each match is recorded as
`(category, sub_category) → Vec<(start, end)>`.

**Query:** `has_hit_in_range(cat, sub, range_start, range_end)` checks
whether any keyword hit for that `(cat, sub)` falls within the given
byte range.

**Iteration:** `hit_keys()` returns every `(cat, sub)` that had at
least one keyword hit anywhere in the document. The scanner uses this
to build the `active_gated` set (the set of context-gated patterns
whose keywords are present).

## The AC matcher

**Build:** `AC_MATCHER` is a `Lazy<_>` singleton (line ~142) built
once at startup from all keywords in `CONTEXT_KEYWORDS` (defined in
`crates/siphon-core/src/context/keywords.rs`, ~8000 lines).

### Keyword deduplication and fan-out

A single keyword string (e.g., `"national id"`) can be registered
under many different `(category, sub_category)` pairs — Taiwan
National ID, Saudi Arabia National ID, UAE Emirates ID, etc. The AC
matcher **deduplicates** identical keyword strings during build:

```
keyword_index: HashMap<String, usize>   // lowercased keyword → pattern index
patterns: Vec<String>                    // unique keywords for AC
pattern_keys: Vec<Vec<(cat, sub)>>       // per-keyword, all owning sub_categories
```

At match time, a single AC hit on `"national id"` **fans out** to
every owning `(cat, sub)` in the corresponding `pattern_keys` entry.
This ensures all 11 countries that register `"national id"` see the
hit.

**Before this fix** (merged in `quality/shared-keyword-ac-fix`), each
registration was a separate AC pattern. The AC matcher returns only one
match per position among equal-length alternatives, so only the first-
registered country got the hit and every other country silently lost
recall on the generic phrase. The fan-out fix closes that entire class.

### MatchKind: LeftmostLongest

The AC matcher uses `MatchKind::LeftmostLongest` (not `LeftmostFirst`).

**Why it matters:** the keyword `"personal"` (registered under
`"Eyes Only"` classification) is a strict prefix of `"personalausweis"`
(registered under `"Germany ID"`). With `LeftmostFirst`, the shorter
keyword wins at the same start position because it was added to the
pattern table first. With `LeftmostLongest`, the longer keyword wins —
which is the correct behavior, because a document containing
"Personalausweis" should match Germany ID, not Eyes Only.

**Before this fix** (merged in the checksum-validation-batch), Germany
ID was silently undetectable whenever its primary keyword
"personalausweis" appeared in the document.

## The `check_context` function

**File:** `crates/siphon-core/src/context/mod.rs :: check_context` (line ~193)

Called per-match during stage F.2. Given a match span and its
`(category, sub_category)`, determines whether a keyword is "close
enough":

1. **Fast path (AC hit index):** Looks up the hit index for a
   keyword position within `±distance` bytes of the match span.
   Authoritative — if the index has no entry, return `false`.

2. **Fallback:** If no AC index is available (shouldn't happen in
   normal flow), falls back to a linear scan of the keyword list
   with case-insensitive substring matching.

The `distance` is configured per-category in `CONTEXT_KEYWORDS` (most
categories use 50 characters; some use 80).

## The keywords file

**File:** `crates/siphon-core/src/context/keywords.rs`

~8000 lines of keyword definitions, organized as:

```rust
pub static CONTEXT_KEYWORDS: &[(&str, &str, ContextEntry)] = &[
    ("Category Name", "Sub Category", ContextEntry {
        keywords: &["keyword1", "keyword2", ...],
        distance: 50,
    }),
    // ...
];
```

Each `(category, sub_category)` pair maps to a set of keywords and
a distance. Keywords are case-insensitive (the AC matcher is built
with `ascii_case_insensitive(true)`).

Keywords should be chosen to be:
- **Specific enough** not to fire on unrelated text
- **Not too short** — a 2-char keyword like `"cf"` (Italy Codice
  Fiscale) matches substrings of many unrelated words
- **Unique enough** not to shadow longer keywords via prefix overlap
  (the LeftmostLongest fix handles this, but shorter keywords at the
  same position still shadow longer ones if they're in a different
  alternative)
