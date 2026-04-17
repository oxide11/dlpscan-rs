# Scan Pipeline — Stage by Stage

> **Entry point:** `src/scanner/mod.rs :: scan_text_with_config` (line ~283)
>
> Every public API surface — `scan_text`, `InputGuard::scan`, the CLI,
> the HTTP server — funnels into this single function. Understanding it
> is understanding the scanner.

## Pre-scanner: file extraction

**File:** `src/extractors.rs`

Before the scanner sees text, file-based inputs go through a
type-specific extractor. The dispatcher at `get_extractor` (line ~123)
maps file extensions to extractor functions:

| Extension group | Extractor | Feature gate |
|---|---|---|
| `.pdf` | `extract_pdf` | `pdf` |
| `.docx` / `.xlsx` / `.ods` / `.odt` / `.pptx` | `extract_office` | `office` |
| `.eml` / `.msg` | `extract_eml` / `extract_msg` | always / `msg` |
| `.mbox` | `extract_mbox` | always |
| `.zip` / `.rar` / `.7z` / `.cab` | archive extractors | `archives` |
| `.parquet` / `.db` / `.sqlite` | `extract_parquet` / `extract_sqlite` | `data-formats` |
| `.png` / `.jpg` / `.gif` / `.bmp` / `.tiff` / `.webp` | `extract_barcode` (QR/barcode decode) | `barcode` |
| `.vcf` / `.ics` / `.warc` / `.mhtml` / `.ldif` | format-specific | always |
| unknown | magic-byte detection fallback | always |

Each extractor returns an `ExtractionResult { text, source, warnings,
metadata }`. The `text` field is the UTF-8 blob that enters the
scanner. Everything after this point is format-agnostic.

**Key implication:** a credit card number inside a QR code on a PNG
image goes through the full Luhn + BIN check path like any other PAN.
The barcode extractor decodes the image, produces text, and the
scanner handles the rest.

Text-only inputs (API calls, stdin) skip extraction entirely and go
straight to stage B.

---

## Stage B: input validation

**File:** `src/validation.rs :: validate_text_input` (line ~9)

Two guards:
- Empty input → `DlpError::EmptyInput`
- Size > `MAX_INPUT_SIZE` (10 MB) → `DlpError::InputTooLarge`

The size ceiling is the only defense against an attacker feeding a
multi-GB payload and forcing the normalizer to walk every byte 10
times. There is no streaming mode — the entire input must fit in
memory as a single `&str`.

---

## Stage C: normalization

**File:** `src/normalize/mod.rs :: normalize_text` (line ~1009)

This is the largest single stage. It transforms the text to defeat
evasion AND builds an `offset_map: Vec<usize>` that maps each byte in
the normalized output back to its origin byte in the original input.

See **[normalization.md](normalization.md)** for the full stage-by-stage
breakdown. The stages run in this order:

| # | Stage | Purpose |
|---|---|---|
| 1 | `decode_percent_encoding` | URL `%XX` (two passes for double-encoding) |
| 2 | `decode_html_entities` | `&#65;` HTML decimal entities |
| 3 | `strip_comments` | Empty `/**/` and `<!---->` used to break up keywords |
| 4 | `decode_hex_spaced` | `48 65 6c 6c 6f` → `Hello` |
| 4b | `decode_hex_escapes` | `\x48\x65` → `He` |
| 4c | `decode_encoded_tokens` | Token-level base64/base64url/base32/hex decode (nested, max 3 iterations). Skips JWT dot-delimited segments. |
| 5 | `collapse_padding` | Strip whitespace between non-alpha chars |
| 6 | `normalize_delimiters` | `123--45` → `123-45` |
| 7 | `strip_zero_width` | Remove ZWSP, ZWJ, etc. |
| 8 | `normalize_exotic_whitespace` | Unicode spaces → ASCII space |
| 9 | `NFKC` | Unicode canonical/compatibility normalization |
| 10 | `homoglyph_map` | Cyrillic `а` → Latin `a`, fullwidth digits → ASCII |

Stages 7-10 only run if the text contains non-ASCII bytes (fast
`is_ascii_only` check gates them). Clean ASCII text skips most stages.

---

## Stage D: context hit-index build

**File:** `src/context/mod.rs :: build_hit_index` (line ~190)

Runs an Aho-Corasick sweep over the normalized text to find every
registered context keyword and record its byte position plus the
`(category, sub_category)` it belongs to. The result is a
`ContextHitIndex` — a `HashMap<(&str, &str), Vec<(start, end)>>`.

See **[context-matching.md](context-matching.md)** for the AC matcher
build, keyword deduplication, and the two bugs that were fixed
(prefix-shadow + shared-keyword fan-out).

---

## Stage E: pattern prefilter

**File:** `src/scanner/mod.rs` (lines ~320-343)

The scanner knows which keywords fired and where. It uses that to
decide which of the ~560 compiled patterns to actually run:

1. **Category filter** (optional, from `config.categories`) — restrict
   to specific categories.
2. **Baseline-only mode** (optional) — restrict to always-run patterns
   for high-throughput pipelines.
3. **AC prefilter** — for every pattern that is NOT always-run, check
   whether its `(category, sub_category)` appears in the hit index. If
   not, **drop the pattern entirely** — its regex never runs.

A pattern is "always-run" (`is_always_run`, line ~267) if either:
- `pattern_specificity >= 0.85` (structurally tight patterns like JWTs,
  Bitcoin addresses, AWS keys)
- It's in the `CRITICAL_ALWAYS_RUN` curated set (national IDs, crypto
  addresses, core PCI/PII)

The prefilter is the biggest throughput win in the whole pipeline. On a
clean English-prose document with zero sensitive keywords, ~80% of the
560 patterns are dropped before their regex ever compiles a match
attempt.

---

## Stage F: parallel regex match

**File:** `src/scanner/mod.rs` (lines ~346-460)

For each active pattern, in parallel via `rayon::par_iter`:

1. **Regex `find_iter`** over the normalized text. Capped at
   `MAX_MATCHES_PER_PATTERN = 10_000` per pattern.

2. **F.1 — Validate** via `validation::validate_match` (line ~362).
   This is where Luhn, mod-97, Verhoeff, ISO 3779, Base58Check, and
   every checksum from the validator batches runs. **Failed validation
   → `continue` (skip the match entirely).** The validator runs BEFORE
   the context check because it's cheaper — a Luhn check is tens of
   nanoseconds; an AC lookup is hundreds.

3. **F.2 — Context check** via `context::check_context` (line ~368).
   Looks up the hit index to see if a keyword for this sub_category
   appears within the configured distance (default 50 chars) of the
   match.

4. **F.3 — Context gate** (line ~378). If `is_context_required` is
   true for this sub_category AND no context was found, drop the match.
   Also drops if `config.require_context` is globally set.

5. **F.4 — Confidence** via `scoring::compute_confidence` (line ~386).
   - `has_context` → `base_specificity + 0.20`
   - `!has_context && ctx_required` → `base × 0.3` (rarely reached)
   - otherwise → `base_specificity`

6. **F.5 — Min-confidence filter** (line ~387). Drop if below
   `config.min_confidence`.

7. **F.6 — Offset remap** (lines ~405-418). Translate the match's
   normalized byte range back to the original input's byte range using
   `offset_map`. UTF-8 char-boundary safety check prevents producing
   an invalid slice.

8. **F.7 — BIN enrichment** (lines ~443-453). Only for `Credit Card
   Numbers` category, only with the `bin-data` feature. Looks up the
   first 6-8 digits in a 374k-entry BIN table, populates metadata
   fields, and bumps confidence by +0.05.

---

## Stage G: flatten + max-matches cap

**File:** `src/scanner/mod.rs` (lines ~471-475)

The `Vec<Vec<Match>>` from rayon gets flattened into a single
`Vec<Match>` and truncated to `config.max_matches` (default
`MAX_MATCHES = 50_000`).

---

## Stage H: alt-decodings second pass

**File:** `src/scanner/mod.rs` (lines ~494-560)

**Only runs if:**
- `matches.len() < 3` (primary pass found almost nothing)
- `text.len() < 4096` (small document)
- Elapsed time < `MAX_SCAN_SECONDS / 2`

Generates alternative decodings of the normalized text
(`src/normalize/mod.rs :: generate_alternative_decodings`):
- ROT13
- leet-speak (`h3ll0` → `hello`)
- morse code

**Note:** base64/base32 decode used to live here but has been moved
to the normalization pipeline (stage 4c) where it runs on ALL
documents with full context checking and supports nested decode.

For each alt, runs **only always-run patterns** (not the full 560),
and **skips context-required patterns entirely** (the alt text has
no context hit index, so keyword proximity can't be verified).

Each alt match:
- Goes through `validate_match` (checksums still apply)
- Gets confidence × 0.9 (alt-decoded matches are less trustworthy)
- Span is set to `(0, text.len())` — offset mapping through a decode
  step is not reliable

---

## Post-regex stages

After stage H, three optional stages run in sequence. They're additive
— all contribute to the final match list, they're not alternatives.

### Stage I: deduplication

**File:** `src/scoring.rs :: deduplicate_overlapping`

When two patterns match overlapping byte ranges (common: Visa + IMEISV
on the same 16 digits), keep one. Tiebreaker chain:

1. Higher confidence wins
2. Same confidence → higher base specificity wins
3. Same specificity → longer match wins

Controlled by `config.deduplicate` (default `true`).

### Stage J: entropy secret scan

**File:** `src/scanner/mod.rs :: scan_high_entropy_tokens` (line ~679)

Controlled by `config.entropy_scan` (`EntropyMode`):

| Mode | Behavior |
|---|---|
| `Off` (default) | Skip |
| `Gated` | Only near secret-related keywords |
| `Assignment` | Only in `KEY=VALUE` patterns |
| `All` | Flag every high-entropy token |

Finds random-looking strings (high Shannon entropy) that don't match
any regex pattern. Dominated matches (span already covered by a regex
match) are dropped.

### Stage K: EDM (Exact Data Match)

**File:** `src/scanner/mod.rs` (lines ~566-589)

Scans for registered known-sensitive values (literal strings). EDM
matches are **never dominated** by regex matches — if you registered
`123-45-6789` as a specific customer SSN, the match fires even if
`USA SSN` also caught it. The distinction matters: EDM is confirmed
known data, not a pattern guess.

### Stage L: LSH (Document Similarity)

**File:** `src/scanner/mod.rs` (lines ~591-610)

MinHash/LSH query against a registered document vault. Detects
whole-document similarity: "is this document similar to an internal
strategy memo we classified as confidential?"

---

## What comes out

The return value is `Vec<Match>` where each `Match` carries:

| Field | Type | Notes |
|---|---|---|
| `text` | `String` | The matched text from the ORIGINAL input (not normalized) |
| `category` | `String` | Top-level pattern category |
| `sub_category` | `String` | Specific pattern name |
| `has_context` | `bool` | Whether a keyword was found nearby |
| `confidence` | `f64` | 0.0 to 1.0, computed from specificity + context |
| `span` | `(usize, usize)` | Byte offsets in the ORIGINAL input |
| `context_required` | `bool` | Whether this pattern requires context |
| `metadata` | `HashMap<String,String>` | Optional enrichment (BIN brand, etc.) |

The `span` uses **original-input byte offsets** thanks to stage F.6's
offset remap. Downstream tools (redaction, tokenization, highlighting)
can slice the original input safely at these boundaries.
