<p align="center">
  <img src="assets/logo.png" alt="Polygon Siphon" width="200">
</p>

# Architecture

This is the entry point for understanding how Polygon Siphon is put together.
For a deeper look at any specific layer, follow the links below — each
deep-dive doc covers one concern in detail with file/line references back
to the source.

## What Polygon Siphon is

A library and CLI that takes a piece of text (or a file it can extract
text from) and returns a list of `Match` objects describing every
sensitive-data finding: credit cards, national IDs, secrets, addresses,
crypto wallets, and so on. Around **560 patterns** across **126
categories**, with a structural validator wired in for every pattern
that has a published checksum, and an enforced labeled-corpus
regression harness.

The library is single-binary, no runtime services required, and runs on
plain `&str` inputs. The CLI, server, and Python bindings are all thin
wrappers over the same `scanner::scan_text_with_config` entry point.

## The pipeline at a glance

Every scan follows the same path, top to bottom. Optional stages are
shown with `[opt]`.

```
input bytes / file path
        │
        ▼
[A] file-type extraction          src/extractors.rs
        │  produces:  utf-8 text
        ▼
[B] input validation              src/validation.rs :: validate_text_input
        │  reject empty, reject > 10 MB
        ▼
[C] NORMALIZATION                 src/normalize/mod.rs :: normalize_text
        │  10 stages + token-level encoded-data decode (base64,
        │  base64url, base32, hex — nested up to 3 iterations)
        │  builds offset_map: normalized byte → original byte
        ▼
[D] CONTEXT HIT-INDEX BUILD       src/context/mod.rs :: build_hit_index
        │  Aho-Corasick sweep, deduplicated keywords, fan-out at match
        ▼
[E] PATTERN PREFILTER             src/scanner/mod.rs :: active_patterns
        │  category filter + AC prefilter + baseline_only
        │  always-run patterns bypass the AC prefilter
        ▼
[F] PARALLEL REGEX MATCH          rayon par_iter over active_patterns
        │  per pattern, per match:
        │    ├─ VALIDATE         validation.rs :: validate_match
        │    ├─ CONTEXT CHECK    context.rs :: check_context
        │    ├─ CONTEXT GATE     drop if context_required && !has_context
        │    ├─ CONFIDENCE       scoring.rs :: compute_confidence
        │    ├─ MIN CONF FILTER
        │    ├─ OFFSET REMAP     normalized span → original span
        │    └─ BIN ENRICHMENT   credit cards only, with bin-data feature
        ▼
[G] FLATTEN + MAX-MATCHES CAP
        │
        ▼
[H] ALT-DECODINGS SECOND PASS  [opt]
        │  ROT13, leet-speak, morse (base64/base32 moved to stage C)
        │  only if matches.len() < 3 && text.len() < 4096
        │  runs always-run patterns only; skips context-required patterns
        ▼
[I] DEDUPLICATE OVERLAPPING       scoring.rs :: deduplicate_overlapping
        │  tiebreakers: confidence → specificity → length
        ▼
[J] ENTROPY SECRET SCAN  [opt]    scanner/mod.rs :: scan_high_entropy_tokens
        │  finds high-entropy tokens not covered by regex matches
        ▼
[K] EDM — EXACT DATA MATCH  [opt]
        │  literal match against registered known-sensitive values
        │  EDM matches are never dominated by regex matches
        ▼
[L] LSH — DOCUMENT SIMILARITY  [opt]
        │  MinHash query against a registered document vault
        ▼
output: Vec<Match>
```

The single most load-bearing invariant in this whole picture is the
**offset map** built in stage C and consumed in stage F.6. Every
normalization stage transforms the text and preserves a parallel
`Vec<usize>` mapping each byte of the normalized output back to its
origin byte in the input. Without that map, every match span we report
would be wrong relative to the user's original input — and downstream
redaction or tokenization would slice in the middle of a UTF-8
character.

## Where to read next

The pipeline diagram is intentionally short. Each of these docs picks
up one slice of it and goes deep:

| Doc | What it covers |
|---|---|
| **[architecture/pipeline.md](architecture/pipeline.md)** | Stage-by-stage walkthrough of `scan_text_with_config`. Read this first if you want to understand what runs in what order and why. |
| **[architecture/normalization.md](architecture/normalization.md)** | The 10 normalization stages, what each one defends against, the offset-map invariant, and the known `collapse_padding` over-reach gotcha. |
| **[architecture/context-matching.md](architecture/context-matching.md)** | The Aho-Corasick prefilter, the keyword hit index, why `MatchKind::LeftmostLongest` matters, and the shared-keyword fan-out fix. |
| **[architecture/validation.md](architecture/validation.md)** | Pattern validation: how `validate_match` is wired, the always-run vs context-gated split, the validator inventory, and the labeled-corpus regression harness. |
| **[architecture/extending.md](architecture/extending.md)** | "I want to add X" cookbook: new pattern, new validator, new corpus test, new keyword set, new file extractor. With file/line references. |

## Cross-cutting concerns

A handful of things show up repeatedly across the layers. Each is
covered in detail in the appropriate deep dive but worth flagging
upfront:

**Offset map discipline.** Every normalization stage takes
`(text, in_offsets)` and returns `(new_text, new_offsets)` where
`new_offsets[i]` is the input offset of the byte at `new_text[i]`. The
invariant is preserved through every stage. See
[normalization.md](architecture/normalization.md#the-offset-map-invariant).

**Validate-before-context order.** Inside the per-match loop in
`scan_text_with_config`, the validator runs *before* the context
check. This is deliberate: validation is usually cheaper than context
lookup, and rejecting early saves work. See
[pipeline.md](architecture/pipeline.md#stage-f-parallel-regex-match).

**Always-run vs context-gated.** Patterns split into two classes. The
AC prefilter (stage E) is the biggest throughput win in the pipeline:
for a clean English-prose document with zero PII keywords, ~80% of
the 560 patterns are skipped entirely. The always-run set is the
explicit exception list. See
[validation.md](architecture/validation.md#always-run-vs-context-gated).

**The alt-decodings pass is separate.** Stage H runs only when stage F
found almost nothing on a small input. It does its own validate →
push loop and **does not go through the primary pass's context
check**. Patterns added to `CRITICAL_ALWAYS_RUN` need to consider
both passes. See [pipeline.md](architecture/pipeline.md#stage-h-alt-decodings-second-pass).

**Layered post-stages.** Regex, entropy, EDM, and LSH all run in
sequence after dedup and all contribute to the final match list.
They're additive, not alternatives. See
[pipeline.md](architecture/pipeline.md#post-regex-stages).

## A note on accuracy

Every section in these docs is grounded in the source code with
specific file/line references where the behavior lives. The diagrams
and tables were cross-checked against the current `main` at the time
of writing. If you're ever unsure whether the doc matches reality, the
truth is in the source — the references should make that easy to
verify.

If you find a place where the doc disagrees with the code, the doc is
wrong; please open an issue or fix it in place.
