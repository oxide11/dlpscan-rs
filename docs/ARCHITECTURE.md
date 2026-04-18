<p align="center">
  <img src="assets/logo.png" alt="Polygon Siphon" width="200">
</p>

# Architecture

Polygon Siphon is designed in two layers:

1. **A shared scanner engine** (`siphon-core`) that does all detection —
   pattern matching, validators, context keywords, scoring. No file
   I/O. No network. Pure `&str → Vec<Match>`.

2. **A family of specialized pods** that each handle one class of
   ingestion or detection. Every pod depends on `siphon-core` for the
   scanning logic, so detection is identical everywhere. The pods
   differ only in how data gets in and what the output is connected
   to.

This doc is the entry point. Each deep-dive doc below covers one
concern in detail with file/line references back to the source.

## The two-layer model

```
                     ┌──────────────────────┐
                     │     Siphon-Core      │
                     │  scanner + Detector  │
                     │    trait (library)   │
                     └──────────┬───────────┘
    ┌─────────────┬─────────────┼─────────────┬──────────────┐
    │             │             │             │              │
 Ingestion pods                      Detector pods
 (how data gets in)                  (how detection happens)
    │             │             │             │              │
┌───▼──┐  ┌──────▼────┐  ┌─────▼─────┐  ┌───▼──────┐  ┌────▼────┐
│ FS   │  │ API       │  │ DS        │  │ GW       │  │ ML      │
│      │  │           │  │           │  │          │  │ Vision  │
│Files │  │HTTP/gRPC  │  │Multi-proto│  │Inline    │  │Classify │
│+ bkt │  │POST /scan │  │consumer   │  │proxy     │  │(gRPC)   │
└──────┘  └───────────┘  └───────────┘  └──────────┘  └─────────┘
                         │
                         ▼
                   ┌──────────┐
                   │Siphon-C2 │ ← admin web UI, management plane
                   │          │   orchestration, policy, dashboards
                   └──────────┘
```

See **[architecture/microservices.md](architecture/microservices.md)**
for the full pod inventory, deployment topology, and migration path.

## The detection core (`siphon-core`)

`siphon-core` is a Rust library. Its public entry point is
`scan_text_with_config(&str, &ScanConfig) → Vec<Match>`. Every pod
(ingestion or detector) ultimately calls this or a derivative.

The scanner runs **560+ regex patterns** across **126 categories**,
with **72 checksum validators** and **5,000+ context keywords** across
6 languages. A single scan passes through the pipeline below.

```
input text
        │
        ▼
[B] input validation              validate_text_input
        │  reject empty, reject > 10 MB
        ▼
[C] NORMALIZATION                 normalize_text
        │  10 stages + token-level encoded-data decode (base64,
        │  base64url, base32, hex — nested up to 3 iterations)
        │  builds offset_map: normalized byte → original byte
        ▼
[D] CONTEXT HIT-INDEX BUILD       build_hit_index
        │  Aho-Corasick sweep, deduplicated keywords, fan-out at match
        ▼
[E] PATTERN PREFILTER             active_patterns
        │  category filter + AC prefilter + baseline_only
        │  always-run patterns bypass the AC prefilter
        ▼
[F] PARALLEL REGEX MATCH          rayon par_iter over active_patterns
        │  per pattern, per match:
        │    ├─ VALIDATE         validate_match
        │    ├─ CONTEXT CHECK    check_context
        │    ├─ CONTEXT GATE     drop if context_required && !has_context
        │    ├─ CONFIDENCE       compute_confidence
        │    ├─ MIN CONF FILTER
        │    ├─ OFFSET REMAP     normalized span → original span
        │    └─ BIN ENRICHMENT   credit cards only, with bin-data
        ▼
[G] FLATTEN + MAX-MATCHES CAP
        │
        ▼
[H] ALT-DECODINGS SECOND PASS  [opt]
        │  ROT13, leet-speak, morse
        │  only if matches.len() < 3 && text.len() < 4096
        ▼
[I] DEDUPLICATE OVERLAPPING       deduplicate_overlapping
        │  tiebreakers: confidence → specificity → length
        ▼
[J] ENTROPY SECRET SCAN  [opt]    scan_high_entropy_tokens
        │  finds high-entropy tokens not covered by regex matches
        ▼
[K] EDM — EXACT DATA MATCH  [opt]
        │  literal match against registered known-sensitive values
        ▼
[L] LSH — DOCUMENT SIMILARITY  [opt]
        │  MinHash query against a registered document vault
        ▼
output: Vec<Match>
```

The single most load-bearing invariant is the **offset map** built in
stage C and consumed in stage F. Every normalization stage preserves a
parallel `Vec<usize>` mapping each byte of the normalized output back
to its origin byte in the input. Without it, every match span we
report would be wrong relative to the user's original input.

## File-based ingestion (`siphon` / `siphon-fs`)

File processing is a separate concern. The `extractors` module
(shipped with the `siphon` crate, soon to move to `siphon-extractors`)
handles 20+ formats — PDF, DOCX, XLSX, archives, email, QR codes,
Parquet, SQLite — and produces the `&str` that `siphon-core` scans.

The pre-scanner stage for file inputs:

```
input file
    │
    ▼
[A] file-type extraction          extractors::extract_text
    │  format-specific: pdf-extract, calamine, rxing, unrar, ...
    │  produces: ExtractionResult { text, source, warnings, metadata }
    │
    ▼
  &str input → siphon-core pipeline above
```

Text-only inputs (API calls, stdin, stream messages) skip stage A
entirely. This is what makes `siphon-api`, `siphon-ds`, and `siphon-gw`
possible without the heavy extractor dependencies.

## Workspace layout

```
polygon-siphon/
├── Cargo.toml                    # workspace root
├── crates/
│   ├── siphon-core/              # scanner engine (no file I/O)
│   │   ├── models, patterns
│   │   ├── normalize, context
│   │   ├── validation, scoring
│   │   ├── edm, lsh, classification
│   │   ├── errors, bin_lookup
│   │   └── scanner ← primary entry point
│   │
│   └── siphon-api/               # sync HTTP/gRPC scan service
│       └── POST /scan endpoint
│
└── src/                          # siphon crate (CLI + file tooling)
    ├── extractors                ← file format handlers
    ├── pipeline                  ← directory/batch orchestration
    ├── guard                     ← InputGuard scan/redact/tokenize
    ├── main.rs                   ← siphon CLI
    └── ...                       ← audit, compliance, policy, api,
                                    cache, siem, webhooks, tui, etc.
```

**Future crates** (see
[architecture/microservices.md](architecture/microservices.md)):
`siphon-extractors`, `siphon-fs`, `siphon-ds`, `siphon-gw`,
`siphon-ml`, `siphon-vision`, `siphon-classify`, `siphon-c2`.

## Where to read next

| Doc | What it covers |
|---|---|
| **[architecture/microservices.md](architecture/microservices.md)** | The pod architecture: Siphon-Core + FS/API/DS/GW, detector pods (ML/Vision/Classify), Siphon-C2 management plane, unified finding wire format, K8s deployment, migration path. |
| **[architecture/pipeline.md](architecture/pipeline.md)** | Stage-by-stage walkthrough of `scan_text_with_config`. Read this first if you want to understand what runs in what order and why. |
| **[architecture/normalization.md](architecture/normalization.md)** | The 10 normalization stages, what each one defends against, the offset-map invariant, and the known `collapse_padding` over-reach gotcha. |
| **[architecture/context-matching.md](architecture/context-matching.md)** | The Aho-Corasick prefilter, the keyword hit index, why `MatchKind::LeftmostLongest` matters, and the shared-keyword fan-out fix. |
| **[architecture/validation.md](architecture/validation.md)** | Pattern validation: how `validate_match` is wired, the always-run vs context-gated split, the validator inventory, and the labeled-corpus regression harness. |
| **[architecture/extending.md](architecture/extending.md)** | "I want to add X" cookbook: new pattern, new validator, new corpus test, new keyword set, new file extractor. |

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
the patterns are skipped entirely. The always-run set is the explicit
exception list. See
[validation.md](architecture/validation.md#always-run-vs-context-gated).

**Detector pluggability.** `siphon-core` exposes a `Detector` trait.
Regex+validators are one `Detector` implementation; future ML, OCR,
and classifier pods will be remote `Detector` implementations called
via gRPC. Ingestion pods hold a list of detectors — some local, some
remote — and call them in parallel per-request. See
[microservices.md](architecture/microservices.md#detector-plugin-model).

**Specificity drift discipline.** `pattern_specificity()` in
`models.rs` and `PatternDef.specificity` in `patterns/mod.rs` must
stay in sync. The `specificity_drift_zero` regression test
(`tests/audit_spec.rs`) fails any commit that updates one without the
other.

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
