# Siphon Benchmark Results

Scanner throughput and latency, plus the historical record of how the Rust
implementation got here.

**Environment:** 4-core Intel Xeon @ 2.80 GHz, 16 GB RAM, Linux 6.18, Rust 1.98
**Build:** `cargo build --release` — `lto = true`, `opt-level = 3`, `codegen-units = 1`
**Version:** siphon 2.2.0 / siphon-core 2.3.0
**Patterns:** 583 total — 122 always-run, 461 context-gated
**Date:** September 2026

> **Read the numbers as relative, not absolute.** These were measured on a
> modest shared 4-core box. Throughput is hardware-bound, so the ratios between
> scenarios travel to other machines but the absolute MB/s figures do not.
> Re-measure on your own target before making a capacity plan. Run-to-run
> variance on this host is roughly ±10-15%; the throughput below is the median
> of four runs, and the latency table is a single representative run whose
> throughput matched that median.

---

## 1. Current results

### Latency

| Test | Full (ms) | Baseline (ms) | Speedup |
|---|---:|---:|---:|
| scan_clean_1KB | 0.48 | 0.38 | 1.3x |
| scan_mixed_1KB | 0.27 | 0.20 | 1.4x |
| scan_dense_1KB | 0.25 | 0.23 | 1.1x |
| scan_kw_heavy_1KB | 0.60 | 0.52 | 1.2x |
| scan_clean_10KB | 0.46 | 0.46 | 1.0x |
| scan_mixed_10KB | 0.94 | 0.90 | 1.0x |
| scan_dense_10KB | 1.28 | 1.28 | 1.0x |
| scan_kw_heavy_10KB | 0.95 | 0.96 | 1.0x |
| scan_clean_100KB | 2.44 | 2.48 | 1.0x |
| scan_mixed_100KB | 7.82 | 8.09 | 1.0x |
| scan_dense_100KB | 10.52 | 11.54 | 0.9x |
| scan_kw_heavy_100KB | 7.22 | 7.03 | 1.0x |
| scan_clean_1MB | 22.98 | 24.16 | 1.0x |
| scan_mixed_1MB | 112.19 | 114.30 | 1.0x |
| scan_dense_1MB | 152.68 | 154.40 | 1.0x |
| scan_kw_heavy_1MB | 71.30 | 70.51 | 1.0x |
| redact_mixed_10KB | 1.08 | 1.02 | 1.1x |

### Throughput (1 MB, median of 4 runs)

| Scenario | Full (583 patterns) | Baseline (122 patterns) |
|---|---:|---:|
| Clean text | 43.5 MB/s | 41.4 MB/s |
| Mixed content | 8.9 MB/s | 8.7 MB/s |
| Dense sensitive data | 6.5 MB/s | 6.5 MB/s |
| Keyword-heavy text | 14.0 MB/s | 14.2 MB/s |

### Pattern classification

| Tier | Count | Criteria |
|---|---:|---|
| Always-run (baseline) | 122 | Specificity >= 0.85, or in `CRITICAL_ALWAYS_RUN` |
| Context-gated | 461 | Specificity < 0.85, gated by the AC keyword prefilter |
| **Total** | **583** | |

The benchmark derives all three counts from `patterns::PATTERNS` at runtime, so
this table cannot drift from the scanner the way a hand-maintained one does.

### Test data definitions

- **Clean** — ordinary prose with no sensitive values, repeated to size.
- **Mixed** — email, SSN, credit card, phone and AWS key interspersed with normal text.
- **Dense** — back-to-back sensitive values (cards, emails, SSNs, API keys).
- **Keyword-heavy** — many context keywords ("account number", "social
  security", "bank") but **no** actual sensitive data. This is the adversarial
  case for the prefilter: the keywords force context-gated patterns to run and
  then match nothing.

---

## 2. What the numbers mean

**Full and baseline are effectively identical at 10 KB and above.** That is the
Aho-Corasick prefilter working as designed: context-gated patterns whose
keywords are absent get filtered out before their regex ever runs, so the 461
extra patterns cost almost nothing on a keyword-free page. `baseline_only` is
only meaningfully faster on small (< 10 KB) inputs, where the fixed AC-index
build cost dominates — visible above as the 1.1-1.4x column at 1 KB.

**Dense data is the floor, and that is by construction.** It is the only
scenario that actually exercises validation: every matched card runs Luhn,
every IBAN mod-97, every national ID its own algorithm. That work is what took
false positives on the blind-test corpus from ~95% to near-zero on the same
pattern set. Dense input is the worst case for it, so 6.5 MB/s is the price of
precision rather than a defect to optimize away.

**Keyword-heavy is the prefilter's worst case** and still lands above mixed
content, which is the useful result: adversarial keyword stuffing degrades
throughput without collapsing it.

**Finding counts are identical between modes** on the mixed corpus (164 vs
164), confirming baseline mode drops only patterns that were not contributing
findings there — not that it silently loses detections in general. It will miss
low-specificity detections by design.

### When to use baseline mode

- High-throughput pipelines where only critical/high-confidence patterns matter
- Latency-sensitive paths that can tolerate missing low-specificity detections
- A pre-screening pass ahead of a full scan

---

## 3. Historical record

> Everything below is **archival**. It was measured on a different, unstated
> machine during the 2.1.0 era against a 560-pattern table, and the Python
> implementation it compares against no longer lives in this repository. The
> figures are **not comparable** to section 1 and cannot be reproduced from a
> current checkout — they are kept because the optimization narrative explains
> why the scanner is shaped the way it is.

### Rust vs Python (v2.1.0, archival)

| Scenario | Python | Rust | Factor |
|---|---:|---:|---:|
| Clean text | 2.5 MB/s | 83.2 MB/s | 33x |
| Mixed content | 1.0 MB/s | 30.2 MB/s | 30x |
| Dense sensitive data | 0.5 MB/s | 31.9 MB/s | 64x |

### The optimization journey (v2.1.0, archival)

| Stage | Time (ms, 1 MB mixed) | Throughput | vs Python |
|---|---:|---:|---:|
| Python baseline | 960.05 | 1.0 MB/s | — |
| Rust v1 (RegexSet) | 16,124.24 | 0.1 MB/s | 16.8x **slower** |
| Rust v2 (parallel regex) | 44.41 | 22.5 MB/s | 21.6x faster |
| Rust v3 (+ AC prefilter) | 33.14 | 30.2 MB/s | 29.0x faster |

**v1 → v2: replace RegexSet with parallel per-pattern regex (Rayon).** A single
`RegexSet` over the whole table built a ~50 MB DFA that cost 13 ms on 1 KB.
Individual regexes driven by `rayon::par_iter()` were 50-100x faster. This one
change took the scanner from 16x slower than Python to 22x faster, and it is
why the pipeline still runs phase-1/phase-2 rather than one combined automaton.

**v2 → v3: add the Aho-Corasick prefilter and a normalization fast-path.**

- The AC prefilter gates most patterns behind keyword presence.
- An ASCII fast-path skips NFKC, homoglyph and zero-width processing entirely.
- `HashMap` O(1) lookup replaced an O(n) linear scan in `ContextHitIndex`.
- Fuzzy/leet matching is skipped when the AC index gives a definitive answer.

**Context-index tuning after the multilingual expansion.** v2.1.0 added ~2,500
multilingual keywords and the automaton grew to ~5,000 unique entries, which
initially cost ~30% throughput on dense content. Four changes recovered it:

1. **Keyword deduplication** — identical keywords across patterns (`credit
   card` appears in 7+ entries) are stored once and mapped to every pattern ID
   that uses them, shrinking the automaton.
2. **Pattern-ID indexing** — the hit index went from a
   `HashMap<(&str, &str), Vec<(usize, usize)>>` plus a cloned nested-`HashMap`
   reverse map to a flat `Vec<Vec<u32>>` keyed by pattern ID, eliminating
   ~5,000 String allocations per scan.
3. **Sorted position lists** — sorted once per scan, enabling O(log n) binary
   search in range checks instead of a linear walk.
4. **Compact u32 positions** — only `start` is needed for range checks, so
   positions are `u32` rather than `usize` pairs.

---

## 4. Reproducing

```bash
cargo run --release --bin benchmark
```

The banner, the throughput table and the pattern classification all derive
their counts from the live pattern table, so a fresh run is self-describing —
compare its header against this document's before trusting any figure here.

### Full scan vs baseline in the API

```rust
use siphon::guard::{InputGuard, Preset, Action};

// Full scan (default) — all 583 patterns, with the AC prefilter
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii, Preset::Credentials])
    .with_action(Action::Flag);

// Baseline-only — 122 always-run patterns, context-gated ones skipped
let guard_fast = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii, Preset::Credentials])
    .with_action(Action::Flag)
    .with_baseline_only(true);

let result = guard.scan("SSN: 123-45-6789, Card: 4532015112830366")?;
let result_fast = guard_fast.scan("SSN: 123-45-6789, Card: 4532015112830366")?;
```
