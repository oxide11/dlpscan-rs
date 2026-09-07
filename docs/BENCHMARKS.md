# Siphon Benchmarks

Two complementary approaches to measuring scanner performance: a **synthetic
benchmark** that runs the Rust library directly with reproducible template
input, and a **corpus benchmark** that scans real public-domain documents
through the CLI to measure behaviour on realistic input.

Neither replaces the other. The synthetic benchmark is stable and reproducible
— good for tracking regressions across commits. The corpus benchmark catches
what the synthetic misses: varying normalization pressure, format-dispatch
overhead, and the keyword density of real prose.

---

## Synthetic benchmark

```bash
cargo run --release --bin benchmark
```

Defined in `src/bin/benchmark.rs`. Scans four template strings (`clean`,
`mixed`, `dense`, `keyword_heavy`) at four sizes (1 KB, 10 KB, 100 KB, 1 MB)
and compares **full** (all 583 patterns) against **baseline** (always-run
patterns only). Outputs a table of median latency and derived throughput, plus
a pattern classification summary.

Run this after touching the scanner engine, normalizer, or any pattern, to
verify you haven't introduced a latency regression.

**Current synthetic numbers** (measured 2026-09-02, 4-core Intel Xeon @ 2.80
GHz, 16 GB RAM, Linux 6.18, Rust 1.98, release + LTO):

| Scenario (1 MB) | Full | Baseline |
|---|---:|---:|
| clean | ~23 MB/s | ~43 MB/s |
| mixed | ~9 MB/s | ~18 MB/s |
| dense | ~6.5 MB/s | ~12 MB/s |
| keyword_heavy | ~14 MB/s | ~26 MB/s |

Per-document at 10 KB mixed: **~0.94 ms** (~1,060 documents/second).

---

## Performance Corpus

A set of ~25 public-domain documents across small/medium/large size tiers,
used to benchmark the scanner against realistic input. No labelling is
required; these are for throughput measurement only.

### Why real documents matter

Synthetic templates repeat a fixed string to size. Real documents differ in
ways the synthetic cannot reproduce:

- **Variable normalization pressure.** A document with many hyphenated dates
  or accented characters triggers the ~9x-slower normalization path. The
  synthetic clean template never does.
- **Realistic keyword density.** Real contracts, legislation, and correspondence
  contain the kinds of context keywords (account, number, social security, date
  of birth) that activate the Aho-Corasick prefilter and gate context-required
  patterns.
- **Format diversity.** HTML legislative bills exercise the format-dispatch and
  XML extractor paths; plain-text books skip all of that. Together they show
  where extraction overhead lives.

### Sources

All documents are US public domain:

| Tier | Source | Examples |
|---|---|---|
| Small (30–200 KB) | Project Gutenberg plain text | Metamorphosis, Alice in Wonderland, Call of the Wild |
| Medium (200–600 KB) | Project Gutenberg plain text | Frankenstein, Tom Sawyer, Dorian Gray |
| Large (600 KB–1 MB) | Project Gutenberg plain text | Pride and Prejudice, Dracula, War and Peace |
| Legislation (HTML) | govinfo.gov | American Rescue Plan Act, Inflation Reduction Act |
| Regulation (XML) | federalregister.gov | HIPAA Omnibus Rule, GLBA Safeguards Rule, Cyber EO 14028 |

### Data provenance policy

This corpus is governed by the **data provenance policy** in `FUTURE.md`:

- **Real public documents may serve as carriers after screening.** The
  screening step (`scripts/corpus/screen.sh`) runs the scanner against every
  file and exits non-zero if any finding above 0.7 confidence is returned.
- **Sensitive values are always synthetic.** The corpus contains no real
  personal data. Project Gutenberg fiction and US federal legislation contain
  none to begin with; the screening step confirms this before any corpus use.
- **Breach data is prohibited absolutely.** No document sourced from a data
  breach, leaked database, or dark-web repository may enter the corpus under
  any framing ("anonymized", "for testing", "already public"). The harm is in
  the sourcing, not the subsequent use.

### Building the corpus

```bash
# Step 1 — download documents (~25 files, ~15 MB total)
bash scripts/corpus/fetch.sh

# Step 2 — verify no real sensitive data (required before benchmarking)
bash scripts/corpus/screen.sh

# Step 3 — run the benchmark
bash scripts/corpus/bench.sh
```

The fetch script is idempotent — re-running skips already-downloaded files.
Use `--force` to re-download everything.

The raw documents live in `corpus/raw/` which is gitignored. The scripts and
this document are committed; the blobs are not.

### Running the corpus benchmark

```bash
# Build the release binary first
cargo build --release
export PATH="$PWD/target/release:$PATH"

# Fetch and screen if you haven't already
bash scripts/corpus/fetch.sh
bash scripts/corpus/screen.sh

# Benchmark — prints per-file throughput and an aggregate
bash scripts/corpus/bench.sh
```

Output example:

```
Siphon corpus benchmark — 2026-09-07T14:22:00Z
Version: v2.10.0
Corpus:  /path/to/dlpscan-rs/corpus/raw

  File                                                  Size         Time (ms)     MB/s
  --------------------------------------------------------------------------------------
  gutenberg_1952_yellow_wallpaper.txt                29.8 KB            12ms   2.4 MB/s
  gutenberg_5200_metamorphosis.txt                   68.4 KB            29ms   2.3 MB/s
  gutenberg_11_alice.txt                            170.4 KB            58ms   2.9 MB/s
  ...
  --------------------------------------------------------------------------------------
  TOTAL (25 files)                                   14.8 MB          5.812s   2.5 MB/s

Corpus throughput: 2.5 MB/s  (14.8 MB in 5.812s, 25 files)
```

Results are appended to `corpus/bench.log` for trend tracking. Compare runs
across commits by checking this file.

### Last measured

| Date | Version | Throughput | Notes |
|---|---|---|---|
| *(not yet run)* | — | — | Run `bench.sh` to populate |

Update this table after each significant scanner change.

---

## Adding documents to the corpus

New documents must satisfy all of:

1. **Public domain.** US federal publications, Project Gutenberg texts, or
   material with a CC0 / public-domain dedication. No proprietary content,
   no scraping from paywalled sources.
2. **Screened clean.** Run `screen.sh` after adding. Remove the file if it
   flags anything above 0.7 confidence that cannot be explained as a false
   positive.
3. **Representative, not adversarial.** The corpus measures realistic scanner
   behaviour, not worst-case or best-case. A document chosen because it makes
   the scanner look fast (or slow) undermines the point.

Add the URL and local filename to `scripts/corpus/fetch.sh` under the
appropriate tier, then re-run the fetch and screen steps.

---

## Interpreting results

**Throughput is not a proxy for detection quality.** A faster scanner that
misses more is not better. The throughput numbers tell you about capacity
planning; `tests/corpus/` and `evadex` tell you about detection quality.

**Normalization dominates on heavy inputs.** The ~9x slowdown on
normalization-triggering text (hyphenated dates, accented characters) is the
largest variable. If your change touches `normalize/mod.rs`, run both the
synthetic and corpus benchmarks — the synthetic `dense` template triggers
normalization, but real documents show more realistic triggering rates.

**Extraction overhead is per-file, not per-byte.** The govinfo HTML bills are
large but spend time in the extractor (XML parse + entity decode) before the
scanner sees anything. A small improvement to the extractor can move the HTML
throughput number without touching the text-only rows.
