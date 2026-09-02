# Siphon — Future Direction

Last updated: 2026-09-02

Strategy and roadmap. Companion to `CLAUDE.md` (architecture and conventions),
`BACKLOG.md` (the near-term work queue) and `HANDOFF.md` (resume-here notes).
Items here graduate into `BACKLOG.md` when they are ready to build.

---

## The short version

Two foundations gate everything else:

1. **We need far more test data** — for measuring performance against realistic
   input, for detecting recall regressions, and eventually for training
   anything.
2. **We need per-category baselines and instrumentation** — precision, recall
   and accuracy for each of the 128 categories, not a single pass/fail.

Neither is glamorous. Both are prerequisites, not alternatives, to the
interesting work below. Right now the scanner cannot answer *"which of our 128
categories is weakest?"*, and no roadmap item can be validated without that
answer.

---

## Evidence base

Measured 2026-09-02 on a 4-core Intel Xeon @ 2.80 GHz, 16 GB, Linux 6.18,
Rust 1.98, release + LTO. Throughput medians over 4-6 runs; allocation figures
are deterministic and reproduce exactly.

| Scenario (1 MB) | Throughput |
|---|---:|
| Clean text | ~43 MB/s |
| Mixed content | ~9 MB/s |
| Dense sensitive data | ~6.5 MB/s |
| Keyword-heavy text | ~14 MB/s |

Full scan of 1 MB mixed content is ~147 ms, of which normalization is the
largest single component. Per-document latency at 10 KB is ~0.94 ms, or roughly
1,000 documents/second.

**The important lesson from that session:** three consecutive rounds of
constant-factor optimisation inside the existing architecture (eliminating
no-op clones, adding stage prescans, cutting the two largest allocators)
reduced normalizer allocation by 30-63% and halved normalization time *in
isolation* — but moved **end-to-end scan time by only ~2.5%**.

Two conclusions follow, and they shape everything below:

- Isolated micro-benchmarks on this workload **overstate** end-to-end gains.
  Measure the whole scan, not the stage.
- The remaining speed wins are **not** in this architecture's constant factors.
  They are in changing the matching strategy, or in not doing the work at all.

### Known pathology (unowned)

The non-ASCII separator path performs **~945,800 allocations per megabyte**.
This predates the 2026-09-02 work (baseline measured 945,808) and has its own
fix pending. Not urgent — it only affects non-ASCII separator evasion — but it
is a real defect, not a design tradeoff.

---

## Foundation 1 — test data

Today `tests/corpus/` holds **80 labelled findings**. That is too small to
train on, too small to calibrate against, and too small to detect a small
recall regression with any confidence.

"More test data" is really **three different corpora** with different
requirements. Conflating them is the usual reason this work stalls.

### 1a. Performance corpus — realistic documents, no labels needed

The benchmark currently scans a synthetic template repeated to size. Real
documents differ in ways that matter: they contain dates, parenthesised
numbers, tables, headers and boilerplate, all of which change which
normalization stages fire. A document containing a hyphenated date takes a
~9x slower normalization path than the same length of plain prose.

Needs: a few hundred representative documents (invoices, contracts, HR files,
logs, source code, support tickets) at varying sizes. No labelling required.
This alone makes `docs/BENCHMARKS.md` meaningful for capacity planning.

### 1b. Detection corpus — precise span labels, adversarial coverage

Extends today's `tests/corpus/` labelled set. Needs enough examples **per
category** to compute a per-category recall figure with a usable confidence
interval — order hundreds of positives across the categories that matter, plus
negatives that are plausibly confusable with them.

The evadex adversarial harness already generates bypass attempts; wiring its
output back in as labelled negatives is the cheapest source of hard cases.

### 1c. Training data — volume plus a feedback signal

Only relevant once 1b exists. A false-positive reranker wants low thousands of
labelled candidates; NER fine-tuning wants thousands of labelled spans.

**We already have the collection infrastructure.** Findings persist to Postgres
with full scan context (`crates/siphon-api/src/db.rs`), and every scan records
what matched and why. What is missing is a **feedback signal** — an analyst
marking a finding as true or false positive. Adding that one column plus an
endpoint turns production use into a growing labelled corpus, at which point
1c builds itself.

### How much is "enough"

For a per-category recall estimate accurate to ±5% at 95% confidence, a
proportion estimate needs roughly **100-150 examples per category**; ±10%
needs about 35. Across 128 categories that is 4,500-19,000 labelled instances
if every category is treated equally.

It should not be. **Tier the categories** — the ones that carry real
regulatory weight (PCI, national IDs, health identifiers, credentials) get the
full sample; long-tail regional patterns get enough to catch a total break, not
a precise figure. A realistic first target is ~100 positives each for a top
tier of 20-30 categories, and ~20 for the rest.

That volume is not reachable by hand, which is why synthetic generation below
is the primary path rather than a shortcut.

### How to obtain it

The hard constraint: **nothing containing real personal data may enter the
repository.** Everything committed is synthetic or public-domain. If real
customer data is ever used for validation it stays outside git entirely, in a
gitignored fixture store or a separate private corpus, and never in CI logs.

**Performance corpus (1a) — public documents, no labels.**

- **GovDocs1** — roughly a million freely redistributable real-world files
  (PDF, DOC, XLS, PPT, HTML) collected for digital-forensics research. This is
  almost exactly the shape needed: real documents, real structural mess, no
  licensing problem.
- **SEC EDGAR** filings and government FOIA releases for long-form business
  documents.
- **Enron email corpus** for realistic business email and threading.
- **Public GitHub repositories** for source code, and **Project Gutenberg** for
  long prose.

Sample across size buckets (1 KB / 10 KB / 100 KB / 1 MB+) and format mix, then
record the distribution so benchmark numbers are reproducible.

**Detection corpus (1b) — synthetic injection is the workhorse.**

The key insight is that **labels are free when you generate the data**: inject
a known identifier into a carrier document at a known offset and the span
label falls out of the generator.

- **We already have part of a generator.** `src/guard/obfuscate.rs` produces
  valid fake identifiers — `generate_luhn_number` among them — precisely so
  `Action::Obfuscate` can replace real ones without breaking downstream format
  checks. Pointed at carrier documents instead of at matches, it becomes a
  labelled-positive generator.

  Scope check: it currently has **9 type-specific generators** (cards, email,
  phone, SSN/ITIN/SIN, IBAN, IPv4, MAC, secrets) plus a generic fallback. That
  covers the highest-value categories but not the long tail — most categories
  fall through to `obfuscate_generic`, which will not satisfy a checksum
  validator such as Verhoeff or mod-97.

  Extending it is mechanical rather than novel: **each of the 72 validators is
  a specification for its own generator**, usually just "emit the payload, then
  compute and append the check digit the validator would verify." Writing the
  generator next to the validator also cross-checks both — a generator whose
  output its own validator rejects is a bug in one of them.
- **Carrier documents come from 1a**, so positives sit in realistic context
  rather than in bare fixture strings — which is what makes context-gating and
  proximity scoring testable at all.
- **evadex** already generates adversarial variants; wiring its output back in
  as labelled cases is the cheapest source of genuinely hard examples.
- **Public labelled sets** where licensing permits: `ai4privacy/pii-masking`
  (synthetic, span-labelled) for cross-checking, CoNLL-2003 and OntoNotes for
  the NER work later. De-identification challenge sets (i2b2/n2c2) are
  excellent for health data but require a data use agreement — worth it only
  if healthcare becomes a priority vertical.

**Negatives matter as much as positives, and are easier to source.** The
false-positive surface is things that *look* like identifiers: invoice and
order numbers, part numbers, git SHAs, version strings, UUIDs, telephone
extensions, ISBNs, timestamps. These can be mined directly from 1a and public
repositories with no labelling effort beyond "this document contains no PII."
Today's `tests/corpus/negatives/` is the right shape and simply needs volume.

**Training data (1c) — production feedback.**

Synthetic data bootstraps a model but will not teach it the false positives
that actually occur in a customer's documents. That signal only comes from
analyst feedback on real findings, which is why item 1 in the sequence below is
a feedback column rather than a model.

---

## Foundation 2 — baselines and instrumentation

`cargo test --test detection_quality` reports pass/fail against 80 findings. It
became a CI gate on 2026-09-02, which stops silent regressions, but it cannot
tell us **where** the scanner is weak.

What is needed:

- **Per-category precision, recall and F1**, reported as numbers rather than a
  boolean. 128 categories, each with its own figure.
- **A stored baseline** so a change reports a delta ("Card Expiry recall
  -4%") rather than just red or green.
- **Confidence intervals**, so a 2% move on 6 samples is not mistaken for a
  real regression.
- **A precision/recall curve over `min_confidence`**, so the threshold can be
  chosen against evidence instead of taste.
- **Per-category latency**, to identify patterns that are expensive relative to
  what they catch.

This is the highest-value work on the whole list, because every later item is
unverifiable without it — including the claim that a rewrite preserved
behaviour.

---

## What unlocks once the foundations exist

Roughly in order of value per unit of risk.

### Calibrate confidence scores

`specificity: 0.90` is a hand-assigned constant. It is not a probability, so
`min_confidence: 0.6` does not mean "60% precision" — it means nothing
measurable. Fitting a calibration map (logistic regression, Platt scaling or
isotonic regression) against the labelled corpus turns the existing threshold
into an actual precision dial.

Cheap, classical statistics, no new dependencies, and it makes every existing
control honest. Requires Foundation 1b + 2.

### Document-level aggregation

Every finding is currently scored independently. A name *plus* a date of birth
*plus* an address in one document is categorically more sensitive than any one
of them alone, and the pipeline has no way to express that.

Probably the highest-value detection-quality change that needs no ML at all.

### Structure-aware detection

Table and column awareness: a column of 9-digit numbers under a header reading
"SSN" is nearly certain, and that structure is currently discarded by the
extractors. Related: language identification, to select one keyword set rather
than running all six.

### Vectorscan for the matching stage

The clearest unexplored speed lever. The current design — `RegexSet` phase 1 to
find *which* patterns fire, then per-pattern phase 2 to extract spans — is a
hand-rolled approximation of what Intel's Hyperscan/Vectorscan does natively in
a single SIMD pass, including span extraction. It is what Suricata and most
commercial DPI engines use, and Rust bindings exist (`vectorscan-rs`).

Plausibly several times faster on the matching stage. Two caveats: it adds a
C++ dependency to a workspace that currently ships a static Rust binary, and
its regex dialect differs from the `regex` crate's, so every pattern needs
revalidation — which is only possible with Foundation 2 in place.

### Smaller speed items

- **SIMD normalization** — the delimiter stripping is byte-at-a-time and is
  textbook vectorizable.
- **Document-level rather than pattern-level parallelism** — better cache
  locality than `rayon` across 583 patterns.
- **Streaming scan API** — replaces the 10 MB input ceiling with bounded
  memory.
- **Narrow the offset map from `usize` to `u32`** — halves the largest
  recurring allocation in every normalizer stage; the 10 MB ceiling makes
  `u32` provably sufficient. Deferred because it changes a public signature.

---

## On machine learning

Considered on 2026-09-02. Recorded here with reasoning so it does not need
re-litigating.

### Rejected: training a language model from scratch

Significant effort to underperform models that already exist, and none of the
value here is generative.

### Rejected: an inline transformer over the byte stream

On our own numbers: a 10 KB document scans in **0.94 ms** today. The same
document is ~2,500 tokens, about five 512-token sequences, which a small
encoder runs in **50-150 ms** on CPU. That is a **50-150x slowdown**, turning
~1,000 docs/sec into ~10. It also adds 20-250 MB of weights and an ONNX or
candle runtime to a container that currently ships a `--locked` static binary.

That is not an optimisation with a tradeoff; it is a different product.

### Accepted in principle: a model as a *reranker*

The existing pipeline is already an excellent **high-recall prefilter**. 583
regexes plus Aho-Corasick gating cheaply proposes candidates; its weakness is
precision and expressiveness, not recall.

So run any expensive model **only on candidates that already matched**, never
over every byte. On a 10 KB mixed document that is ~164 findings rather than
10,000 bytes — the cost becomes per-finding instead of per-megabyte, and
throughput barely moves. Cheap high-recall filter feeding an expensive
high-precision reranker is the right cascade.

**Start with a gradient-boosted tree, not a neural network.** The features are
already computed: pattern specificity, validator pass/fail, context keyword
hits and distances, entropy, surrounding token shapes, position in document. A
GBDT on those cuts false positives, trains on thousands rather than millions of
examples, runs in microseconds, and yields feature importances.

### Accepted in principle, deferred: NER for names and addresses

The one capability regex fundamentally cannot provide. No amount of pattern
work will find "Jane Analyst, 42 Elm Street", and in many real DLP incidents
that is the thing that matters.

Ship it as a **feature-gated optional stage, off by default**, consistent with
how `siem`, `tui` and `python` are already handled. Biggest capability gain,
biggest cost, so it goes last.

### The constraint that shapes all of it

Siphon is a **compliance tool**. It has an HMAC audit chain and a
`/v1/scan/explain` endpoint. "Matched Visa pattern, passed Luhn, keyword 'card
number' within 40 characters" is a defensible audit artifact. A logit is not.

Any model must therefore **feed the existing confidence score as one more
signal**, never replace the decision. That is a product constraint, not just an
engineering preference.

### The trap

Reaching for a model is often a substitute for defining the metric. This
scanner cannot currently report its precision per category. Adding a model to
an unmeasured system makes it harder to reason about, not easier — which is
why both foundations come first.

---

## Suggested sequence

| # | Item | Depends on | ML? |
|---|---|---|---|
| 1 | Analyst feedback column + endpoint on findings | — | no |
| 2 | Per-category precision/recall/F1 with stored baselines | — | no |
| 3 | Realistic performance corpus | — | no |
| 4 | Grow the labelled detection corpus | 3 | no |
| 5 | Calibrate confidence scores | 2, 4 | no |
| 6 | Document-level aggregation | 2 | no |
| 7 | Vectorscan evaluation | 2, 4 | no |
| 8 | GBDT false-positive reranker | 1, 4 | yes |
| 9 | Optional NER stage | 4, 8 | yes |

Items 1-4 are the foundations the user identified. Items 5-7 need no ML at all
and are worth doing regardless. Items 8-9 only become possible — and only
become measurable — once the rest exists.
