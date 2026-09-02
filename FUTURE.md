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

Foundation 1 is governed by the **Data provenance policy**, which is binding:
real public documents as carriers, synthetic values, no breach data.

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

All of it is governed by the **Data provenance policy** below, which is binding
rather than advisory. In short: real public documents may serve as carriers
after screening, the sensitive values are always synthetic, and breach dumps
are out of the question.

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

### Worked example: what real carriers found in minutes

On 2026-09-02 a public dataset — the US House of Representatives office
directory, 442 rows of name / phone / office address as an `.xlsx` — was run
through the scanner as a provenance screening test. It is squarely within the
policy below: official contact details of elected officials in their official
capacity, published by design, US government work.

**The scanner returned zero findings**, from a document containing 441 valid US
phone numbers. Extraction was fine (30,164 characters recovered), so this was a
detection failure, and reducing it gave:

| Input | Detected |
|---|---|
| `202-225-8490` | yes |
| `Phone: 202-225-8490` | yes (with context) |
| `202-225-8490 CHOB` | yes |
| `202-225-8490 417` | **no** |

The cause is in normalization, not in the phone pattern:

```
"202-225-8490 417"   ->  "2022258490417"     13-digit run, matches nothing
"202-225-8490 CHOB"  ->  "2022258490 CHOB"   10-digit run, matches
```

`collapse_padding` drops whitespace between two non-alphabetic characters to
defeat `4 5 3 2 0 1 5 1` padding evasion. Digits are not alphabetic, so it also
**fuses adjacent numeric fields**. Any sensitive number followed by another
number — a room number, an extension, an employee ID, a date, an amount —
becomes invisible. That is the normal shape of a spreadsheet row, and
spreadsheets are a headline supported format.

This is not a simple fix, because the same fusing is *required* elsewhere: a
card number written `4532 0151 1283 0366` is only detected because
`collapse_padding` fuses it. One destructive normalization cannot serve both
cases.

Two candidate directions, neither yet chosen:

- **Scan the original text alongside the normalized text.** The scanner already
  has an alternatives mechanism for alt-decodings; raw text becomes one more
  candidate. Costs roughly a second matching pass, and fixes the whole family
  of "normalization destroyed the evidence" bugs — of which the GPS coordinate
  miss fixed earlier that day was another instance, patched by special-casing
  rather than at the root.
- **Make `collapse_padding` sensitive to run length**, on the theory that
  padding evasion uses single-character groups while legitimate adjacent fields
  are multi-digit. Cheaper, but a heuristic layered on a heuristic.

The finding matters more than the fix. **One real document, minutes of work,
and it surfaced a recall bug across an entire supported file format that 80
synthetic fixtures had not.** Synthetic data validates what we thought to
encode; real carriers surface what we did not.

### Three legislative directories, measured

Extending the same exercise to the Canadian House of Commons address list and
the UK Parliament members CSV — both official public directories of elected
representatives, both squarely within the policy below — gives the first real
per-category numbers we have ever had:

| Source | Ground truth | Detected | Recall |
|---|---:|---:|---:|
| US House directory (xlsx) | 441 phones | 0 | **0%** |
| Canada MP addresses (html) | 1,306 phones | 1,141 | 87% |
| Canada MP addresses | 408 postal codes | 0 | **0%** |
| UK MPs (csv) | 649 postcodes | 649 | **100%** |
| UK MPs (csv) | 643 emails | 643 | **100%** |

Canada also produced roughly **250 false positives** across fifteen foreign
identifier categories — Colombia Cedula, British NHS, Thailand Tax ID, Indiana
DL, India Aadhaar and eight **credit-card PANs** among them — on a document
containing nothing but Canadian office contact details.

**The 0% versus 100% on postal codes is the same pattern class**, and the
explanation is the most valuable finding of the exercise.

### First held-out measurement, and what it found

A 13,551-record Canadian public-professional-contact corpus (27,102 annotated
samples, 218,150 entity spans, train/validation/test split with zero
person-level leakage) was audited independently and then used to measure the
scanner on its **test split** — 2,586 samples never used for anything else.

Audit first, since the numbers below only mean something if the corpus is
sound: all 218,150 annotation offsets verified, zero out-of-bounds, zero
overlapping spans, zero split leakage, label counts matching the manifest, and
3,872 of 3,875 postal values independently confirmed by our own
`is_valid_canada_postal_code` (the three rejects are documented `NA`/`-`
placeholders). The province distribution derived from district letters is
Ontario 2,028 / Quebec 1,566 with everything else small — the National Capital
Region dominating a federal directory, which is a semantic signature synthetic
data rarely reproduces.

**One interoperability trap:** annotation offsets are **character** offsets,
the Python convention. 60% of samples contain non-ASCII (the corpus is
bilingual) and 116,155 of 218,150 spans would be wrong if read as **byte**
offsets. Rust strings are byte-indexed and `Match.span` is byte-based, so any
Rust consumer must convert. Reading them raw silently corrupts exactly the
French records.

Recall on the held-out test split, for the three labels the scanner supports at
all:

| Label | Found | Missed | Recall |
|---|---:|---:|---:|
| EMAIL_ADDRESS | 1,160 | 8 | 99.3% |
| POSTAL_CODE | 2,314 | 150 | 93.9% |
| PHONE_NUMBER | 920 | 1,086 | **45.9%** |

The remaining six labels — PERSON_NAME, JOB_TITLE, ORGANIZATION,
STREET_ADDRESS, CITY, REGION — the scanner cannot detect at all. That is the
NER gap, now quantified rather than asserted.

### Phone numbers are not missed, they are misattributed

45.9% looks like a recall failure and is not one. The spans *are* detected; they
are labelled as the wrong thing:

    343-553-1633  ->  Peru Carnet Extranjeria
    519-827-9864  ->  Peru Carnet Extranjeria
    343-990-8909  ->  British NHS

For a DLP tool this is worse than a miss, because a finding routed to the wrong
category is routed to the wrong policy.

The competing patterns explain it:

| Pattern | Regex | Specificity | Always-run |
|---|---|---:|---|
| British NHS | `\d{3}\s?\d{3}\s?\d{4}` | 0.65 | yes |
| Peru Carnet Extranjeria | `\d{9,12}` | 0.40 | no |
| Colombia Cedula | `\d{6,10}` | 0.40 | no |
| US Phone Number | `(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` | 0.40 | yes |

`British NHS` matches every ten-digit number on earth, is always-run, and
outranks the phone pattern, so it wins deduplication. It is not an unvalidated
pattern — NHS numbers carry a mod-11 check digit and we verify it — but roughly
one in eleven arbitrary ten-digit numbers passes that check by chance, and
`3439908909` is one of them.

The defect is the **ranking**, not the validation. A `NNN-NNN-NNNN` string that
also satisfies NANP structure is far more likely to be a telephone number than
an NHS number that merely passed a one-in-eleven checksum, yet the phone
pattern is scored 0.40 against the NHS pattern's 0.65. Specificity is being
used as a proxy for confidence while being assigned by hand and never
calibrated against outcomes.

This is the concrete case for the calibration item below, and the corpus is now
the instrument for it: 2,586 held-out samples with known answers make it
possible to fit specificity to observed precision instead of guessing. It also
explains the ~250 "false positives" measured earlier on the Canadian MP
directory, which were largely not spurious findings at all but real phone
numbers wearing foreign identity-document labels.

### `context_required: false` does not mean the pattern runs

`Canada Postal Code` and `UK Postcode` both declare `context_required: false`,
and `docs/PATTERNS.md` reports "Context Required: No" for both. Neither fires
on a bare address block:

| Input | Detected |
|---|---|
| `Edmonton, Alberta T5A 1B7` | no |
| `Postal code: T5A 1B7` | yes |
| `House of Commons London SW1A 0AA` | no |
| `Postcode` (header) then `SW1A 0AA` | yes |

The cause is that **two independent gates exist and only one is documented.**
Beyond the pattern's own `context_required` flag, the scanner's Aho-Corasick
prefilter drops any pattern whose specificity is below the 0.85 always-run
threshold unless one of its keywords is present. Canada Postal Code is 0.75 and
UK Postcode is 0.70, so both are keyword-gated in practice no matter what their
flag says.

The UK CSV scored 100% purely because it has a `Postcode` column header
supplying that keyword. The Canadian page renders addresses as humans write
them, with no label, so the same pattern never ran. **Detection therefore
depends on document formatting in a way the pattern definitions actively deny.**

This affects every one of the 461 context-gated patterns that declares
`context_required: false`, and it makes `docs/PATTERNS.md` misleading rather
than merely incomplete. Two things follow: the generated documentation should
report the effective gate rather than the declared one, and the specificity
threshold deserves review against real unlabelled address and contact data.

### The same defect cuts both ways

The Canadian false positives are the *same* normalization behaviour as the US
recall miss, seen from the other side. Matches such as
`306-975-4051\n1-620` (PAN) and `613-498-3100\n29` (Aadhaar) are phone numbers
fused across a line break into digit runs long enough to satisfy a card or
national-ID pattern.

One behaviour, two failure modes: numbers that should match become too long to
match, and numbers that should not match become long enough to. Any fix has to
be evaluated against both.

---

## Data provenance policy

Binding, not aspirational. Written down because it will be re-litigated the
first time someone finds a large, convenient dataset.

### The rule

**No real personal data enters this repository, in any form, ever.** Real
documents may serve as *carriers* only after passing the screening gate below.
The sensitive values themselves are always synthetic.

### Exemption: official public records of officials acting in official capacity

Added 2026-09-02 by owner decision, after the legislative directories below
proved their value. This is a **narrow, bounded** carve-out from the "no real
personal data" rule, not a softening of it.

Such records may be committed to the repository **as-is** when *all* of the
following hold:

1. Published by a government or public body, either under a legal mandate or
   deliberately for public use.
2. It concerns individuals **acting in an official or institutional capacity** —
   an elected representative, a public office holder.
3. The contact details are **institutional**: office telephone, office address,
   official email. Never home addresses, personal mobiles or private email.
4. Freely accessible without authentication, and not disallowed by the
   publisher's `robots.txt`.
5. Provenance is recorded — source URL, retrieval date, publishing authority —
   in a `PROVENANCE.md` beside the data.

Currently exercised by `tests/corpus/public_records/`.

**The exemption does not reach**, and no argument from "it is public" extends
it to:

- Breach dumps and leaked databases. Unchanged and absolute.
- Scraped or brokered consumer directories.
- Personal contact details of private individuals, however obtained.
- Records that are *about* a person rather than about their office. Public
  sector compensation disclosures sit exactly on this boundary: lawfully
  published under statute, but a named individual's salary is personal
  information rather than institutional contact data. Treat case by case, and
  prefer using such sources as **negative** corpora — documents where the
  scanner should find little — over retaining the personal fields.

The distinction the exemption turns on is **institutional versus personal**,
not **public versus private**. A minister's switchboard number is the
organisation's data; their home number would not be, even if a newspaper
printed it.

### Permitted

- **Public-domain or openly licensed documents, used as carriers.**
  CourtListener / the RECAP archive (US federal court records — US government
  works are not copyrightable), SEC EDGAR filings, GovDocs1, Project Gutenberg,
  public source repositories.
- **Synthetic identifiers from our own generators** (`src/guard/obfuscate.rs`,
  extended per validator).
- **evadex adversarial output**, which is generated rather than collected.
- **Synthetic labelled sets** with compatible licences, e.g.
  `ai4privacy/pii-masking`, for cross-checking our own generators.
- **DUA-gated de-identification corpora** such as i2b2/n2c2 — real clinical
  documents with *surrogate* identifiers substituted in. This is the pattern
  the de-identification research community converged on, and it is the right
  model: real structure, fake values. Usable only under the executed agreement,
  and never committed here.

### Prohibited

- **Breach dumps and leaked databases.** No lawful basis exists for processing
  them under GDPR Art. 6 — possession and processing are the regulated acts,
  and "it was already public" is not a basis. Several US state regimes and CFAA
  theories reach them as well.

  The commercial argument is stronger than the legal one. Siphon is sold as a
  compliance tool; a test corpus built from breach data would be an existential
  trust event and a probable breach of any signed DPA. Git history is
  permanent, so this is not a decision that can be quietly reversed later.

  They are also poor data for the purpose: mostly single-field credential
  tables with none of the document context the detection corpus needs.

- **Scraped or commercially aggregated people-directories.** Murky provenance,
  and purpose limitation bites — data published so the public can find a
  licensed physician does not thereby permit bulk reuse as training data.
  Genuinely public registries published *by design* (business registries,
  professional licensing boards) are a different case and are permitted as
  carriers.

- **Any real PII committed to the repository** — including fixtures, CI logs,
  benchmark inputs and issue attachments.

### The grey area, handled explicitly: court records

Court filings are public record, cleanly licensed, and genuinely the most
realistic carrier material available. They are also **well documented as
containing PII that should have been redacted and was not** — researchers have
repeatedly recovered SSNs, financial account numbers and minors' names from
PACER filings.

So they are permitted as carriers, but *only* through the screening gate. Their
public-record status is a better footing than breach data; it is not a blanket
exemption, and under GDPR "publicly available" is a factor rather than a
defence.

### The screening gate

Every real document ingested as a carrier is scanned with Siphon before it is
committed. Anything producing a high-confidence finding is excluded or
redacted.

This has a useful recursive property: **our own tool becomes the intake
filter**, and every finding raised during screening is a real-world example of
how PII appears in the wild. Record the *shape* — the formatting, the
surrounding context, the failure mode — as a case for the synthetic generator.
Never retain the value.

### If real data must ever be used

For validation against a customer's own corpus, or under a DUA:

- It never enters git. Access-controlled external storage, with the lawful
  basis or agreement documented alongside it.
- It never reaches CI logs or artifacts.
- Only aggregate metrics cross that boundary — counts and rates, never spans or
  matched text.

### Why the hybrid wins on merit, not only on caution

Real data arrives **unlabelled**. Labelling it means people reading real PII at
volume, which compounds the exposure, and yields a few thousand labels for
weeks of effort. Synthetic injection yields exact spans, free, at any volume.

Real PII is therefore *more* work, *more* risk and *less* useful output. The
one thing it genuinely offers — the distribution of how identifiers actually
appear in real documents — is captured by using real documents as carriers,
which the policy above already permits.

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

### Metadata-driven routing: activate patterns by document evidence

The scanner currently runs the same 583 patterns and 5,178 keywords across six
languages against every document, regardless of what the document is. A
French-Canadian Word file is scanned for Peruvian immigration cards with
exactly the same enthusiasm as a Peruvian one.

That is not only wasteful, it is a measured precision problem. The false
positives fixed on 2026-09-02 came overwhelmingly from **foreign-language short
keywords** — `ce` (Peru), `cc` (Colombia), `ci` (Venezuela), `cf` (Italy) —
firing inside ordinary English words. Word boundaries fixed the mechanism; they
did not address the deeper oddity, which is that those keyword sets were live
at all in a document with no connection to those jurisdictions.

The structure to aim for is a **sparsely activated** one: a cheap routing
signal decides which pattern and keyword families are plausible for this
document, and the rest stay dormant. The scanner already has the shape of it —
the Aho-Corasick prefilter *is* a router — it simply routes on the wrong
signal, using hand-assigned specificity where it could use evidence about the
document in hand.

#### The signals already exist and are already extracted

`forensics/` parses OOXML and PDF metadata today and hands it to a separate
report; **the detection path consumes none of it**.

| Signal | Where it lives | Notes |
|---|---|---|
| `dc:language` | OOXML `docProps/core.xml`, PDF XMP | Already captured — `parse_core_xml`'s catch-all files it under `raw["cp:language"]`, a mislabelled prefix since it is Dublin Core |
| Editing language | OOXML `word/settings.xml` `w:themeFontLang` (`en-US`, `fr-CA`) | Strong signal; the language the author's Word was configured for. Not yet parsed |
| Timezone offset | `created_at` / `modified_at` ISO 8601 strings | Already stored verbatim, offset included. `-05:00` narrows to the Americas |
| Producer locale | `application` (`xmp:CreatorTool`, OOXML `<Application>`) | Often carries a locale suffix |
| Organisation | `company` (OOXML `<Company>`) | Populated on domain-joined installs |

Adding a first-class `language` and `locale` field to `FileMetadata`, and
parsing `w:themeFontLang`, is a small change with the signals mostly in hand.

#### How it should be used: a prior, never a filter

Two constraints make the difference between a good feature and a vulnerability.

**Metadata is attacker-controlled.** Any of these fields is trivially editable
in a document someone is trying to exfiltrate through. If metadata *gates*
detection, then setting `dc:language` to `zh` becomes a one-line evasion for
every non-Chinese pattern — a far worse bug than the false positives it would
fix. Metadata may therefore **weight confidence**; it must never suppress a
pattern outright.

**Metadata is frequently absent or wrong.** Scanned PDFs, stripped documents,
plain text and anything through a converter carry nothing. The routing must
degrade to today's behaviour rather than fail closed.

Both point the same way: **language identified from the document text is the
more robust signal**, with metadata corroborating it rather than the other way
round. Text-derived language cannot be edited without editing the document, and
it is present whenever there is text to scan at all.

#### What it buys

- **Precision.** A `de-DE` document with a bare nine-digit number is far more
  likely to hold a German identifier than a Peru Carnet Extranjeria. This is
  the same misattribution class that put phone recall at 45.9%, attacked from a
  different side: instead of asking which pattern is more specific in the
  abstract, ask which is more plausible *here*.
- **Speed.** Five of six keyword languages skipped shrinks the automaton
  materially, and the prefilter is the pipeline's largest throughput win
  already.
- **Corroboration, and the postal case is the worked example.**
  `canada_postal_district_region()` maps a district letter to a province:
  metadata region, postal district and city name are three independent signals
  that either agree or contradict. `B3P` beside "Halifax" in an `en-CA`
  document is coherent and should score up; `T5A` beside "Nova Scotia" is
  incoherent and should score down. Today each finding is scored alone, so
  none of that is expressible.

#### Suggested first step

Not the routing. First make the signals visible: add `language` and `locale` to
`FileMetadata`, parse `w:themeFontLang`, correct the `dc:language` prefix, and
**report what is found without acting on it**. Then measure how often real
documents actually carry usable locale metadata, using the public-records
corpus and whatever else is to hand.

If the answer is "rarely", text-derived language identification is the whole
feature and metadata is a footnote. If it is "usually", the routing is worth
building. That is a day's work and it decides the shape of everything after it
— which is the same discipline the rest of this document argues for: measure
the premise before building on it.

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
| 7 | Locale-signal survey — measure, don't build | — | no |
| 8 | Metadata/language routing, if the survey supports it | 2, 7 | no |
| 9 | Vectorscan evaluation | 2, 4 | no |
| 10 | GBDT false-positive reranker | 1, 4 | yes |
| 11 | Optional NER stage | 4, 10 | yes |

Items 1-4 are the two foundations. Items 5-9 need no ML at all and are worth
doing regardless of whether any model is ever trained. Items 10-11 only become
possible — and, more to the point, only become *measurable* — once the rest
exists.

Item 7 is deliberately a survey rather than a build. Whether locale metadata is
usually present or usually absent in real documents decides whether item 8 is a
feature or a footnote, and that is a day's measurement rather than a guess.
