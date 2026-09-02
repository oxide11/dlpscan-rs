# Canada public professional contact corpus v1 — provenance

Committed under the **official public records exemption** in `FUTURE.md` →
Data provenance policy. Every record is the institutional contact detail of a
public official or public servant acting in an official capacity — work email,
office telephone, office address — published by a government body under an
explicit open licence.

Nothing here is a home address, a personal mobile, or a private email. The
corpus schema carries a `mobile_number_excluded` flag precisely because its
builder drew the same line.

## What it is

| | |
|---|---|
| Records | 13,551 |
| Annotated samples | 27,102 |
| Entity spans | 218,150 |
| Splits | train 21,818 · validation 2,698 · test 2,586 samples |
| Built | 2026-09-02 |
| Received | 2026-09-02, as `polygon_siphon_corpus_v1.zip` |

### Included sources

| Source | Publisher | Licence |
|---|---|---|
| GEDS — Government of Canada Employee Directory | Shared Services Canada | Open Government Licence – Canada 2.0 |
| Current Members of Parliament | House of Commons of Canada | House of Commons Open Data — unrestricted reuse |
| Directory of municipalities in Quebec | Government and Municipalities of Québec | CC-BY 4.0 |
| Elected officials, City of Montreal | Ville de Montréal | CC-BY 4.0 |

Three McGill faculty directories were evaluated and **deliberately excluded**,
marked in the source registry as `CAND_` with "No bulk/model-training licence
verified". University directories are outside the exemption in any case: they
mix faculty with students and teaching assistants, who are not public officials,
and student directory information is separately governed (FERPA in the US, and
provincial equivalents here).

## Independent audit, 2026-09-02

The published QA numbers were **not taken on trust**. Verified locally:

- All 9 SHA-256 checksums in `SHA256SUMS.txt` match.
- All **218,150** annotation offsets satisfy `text[start..end] == entity.text`.
- Zero out-of-bounds spans, zero overlapping spans.
- Zero person-level split leakage — no `PERSON_NAME` appears in more than one
  split, confirmed independently rather than read from the manifest.
- Label counts match the manifest exactly.
- **3,872 of 3,875** postal values pass our own `is_valid_canada_postal_code`.
  The three rejects are the `NA`/`-` placeholders the corpus itself documents as
  excluded from its normalized column.
- Province distribution derived from postal district letters comes out Ontario
  2,028 / Quebec 1,566 with everything else small — the National Capital Region
  dominating a federal directory, which is the shape real GEDS data should have
  and a signature synthetic data rarely reproduces.

## ⚠️ Offsets are character offsets, not byte offsets

Annotation spans use the Python convention. **60% of samples contain non-ASCII**
(the corpus is bilingual), and **116,155 of 218,150 spans would be wrong** if
read as byte offsets.

Rust strings are byte-indexed and `Match.span` is byte-based, so any Rust
consumer must convert. Reading them raw does not fail loudly — it silently
mangles exactly the French records:

```
text:  "Aaron Dahl — Data Production and Dissemination Coordinator"
span:  start=13 end=58, label JOB_TITLE
  as chars: "Data Production and Dissemination Coordinator"   correct
  as bytes: "\u{fffd} Data Production and Dissemination Coordinat"   mangled
```

The em-dash is three bytes, so everything after it shifts by two.

## What it measures, and what it cannot

Nine labels: `PERSON_NAME`, `JOB_TITLE`, `ORGANIZATION`, `STREET_ADDRESS`,
`CITY`, `REGION`, `POSTAL_CODE`, `EMAIL_ADDRESS`, `PHONE_NUMBER`.

**Siphon can detect three of them.** The other six are the NER gap described in
`FUTURE.md` — this corpus quantifies that gap rather than closing it.

It is also **not a calibration set for the pattern table at large**. It carries
positives for three categories out of 128; for the remaining 125 it provides
negatives only, which can measure a false-positive rate but cannot estimate
precision.

## Where the bulk files live

Three files are **not in git**:

| File | Size |
|---|---:|
| `polygon_siphon_ner_corpus_v1.jsonl` | 29.5 MB |
| `polygon_siphon_dlp_eval_v1.csv` | 12.7 MB |
| `polygon_siphon_entities_v1.csv` | 8.0 MB |

Everything else — this file, `README.md`, `manifest.json`, `SHA256SUMS.txt`,
the source registry, the chunk audit, the negative controls and the review
workbook — **is** committed, totalling ~560 KB. That is the part worth keeping
in history, and it is what makes a fetched copy verifiable.

The threshold is one megabyte, applied per file. It is not about this corpus:
the US corpus is ~600 MB, and more jurisdictions are expected. Committing them
would put every byte in every clone permanently, for data only the
detection-quality suites read.

### Fetching

```bash
scripts/fetch-corpus.sh --check              # what is missing
scripts/fetch-corpus.sh canada_contact_v1    # fetch and verify
```

Source is chosen by environment:

- `SIPHON_CORPUS_DIR` — a local directory laid out as
  `<dir>/<corpus>/<filename>`. Used by the CI cache and for offline work.
- `SIPHON_CORPUS_BASE_URL` — an HTTPS base; files are fetched from
  `$BASE_URL/<corpus>/<filename>`.

With neither set the script reports what is missing and exits 0, and
`tests/held_out_recall_test.rs` **skips rather than fails**. A contributor
without the corpus can still run every other suite. Checksums are verified
after any fetch *and* on a corpus that is already present — a file that is
present but corrupt is worse than one that is absent, because the suites would
run against it and measure the wrong thing silently.

### Why Cloudflare R2

The repository already deploys to Cloudflare (`deploy/cloudflare/`, wrangler
4.x), and CI already holds `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`.
The deciding property is **zero egress fees**: CI pulls the corpus on every
run, and at 600 MB the alternatives charge for exactly that.

- **Git LFS** was rejected. GitHub meters LFS bandwidth at 1 GB/month on the
  free tier, so a single 600 MB corpus exhausts it in two CI runs.
- **GitHub Releases** works and is free, with a 2 GB per-file cap. It remains
  a reasonable fallback, and needs no credentials for a public repository.
- **R2** costs about $0.015/GB-month — the whole corpus set is cents — and
  egress is free regardless of how often CI runs.

Bucket layout mirrors the fetch URL:

```
r2://siphon-corpora/
  canada_contact_v1/polygon_siphon_ner_corpus_v1.jsonl
  canada_contact_v1/polygon_siphon_dlp_eval_v1.csv
  canada_contact_v1/polygon_siphon_entities_v1.csv
  us_contact_v1/...
```

Create and populate with the wrangler already vendored under
`deploy/cloudflare/`:

```bash
npx wrangler r2 bucket create siphon-corpora
npx wrangler r2 object put \
  siphon-corpora/canada_contact_v1/polygon_siphon_ner_corpus_v1.jsonl \
  --file tests/corpus/canada_contact_v1/polygon_siphon_ner_corpus_v1.jsonl
```

Reads can be credentialed or public. A **public bucket** (custom domain, or
`r2.dev`) is simplest — CI needs no secrets and the objects cache well — but
it republishes the data under your account, which is a deliberate decision even
for public-record material rather than an implementation detail. A
**credentialed private bucket** avoids that question at the cost of an R2 token
in CI. Either way `SIPHON_CORPUS_BASE_URL` is the only thing the test harness
needs to know.

## Refreshing

Point-in-time snapshot. Membership changes with each election and staff move,
so `tests/held_out_recall_test.rs` pins its numbers to the files as committed.
Re-fetching means re-deriving the baselines in the same commit.
