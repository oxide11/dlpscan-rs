# Forensics & Author Attribution

Siphon's forensics module extracts **document-level metadata** from
PDF and OOXML (docx / xlsx / pptx) files and computes **pairwise
attribution scores** across a set of documents. The goal is
investigator-grade evidence: even after a leaked document is
renamed, re-saved, and its visible content stripped, its internal
metadata usually still identifies the machine and tool that
authored it.

The module ships behind a `forensics` Cargo feature (on in the
default build). Use it from the CLI or drive it directly from code.

## CLI

```sh
# Single file — metadata dump
siphon forensics path/to/report.docx

# Multiple files — metadata + pairwise attribution matrix
siphon forensics doc-a.docx doc-b.docx report.pdf

# JSON output for piping into SIEM / evidence-management tooling
siphon forensics doc-a.docx doc-b.docx --json > evidence.json
```

Human output on a two-file invocation looks like:

```
── doc-a.docx ──
  kind               Docx
  sha256             3a1f…9c02
  size               18043 bytes
  creator            Jane Analyst
  last modified by   Jane Analyst
  application        Microsoft Word 2021
  company            Acme Corp
  rsids              4 sessions (root: 00A1B2C3)

── doc-b.docx ──
  kind               Docx
  sha256             7b5e…e811
  size               14219 bytes
  creator            Bob Auditor
  application        Microsoft Word 2021
  rsids              3 sessions (root: 00A1B2C3)

── attribution ──
 0.70  doc-a.docx  ↔  doc-b.docx
        +0.50  shared rsidRoot = 00A1B2C3
        +0.10  application = "Microsoft Word 2021"
        +0.10  2/5 session IDs overlap (Jaccard 0.40)
```

A score ≥ 0.60 is worth a manual look; ≥ 0.80 is strong evidence of
shared origin.

## Signals

| Signal | Weight | Source | What it tells you |
|---|---|---|---|
| **RSID root match** | up to 0.50 | docx `word/settings.xml` → `<w:rsidRoot>` | Two docs were authored on the same Word installation. Rare false positives — RSIDs are 32-bit random values assigned per edit session. |
| **RSID overlap** (non-root) | up to 0.25 | docx `<w:rsid>` list | Scaled by Jaccard similarity of the session-ID sets. More shared sessions = tighter correlation. |
| **PDF /ID match** | 0.40 | PDF trailer `/ID` first token | Stable creation-time ID. A match means "same original PDF", even after subsequent saves rotate the second token. |
| **Creator match** | 0.20 | `dc:creator` / PDF `/Author` | Case-insensitive. "Jane Analyst" matches "JANE ANALYST". High false-positive rate for common names; weight kept moderate. |
| **Application match** | up to 0.10 | `<Application>` / PDF `/Producer` | Trimmed when generic ("Microsoft Office Word") — full weight only if the string includes a version digit. |
| **Company match** | 0.15 | docx `<Company>` | Only populated on domain-joined Office installs. Rare signal, stronger than creator when present. |

Total scores are **capped at 1.0** — stacking every signal doesn't
multiply past certainty.

## Library use

```rust
use siphon_core::forensics::{compare, extract_metadata};

let a = extract_metadata("doc-a.docx".as_ref())?;
let b = extract_metadata("doc-b.docx".as_ref())?;

let score = compare(&a, &b);
if score.total >= 0.60 {
    for signal in &score.signals {
        println!("  +{:.2}  {}  {:?}", signal.weight, signal.detail, signal.kind);
    }
}
```

`FileMetadata` serializes via serde, so the score + metadata records
drop straight into JSON / `evidence.json` pipelines.

## What's extracted

### OOXML (docx / xlsx / pptx)

From `docProps/core.xml`:
- `dc:creator` → `creator`
- `cp:lastModifiedBy` → `last_modified_by`
- `dc:title`, `dc:subject`, `dc:keywords`
- `dcterms:created`, `dcterms:modified`

From `docProps/app.xml`:
- `<Application>` → `application`
- `<Company>` → `company`
- everything else lands in `raw["app:<tag>"]`

From `word/settings.xml` (docx only):
- `<w:rsidRoot>` → `rsids[0]`
- `<w:rsid>` list → remaining entries

### Legacy binary Office (doc / xls / ppt)

Pre-2007 Office files are OLE Compound Files. Two well-known
internal streams carry metadata:

From `\x05SummaryInformation`:
- Author (PID 0x04) → `creator`
- Title (0x02) → `title`
- Subject (0x03) → `subject`
- Keywords (0x05) → `keywords`
- Last Author (0x08) → `last_modified_by`
- AppName (0x12) → `application`
- CreateTime / LastSaveTime → `created_at` / `modified_at`
  (FILETIME ticks → ISO-8601)

From `\x05DocumentSummaryInformation`:
- Company (0x0F) → `company`
- Manager (0x0E) → `raw["ole:Manager"]`

Anything else the streams carry (VT_LPSTR / VT_LPWSTR / VT_FILETIME
values keyed by unknown property IDs) lands in
`raw["ole:summary:<pid>"]` or `raw["ole:docsummary:<pid>"]` for
manual review.

### PDF

From the `/Info` dictionary:
- `/Author` → `creator`
- `/Title`, `/Subject`, `/Keywords`
- `/Producer` → `application`
- `/Creator` → `raw["pdf:Creator"]` (authoring-tool, distinct from producer)
- `/CreationDate`, `/ModDate` — normalised from `D:YYYYMMDDHHMMSS±HH'mm'` to ISO-8601

From the trailer:
- `/ID` array → `pdf_doc_id` (two lower-case hex tokens: creation, current)

From the XMP metadata stream (`/Root → /Metadata`):
- `xmp:CreatorTool` → fills `application` if the Info dict left it empty
- `xmpMM:DocumentID` → `raw["xmp:DocumentID"]` — UUID minted at
  first save, persists across every edit. Strongest attribution
  signal when the Info dict has been stripped.
- `xmpMM:InstanceID` → `raw["xmp:InstanceID"]` — UUID that rotates
  every save.
- `dc:title` / `dc:creator` / `dc:subject` → fill the matching
  first-class field if the Info dict didn't populate it. The Info
  dict always wins when both sources disagree.
- All other XMP tags land in `raw["xmp:<tag>"]`.

Structural RDF nodes (`rdf:Description`, `Bag`, `Seq`, `Alt`, `li`,
etc.) are skipped so the `raw` dump stays readable.

## Limits

- **Generic producer strings are down-weighted**, not suppressed —
  "Microsoft Office Word" still contributes ~0.04. If your corpus
  is 100% Office docs, expect a small baseline score between every
  pair.
- **Scanner output and forensics output are independent.** Running
  `siphon forensics` doesn't invoke the PII pipeline; running
  `siphon scan` doesn't capture metadata. Invoke both when you
  need both.
- **OLE property-set decoding covers the types Office actually
  emits** (VT_LPSTR, VT_LPWSTR, VT_FILETIME). Custom properties
  using exotic types (VT_BLOB, VT_CF) are skipped rather than
  guessed at.

## Tests

- `crates/siphon-core/src/forensics/tests.rs` — 17 unit tests
  covering every extractor arm (docx / PDF Info dict / PDF XMP /
  legacy .doc OLE), attribution signal, and edge case
  (malformed zip / OLE / PDF, missing entries, XMP doesn't
  override populated Info fields, case-insensitive creator match,
  score cap at 1.0, order-independence).
- `tests/forensics_test.rs` — 5 integration tests exercising the
  public `extract_metadata` API against synthetic docx + .doc OLE
  files built on disk, verifying JSON serialization round-trips,
  and the shared-rsidRoot attribution case end-to-end.

CI runs both under the `forensics` feature in
`.github/workflows/ci.yml`.
