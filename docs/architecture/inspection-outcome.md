# One inspection outcome for every ingress

Status: **complete.** Type landed in siphon-core (2.11.0); CLI (step 2, siphon-cli 2.6.0), siphon-fs (step 3, 1.6.0), siphon-icap (step 4, 0.4.0) and siphon-smtp/siphon-mail (step 5, 0.3.0 / 0.2.0) adopted; the mechanisms they replaced deleted (step 6, siphon-cli 2.7.0 / siphon-fs 1.7.0 / siphon-smtp 0.3.1) on 2026-10-16.
Companion to `siphon_core::inspection` (the code) and the "Security audit
log" in `BACKLOG.md` (the incidents).

## The problem, stated once

A scanner that returns zero matches has answered one of two questions:

1. "I read all of it and found nothing."
2. "I found nothing in the part I managed to read."

Between 2026-09-03 and 2026-10-15 nine audit rounds each found an ingress
giving answer 2 in the voice of answer 1:

| Date | Surface | What answered clean for content nobody read | Fixed with |
|---|---|---|---|
| 09-03 | CLI zip | a `.zip` of a `.txt` extracted to nothing | walk text entries |
| 09-03 | CLI archives | nested / encrypted entries skipped in silence | warning strings |
| 09-03 | siphon-fs | empty text dropped the nested-archive warning | merge warnings |
| 09-04 | siphon-fs | oversize text came back as a generic error | 422 + "not scanned" |
| 09-04 | CLI eml | base64 attachments never decoded | shared MIME layer |
| 09-07 | siphon-icap | over-limit remainder drained, partial scan, no record | `truncated` flag |
| 09-07 | siphon-smtp | unfaithful extraction treated as inspected | `PartStatus::Error` |
| 09-07 | CLI | zip renamed `.txt` read as text, faithfully clean | `format_mismatch` metadata |
| 09-09 | core / CLI | match cap produced a "redacted" output still holding values | `TruncationSink` |
| 09-09 | siphon-icap | oversize and binary bodies got the same bare 204 as clean | `Unscannable` enum |
| 09-09 | siphon-smtp | a flagged part delivered an unread part | `siphon_mail::Inspection` |
| 10-15 | CLI (#494) | extractor warnings dropped; encrypted entry printed `Matches: 0` | `PipelineResult.warnings` |

Twelve fixes, seven mechanisms: warning strings, a metadata key, a bool, an
`AtomicBool` sink, a per-crate enum, a per-crate status, and an exit code
that ignores all of them. The next round will find the path that has none.
Today that path is easy to name: `scan-dir` never sets a non-zero exit code
at all, and the CLI re-reads an extractor `Err` as plain text and reports it
clean (`src/pipeline/mod.rs:283-327`).

## The rule

`siphon-mail` already has the right shape (`crates/siphon-mail/src/lib.rs:226-248`):

> A verdict is **complete** only when every unit of content was read and
> matched. Anything else is **incomplete**. No units at all is incomplete,
> not clean.

`siphon_core::inspection::Inspection` is that rule, lifted into the crate
every ingress already depends on, with the reasons typed
(`Unread::{Oversize, Truncated, Encrypted, NestedArchive, Unsupported,
ReadError, FormatMismatch, MatchCapReached, Other}`). It is deliberately
**not** a verdict: it says what the verdict covers, and each ingress keeps
deciding what to do about a gap, because a proxy, a mail filter and a CLI
should not do the same thing.

Invariants the type holds that strings and flags could not:

- there is no way to be `Complete` and carry reasons;
- once `Incomplete`, merging in a clean member cannot undo it;
- `absorb_warnings` keeps every non-empty warning, so a producer that is
  still on strings cannot lose one on the way to the verdict.

## Adoption, in order

Each step is a PR on its own, each shrinks the per-crate mechanism it
replaces, and none changes a wire format without saying so.

### 1. siphon-core: `scan_text_inspected` — **landed with this document**

`scan_text_with_config` returns a bare `Vec<Match>`; truncation was an
opt-in `AtomicBool` only `InputGuard` read. Now

```rust
pub struct ScanOutcome { pub matches: Vec<Match>, pub inspection: Inspection }
pub fn scan_text_inspected(text: &str, cfg: &ScanConfig) -> Result<ScanOutcome>
```

installs its own sink and reports `Unread::MatchCapReached` when any cap
fired (per-pattern, total, entropy, EDM, LSH, runtime patterns — the sink is
threaded through `scan_impl`, so every cap site reports the same way). A
sink the caller installed is set alongside, never cleared.
`scan_text_with_config` is unchanged in behaviour and is now a thin wrapper.

### 2. CLI (`src/pipeline`, `src/main.rs`) — **landed, siphon-cli 2.6.0**

- `ExtractionResult` gains `inspection: Inspection`; each extractor sets
  typed reasons where it currently pushes a warning string or `continue`s
  in silence (the table in the fact-finding report lists every silent
  path: entry caps, bomb ratios, budget exhaustion, non-text members,
  Office reading only three XML trees, msg never reading attachments, rar/7z
  skipping files ≥ 1 MB and cutting content at 100k chars, parquet/sqlite
  row caps). The `warnings: Vec<String>` field stays for one release,
  populated from `inspection.describe()`.
- An extractor `Err` is `Unread::ReadError`, **not** a fall-through to
  `read_to_string`. A `SIPHON_ON_FORMAT_MISMATCH=reject` `Err` is
  `Unread::FormatMismatch`.
- `PipelineResult` gains `inspection` (serialised as
  `{"status": "complete"}` / `{"status": "incomplete", "unread": [...]}`),
  and `siphon scan` / `scan-dir` print `describe()` under
  "Unscanned content:" (#494's block).
- Exit codes: `0` complete, `1` error (unchanged), **`3` incomplete** when
  `--on-incomplete fail` is set; default `report` keeps today's `0` so no
  script breaks on the day this lands. `scan-dir` starts honouring exit
  codes at all.

Notes from landing it:

- Two silent paths are still silent, on purpose: a non-text member of a
  plain archive (an image, a binary) and the Office XML trees the extractor
  does not open. Nearly every real archive has one, and step 5's milter
  defers on any unread unit under its fail-closed default, so typing them
  here would defer ordinary mail carrying a `.png`. Each ingress has to
  decide what an unread image means before the reader reports it; that
  decision is step 6's, with the deletions.
- `FormatMismatch` under the `flag` policy goes into `inspection` but not
  into `warnings` (`ExtractionResult::note`). The file *was* read, as what
  its bytes are, so the string channel the milter still reads must not call
  it a gap. Once siphon-smtp is on the typed inspection (step 5) it will see
  the reason and `policy::action_for` decides what to do with it — which is
  the moment to say whether a misnamed attachment defers.
- An extractor `Err` still scans the raw bytes, as the old fall-through
  did, because a value that survives in them is worth reporting; the
  difference is that the verdict now says what it covers. The ADR text
  above says "not a fall-through to `read_to_string`" and means the
  *claim*, not the scan.
- `ExtractionResult.warnings` is derived from `inspection` at every write
  (`unread`, `with_unread`, `unread_within`), and `PipelineResult.warnings`
  is `inspection.describe()`. Neither is written on its own any more, so
  step 6 deletes them without a behaviour change.

### 3. siphon-fs — **landed, siphon-fs 1.6.0**

`ScanResponse.scanned: bool` becomes `inspection.is_complete()`, and an
`inspection` object joins the response beside `warnings`. The three cases
that disagree today converge: extractor `Err` → `Incomplete(ReadError)`
with HTTP 200 (today: 200, `scanned:false`); empty text with warnings →
`Incomplete` (today: `scanned:true`); oversize text → `Incomplete(Oversize)`
with the existing 422. `format_mismatch` finally reaches the caller, as a
typed reason instead of a metadata key that is never serialised.

### 4. siphon-icap — **landed, siphon-icap 0.4.0**

`unscannable_verdict(reason: &str)` takes an `Inspection`; `body_truncated`
is `Unread::Truncated { unit: "body" }`, `looks_binary` is
`Unread::Unsupported { unit: "body" }`, and `X-DLP-Reason` carries
`describe().join("; ")`. The `Unscannable { Pass, Block }` policy enum
stays — it is the *decision*, which this document leaves alone.

### 5. siphon-smtp / siphon-mail — **landed (siphon-mail 0.2.0, siphon-smtp 0.3.0)**

`siphon_mail::Inspection` is a re-export of the core type;
`PartStatus → Unread` is a one-arm-per-variant mapping
(`SkippedOversize → Oversize{unit: "part <path>"}`, `SkippedEncrypted →
Encrypted`, `SkippedNestedArchive → NestedArchive`, `SkippedUnsupported →
Unsupported`, `Error → ReadError`, `Pending → Other`), done in
`PartOutcome::unread()`. `policy::action_for` is unchanged in what it
decides: it already took an inspection and a verdict separately, which is the
design the rest of the workspace is converging on; it now borrows the
inspection, since the core type carries its reasons. The MIME walker's
warnings are absorbed as `Unread::Other` until it is typed. Nothing on the
wire or in `message_parts` changed.

### 6. Delete what it replaced — **landed, siphon-cli 2.7.0 / siphon-fs 1.7.0 / siphon-smtp 0.3.1**

Gone: `ExtractionResult.warnings`, `PipelineResult.warnings` (and the
`warnings` array in `siphon scan --format json`), `ScanResponse.scanned`
and `ScanResponse.warnings` in siphon-fs, `metadata["format_mismatch"]`,
and siphon-fs's `coverage()` re-typing extractor strings as `Unread::Other`
— the extractor's `inspection` now merges in whole, so a nested archive
arrives at the HTTP caller as `nested_archive`, not `other`. The ICAP reason
strings had already gone in step 4 (`X-DLP-Reason` is `describe()`), so
siphon-icap did not move. The `TruncationSink` stays as the mechanism inside
core; `scan_text_inspected` is its only consumer. `Inspection::absorb_warnings`
stays for the one producer still on strings, the MIME walker's structural
warnings in siphon-smtp.

Two decisions this step owed:

- **A misnamed attachment that was read does not defer.** Under the default
  `flag` policy `Unread::FormatMismatch` means the bytes were read as what
  they are and only the name lied; the verdict over that content stands.
  The milter's `extract_attachment` treats a part as faithful when its
  inspection carries no reason *other than* `FormatMismatch` (and the format
  is not `unparsed`), which is the same answer the old string channel gave
  — `note()` never wrote to `warnings` — now stated in the type rather than
  by omission. An operator who wants misnamed files refused has
  `SIPHON_ON_FORMAT_MISMATCH=reject`, which arrives as an extraction `Err`
  and defers through the ordinary path. The CLI still exits 3 on it under
  `--on-incomplete fail`, and siphon-fs reports it `incomplete`: for those
  two the reader is a person or a script that asked to be told, not an MTA
  holding ordinary mail.
- **Non-text archive members and unopened Office XML trees stay silent.**
  Typing them as `Unsupported` would be true and would defer every message
  carrying a zipped `.png` under the milter's fail-closed default, with no
  way for `policy::action_for` to tell that reason from a text part it could
  not decode — both are `Unsupported`. The honest fix is not a quieter
  reader but a reason the ingresses can treat as informational (a distinct
  variant, which is a core change) or, for the Office trees, reading more:
  cell comments, speaker notes, text boxes and embedded objects carry text,
  and an extractor that reads the slides and says nothing about the notes
  is a reading gap, not a reporting one. Both are in `BACKLOG.md`; neither belongs in a
  deletion step.

## What this does not do

- It does not choose the action. Deliver / defer / block / exit code are
  ingress policy and stay where they are.
- It does not make an extractor read more. An Office extractor that reads
  three XML trees still reads three; it now *says* it left the rest.
- It does not replace the conformance matrix's `damaged` slot; it is what
  that slot asserts on (`inspection.is_complete()` must be `false` for every
  damaged fixture, which is a sharper test than "no clean read"), and the
  `clean` slots assert the converse — a well-formed file reads `Complete`.
