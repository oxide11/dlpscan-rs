# One inspection outcome for every ingress

Status: **type and `scan_text_inspected` landed in siphon-core; ingress adoption pending** (2026-10-15).
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

### 2. CLI (`src/pipeline`, `src/main.rs`) — after PR #494 merges

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

### 3. siphon-fs

`ScanResponse.scanned: bool` becomes `inspection.is_complete()`, and an
`inspection` object joins the response beside `warnings`. The three cases
that disagree today converge: extractor `Err` → `Incomplete(ReadError)`
with HTTP 200 (today: 200, `scanned:false`); empty text with warnings →
`Incomplete` (today: `scanned:true`); oversize text → `Incomplete(Oversize)`
with the existing 422. `format_mismatch` finally reaches the caller, as a
typed reason instead of a metadata key that is never serialised.

### 4. siphon-icap

`unscannable_verdict(reason: &str)` takes an `Inspection`; `body_truncated`
is `Unread::Truncated { unit: "body" }`, `looks_binary` is
`Unread::Unsupported { unit: "body" }`, and `X-DLP-Reason` carries
`describe().join("; ")`. The `Unscannable { Pass, Block }` policy enum
stays — it is the *decision*, which this document leaves alone.

### 5. siphon-smtp / siphon-mail

`siphon_mail::Inspection` becomes a re-export of the core type;
`PartStatus → Unread` is a one-arm-per-variant mapping
(`SkippedOversize → Oversize{unit: "part <path>"}`, `SkippedEncrypted →
Encrypted`, `SkippedNestedArchive → NestedArchive`, `SkippedUnsupported →
Unsupported`, `Error → ReadError`). `policy::action_for` is unchanged: it
already takes an inspection and a verdict separately, which is the design
the rest of the workspace is converging on.

### 6. Delete what it replaced

`ExtractionResult.warnings`, `ScanResponse.scanned`, the ICAP reason
strings, and `metadata["format_mismatch"]`. The `TruncationSink` stays as
the mechanism inside core; `scan_text_inspected` is its only consumer.

## What this does not do

- It does not choose the action. Deliver / defer / block / exit code are
  ingress policy and stay where they are.
- It does not make an extractor read more. An Office extractor that reads
  three XML trees still reads three; it now *says* it left the rest.
- It does not replace the conformance matrix's `damaged` slot; it is what
  that slot will assert on once step 2 lands (`inspection.is_complete()`
  must be `false` for every damaged fixture, which is a sharper test than
  "no clean read").
