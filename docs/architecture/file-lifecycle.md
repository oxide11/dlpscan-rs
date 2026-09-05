# The life of a file

*What happens, in order, to one file handed to Siphon — every gate it passes,
every test applied to it, and what each outcome means.*

This document follows a single file end to end. Where the path branches, the
branches are named. Where a step can produce a wrong answer, the wrong answer
is described, because "it finds sensitive data" is the easy half of a DLP
scanner and "it knows when it didn't look" is the half that decides whether
anyone can trust the first.

Section numbers refer to the code, not to a spec: every claim here should be
checkable against the file named beside it.

---

## 0. The file

Take a concrete one. An employee attaches `Q3-forecast.xlsx` to an external
email. It is a real Excel workbook, 240 KB, three sheets. The first two hold
charts and regional summaries. The third is called `Raw` and was pasted in
from an export nobody remembered to delete; column D holds 1,800 customer
card numbers.

Everything below is what stands between that file and the internet.

---

## 1. Arrival — four doors, four different contracts

Siphon has four ingress points, and they differ in one respect that matters
more than any other: **what happens when the scanner cannot answer.**

| Door | Component | On "cannot answer" |
|---|---|---|
| CLI | `siphon scan` | non-zero exit |
| HTTP file upload | `siphon-fs` | file reported **not scanned**, never clean |
| SMTP | `siphon-milter` | verdict `indeterminate` → 451, MTA retries |
| Proxy (ICAP) | `siphon-icap` | pass through or block, per `SIPHON_ICAP_ACTION` |

Our file arrives at the milter. Postfix holds the message open on a socket
and asks a question it will not proceed without an answer to.

### 1.1 The milter session

`crates/siphon-milter/src/main.rs`. One TCP connection carries many messages.
Before any content arrives:

1. **Peer check.** The connecting address is matched against
   `SIPHON_MILTER_ALLOWED_NETS`. This is required with no default — a filter
   that accepts connections from anywhere is one anybody can feed mail to.
   Outside the allowlist, the connection is dropped immediately, before a
   byte of protocol is read.
2. **Connection cap.** `SIPHON_MILTER_MAX_CONNECTIONS` (256) bounds
   concurrency; extras are dropped rather than queued.
3. **Option negotiation.** The MTA and the filter agree on which protocol
   stages are exchanged and which modifications the filter may make.

Then, per message: macros (including the queue id), connect/helo, the
envelope sender, each recipient, each header, end-of-headers, body chunks,
and finally end-of-message — which is the only point at which a verdict is
required.

Two limits apply while the body streams in:

- **`SIPHON_MILTER_MAX_MESSAGE_BYTES`** (30 MB) bounds what is accepted at
  all.
- **`SIPHON_MILTER_TIMEOUT_SECS`** (10) bounds how long the scan may take.
  The number is not arbitrary: it is roughly 4× the worst contended message
  and 40× the mixed-flow p99 measured in `docs/architecture/email-dlp.md`
  §4.5.

Exceeding either yields `indeterminate`, which under the default policy is a
451 and a retry — not a delivery.

> **The MTA gets the last word.** If Postfix is configured
> `milter_default_action = accept`, it fails *open* when the filter times
> out, regardless of anything Siphon decides. Under Siphon's default policy
> the MTA needs `milter_default_action = tempfail`. A disagreement here is a
> silent bypass, and it is configured in a different file by a different
> person, which is exactly why it is called out in the module docs.

### 1.2 The message becomes parts

`crates/siphon-core/src/mime/`. The raw bytes are walked into a part tree:
containers, text parts, attachments. Our file surfaces as one
`PartKind::Attachment` with `filename: "Q3-forecast.xlsx"` and a decoded byte
buffer — base64 having already been undone by the MIME walk, which is not a
detail: an attachment that reached the scanner still encoded was a live
bypass, and the message came back clean.

If the walk itself gives up — a part ceiling hit, a truncated boundary — it
records a **structural warning**. That warning is attached to no part,
because the content it describes was never enumerated, and it alone forces
the whole message to at least `indeterminate` no matter how clean every part
we *did* see turned out to be.

### 1.3 The envelope is indexed once

Before any part is scanned, `parsed.envelope_index()` builds one
Aho-Corasick hit index over the message's headers and sibling parts.

This is a performance property with a correctness consequence. Context
keywords may legitimately be corroborated by the *envelope* — a subject line
reading "employee tax forms" is evidence about an attachment's contents. Done
naively, that means re-scanning the whole message for every part: O(parts ×
message). Measured, that was 400 parts taking 28.1 seconds. Indexed once and
range-filtered per part, the same message takes 813 ms — 34.6× — and per-part
cost goes flat at ~2 ms.

---

## 2. Admission control — before anyone tries to read it

Each part is now a filename and a byte buffer. Three caps apply, and they are
deliberately different numbers, which trips people up:

| Cap | Value | Owner | What it protects |
|---|---|---|---|
| `SIPHON_FS_BODY_LIMIT_MB` | 100 MB | siphon-fs | the HTTP layer |
| `MAX_EXTRACT_SIZE` | 100 MB | `src/extractors.rs` | the extractor |
| `MAX_INPUT_SIZE` | **30 MB** | `crates/siphon-core/src/validation.rs` | the scanner |

The scanner's cap is the smallest, and the gap between them is a real state:
a file can be accepted, fully extracted, and *then* found to exceed the
scanner limit. That is not an error and it is emphatically not "clean" — it
is reported as `TEXT_EXCEEDS_SCANNER_LIMIT` with the file marked **not
scanned**. A 40 MB archive of text is inspected right up to the moment it
isn't, and the caller is told which.

Our 240 KB workbook passes all three without comment.

---

## 3. Identification — what is this file, actually?

`src/extractors.rs`, `extract_text_with_policy`.

This is the step where a scanner is most easily lied to, so it is worth being
precise about what evidence exists and how much each piece is worth.

| Signal | Cost to forge | Strength |
|---|---|---|
| Filename extension | free — `mv` | weakest |
| Declared MIME type | free — one header | weak |
| Magic bytes at offset 0 | cheap, but must not break the real parser | medium |
| A reader actually parsing it | expensive: you must build a valid file | strongest |

Siphon used to dispatch on the extension, consulting magic bytes only as a
fallback for extensions it did not recognise. That let the weakest signal
decide, which meant it *gated* detection:

```
zip -q payload.zip secrets.txt
mv payload.zip notes.txt
```

The deflated archive went to the plain-text reader, which read compressed
bytes as lossy UTF-8, found nothing, and returned a faithful clean result
**with no warning of any kind**. Two commands, complete bypass, confirmed for
zip, docx, 7z, sqlite and pdf and for every extension in the text family.

`FUTURE.md`'s corroboration entry already stated the rule for this shape of
problem — *an attacker-controlled signal may weight a decision, it must never
gate it*. A filename is metadata. So the bytes now lead and the name
corroborates:

| Evidence | What happens |
|---|---|
| **Agree** | The extension refines the family. Within a proven ZIP, `docx`, `odt` and a plain archive are byte-identical at offset 0, and the name is the only thing that separates them — so it still has a job, as corroboration rather than as a claim taken on trust. |
| **Disagree** | The content decides the reader, and the disagreement is recorded. It is a finding in its own right, not a mistake to correct in silence. |
| **Content proves nothing** | The extension is used, exactly as before. Text has no signature, so this is the common path, and it does not move. |

### 3.1 Signatures are themselves weighted

The same discipline applies one level down, because a sniffer that acts on
weak evidence becomes its own bug.

- **BMP**'s entire signature is the two ASCII bytes `BM`. Every CSV whose
  first column begins "BM…" carries it. So it is accepted only when the
  4-byte little-endian size field behind it *also* equals the real file
  length — two independent facts agreeing. Without that, a spreadsheet of car
  models gets dispatched to an image decoder and read as nothing.
- **SQLite** is matched against its full 16-byte `SQLite format 3\0`, not the
  leading `SQLite`, which is a word plenty of documentation starts with.

`sniff_family()` is the single signature table, and `detect_and_extract()`
dispatches off it rather than keeping a second copy. That is not tidiness:
both decide dispatch, and two copies drift. The one that used to live in
`detect_and_extract` already had — it accepted 6 of SQLite's 16 bytes, and it
knew nothing about images at all, so a PNG was reachable only through its own
extension.

### 3.2 The lie is itself the signal

A contradiction is recorded in `metadata["format_mismatch"]` and logged at
warn level with structured fields. Deliberately **not** in `warnings`, which
means "content we did not read" and makes the milter defer — a renamed file
that we then read correctly *was* read, and conflating the two would defer
every message carrying a misnamed attachment.

What to do about it is a policy, because both answers are defensible. A
misnamed file is the shape of deliberate exfiltration; it is also what a
badly written export job produces.

| `SIPHON_ON_FORMAT_MISMATCH` | Behaviour |
|---|---|
| `flag` (default) | Read by content, record it, carry on. Cannot cause an outage. |
| `reject` | Refuse the file — extraction returns `Err`, so the CLI exits non-zero, siphon-fs marks it not scanned, and the milter defers. No service has to learn a new signal. |
| `ignore` | Read by content, record nothing. The bypass stays closed either way; only the reporting is suppressed. |

Our workbook is honestly named. `sniff_family` proves ZIP, `declared_family("xlsx")`
claims ZIP, they agree, and the extension refines it to the OOXML reader.
Nothing is recorded.

---

## 4. Extraction — turning a container into text

`extract_zip_archive`. For an XLSX the reader:

1. Detects the OOXML flavour by looking for a `xl/` prefix among the entries.
2. Selects the parts worth reading: `xl/worksheets/*.xml` and
   `sharedStrings`. Not everything in the container — a `.docx`'s theme XML
   is not content.
3. Applies four independent resource guards per entry, because an archive is
   attacker-controlled and a scanner that OOMs is a scanner that is off:

   | Guard | Value |
   |---|---|
   | Entries read | 10,000 |
   | Per-entry uncompressed size | 100 MB |
   | Total uncompressed | 500 MB |
   | Compression ratio | 100:1 |

   The ratio check exists on top of the size caps because without it a
   10,000:1 file burns CPU during streaming right up to those caps.

4. Strips XML tags to recover the text.

### 4.1 Where the text comes from decides what is found

Step 4 is not the formality it looks like. `strip_xml_tags` had, until
recently, an empty `if` block where the separator belonged — a comment
reading "Add space between text from different tags" sitting above no code at
all. Adjacent text nodes were glued together, and it failed in both
directions at once, which is why it survived so long:

- The `SSN` header cell glued to the value below it reads `SSN219-09-9999`,
  which matches no pattern. **A missed detection.**
- Two unrelated 8-digit columns read as `4111111111111111`, which passes
  Luhn. **A fabricated detection**, for a card number appearing nowhere in
  the sheet.

The fix could not be a blanket separator, because the two cases pull opposite
ways. Inside a paragraph, XML element boundaries are meaningless — Word
splits a single word across `<w:r>` runs on nothing more than an edit, so
`<w:t>4111</w:t><w:t>111111111111</w:t>` is one card number and joining the
runs is the only way to see it. Between cells, adjacent values are genuinely
separate.

So `XML_BREAK_TAGS` names the elements that are boundaries in the *document*
— paragraph, row, cell, list item, line break, across OOXML, OpenDocument and
HTML — and only those emit a newline. Newlines then survive the whitespace
collapse, because a space would not have been enough: most value patterns
tolerate one internal separator, so space-joined cells would still read as a
single card.

Our `Raw` sheet now yields one value per line.

### 4.2 The contract every extractor owes its caller

`ExtractionResult` carries `text`, `format`, `metadata` and `warnings`. The
last is the load-bearing one:

> **A warning means: content exists here that this pass did not read.**

That is what lets a caller fail closed. The milter treats a part as
uninspected when `warnings` is non-empty or `format == "unparsed"`, and an
uninspected part cannot reconcile to clean.

The failure mode this guards against is an extractor that returns `Ok("")`
for a file it could not parse. Then the scanner reports "no findings" for
content nobody read, and the CLI's exit code, siphon-fs's response and the
milter's verdict all inherit that. Every one of them says *clean* about a
file none of them opened.

This is not hypothetical; it has been the shape of several real bugs here:

- PDFs were never parsed at all — extraction fell back to raw bytes and
  returned `Ok`, so a caller could not tell a parse from a fallback.
- An image with no barcode came back as `Err(NotFoundException)` from `rxing`,
  indistinguishable from a corrupt image, which made every photo look like an
  unread attachment — enough, under the fail-closed mail policy, to defer
  every message carrying one.
- `rxing`'s file helper picks an image decoder from the **file extension**,
  so a PNG named `.txt` failed even once dispatch had correctly identified it
  as an image — the same misplaced trust in the filename, one layer further
  down.

The `damaged` slot of the conformance matrix (§8) exists to ask this of every
format on every run.

---

## 5. The scan — ten stages over the extracted text

`crates/siphon-core/src/scanner/mod.rs`, `scan_text_with_config`.

### Stage 1 — Input validation

`validate_text_input`. Empty input is an error, not a clean result. Over
`MAX_INPUT_SIZE` (30 MB) is `InputTooLarge`.

The empty case matters more than it sounds: an extractor that faithfully read
a file containing no text has found nothing, which is not the same as a scan
error. The milter handles that explicitly — a faithful extraction yielding no
text is recorded as scanned-clean rather than handed to the scanner, because
handing it on would come back as an error and count the part uninspected,
deferring every message with a photo in it.

### Stage 2 — Normalization

`crates/siphon-core/src/normalize/`. This is where evasion is defeated, and
it is the stage most likely to surprise you, because it rewrites the text
before any pattern sees it while keeping an **offset map** so reported spans
still point at the original bytes.

There is a fast path first: pure ASCII with no evasion markers is returned
untouched.

Otherwise, in order — the numbering is the code's, and the lettered stages
are why the "10 stages" in CLAUDE.md is really fifteen:

| # | Stage | Defeats |
|---|---|---|
| 1 | URL percent-decode, two passes | `%34%31%31%31`, and double-encoding |
| 2 | HTML decimal entity decode | `&#52;&#49;&#49;&#49;` |
| 3 | Strip empty comments | `41/**/11`, `41<!---->11` |
| 4 | Hex-spaced byte sequences | `34 31 31 31` |
| 4b | `\xHH` escapes | `\x34\x31` |
| 4c | Token-level base64 / base32 / hex decode | an encoded payload in a field |
| 5 | Collapse padding between non-alpha chars | `4 1 1 1` |
| 6 | Normalise excessive delimiters | `4---1---1---1` |
| 6b | Strip delimiters between alphanumeric neighbours | `4.1.1.1` |
| 6c | Strip a *consistent* separator between digit groups | `219 09 9999` |
| 7 | Strip zero-width characters | 39 invisible code points |
| 8 | Normalise exotic whitespace | 16 Unicode spaces |
| 9 | NFKC | full-width digits, ligatures |
| 10 | Homoglyph map + Unicode-digit fallback | Cyrillic `А`, Greek `Ο` |
| 11 | Fold digit-confusable letters | `O`→`0`, `l`→`1` |

Stages 7–11 run only if non-ASCII survives that far.

Two design notes worth carrying:

- **Stages report "unchanged" as `None`.** The offset map is one `usize` per
  input byte — 8× the size of the text. A stage that cloned it merely to
  report no change cost ~9 MB of memcpy per megabyte scanned; across 13
  stages and 19 bail-out points, normalising 1 MB of ordinary text allocated
  ~130 MB, and a max-size input extrapolated to ~1.3 GB of transient
  allocation for a single scan. That is an OOM surface under concurrent load,
  not merely slow.
- **Whitespace collapse has a cost.** It is what defeats a whole class of
  separator evasion, and it is also why two adjacent 8-digit spreadsheet
  cells still read as one card even now that the extractor separates them
  with a newline. That trade is recorded as a documented gap rather than
  quietly fixed, because the fix is not local (§8).

### Stage 3 — Pattern narrowing

583 patterns across 128 categories. Three filters run before any regex does:

1. **Category filter** — `ScanConfig.categories`, if set.
2. **`baseline_only`** — the ruleset's baseline subsets (`pci`, `pii`, `phi`,
   …).
3. **The Aho-Corasick context prefilter**, consulted *early*. A
   context-gated pattern whose keywords appear nowhere in the text or the
   envelope is dropped before it ever compiles into the run.

That third one is the pipeline's largest throughput win, and it is stage 6's
index being used at stage 3.

### Stage 4 — Parallel per-pattern match

Every surviving pattern runs as its own `Regex` under rayon
(`active_patterns.par_iter()`).

There is **no `RegexSet` and no two-phase match**. The module doc and
CLAUDE.md both claimed there was, for a long time, and neither was ever true.
A `RegexSet` phase 1 was then measured, in case the doc described something
worth building:

- The 583 patterns exceed the regex crate's default 10 MB compile limit
  outright (`CompiledTooBig`); a set needs `size_limit` raised to 64 MB
  before it will build at all.
- It would cut cold start from ~310 ms to ~223 ms, but add ~3.5 ms per
  document — seven times the entire current steady-state scan of ~0.47 ms.

Wrong trade for a long-lived service, which pays startup once and per-document
cost forever. (For the record on cold start: it is regex compilation at
296.9 ms, not the Aho-Corasick automaton, which is 13.5 ms — 4%.)

The engine is the `regex` crate, which has no backreferences and therefore no
catastrophic backtracking. That is a security property, not a preference:
attacker-controlled input reaching a backtracking engine is a denial-of-service
primitive. It is why `fancy-regex` is flagged as a component in the SBOM
wherever it appears.

Column D of our `Raw` sheet produces 1,800 candidate spans from the Visa
pattern.

### Stage 5 — Checksum validation

`crates/siphon-core/src/validation.rs`, `validate_match(category,
sub_category, matched_text)` — about 70 dispatch arms: Luhn, mod-97 IBAN,
Verhoeff, Base58Check, Bech32, ISO 3779 VIN, SWIFT country codes, CUSIP,
SEDOL, Australian TFN, and so on.

This is the difference between "sixteen digits" and "a card number". Of the
1,800 candidates, the ones that are order references or serial numbers fail
Luhn and are dropped here.

With the `bin-data` feature, card BINs are additionally looked up against
374k issuer prefixes. Note the asymmetry: an **unknown** BIN is still
accepted, because issuers are added faster than any bundled table is
refreshed. A known BIN gets issuer and country metadata attached instead.
Validation is used to reject what is provably wrong, not to accept only what
is provably known.

### Stage 6 — Context checking

`crates/siphon-core/src/context/`. An Aho-Corasick automaton over 5,000+
keywords in six languages.

For each candidate, a window of ±50 characters by default (per-category
distances override it) is checked for a keyword belonging to that
`(category, sub_category)`. The hit index makes this a range lookup rather
than a scan.

Patterns marked `context_required` are the loose ones — a bare nine-digit
number is not evidence of anything by itself — and they are dropped entirely
when no keyword is nearby.

Context may also come from the **envelope** rather than the local text, which
is what §1.3's shared index is for, and it is scored differently (below)
because it is weaker evidence.

### Stage 7 — Confidence scoring

`crates/siphon-core/src/scoring.rs`. Each pattern has a base specificity;
context adjusts it:

| Situation | Score |
|---|---|
| Local context found | `min(specificity + 0.20, 1.0)` |
| Envelope context only | `min(specificity + 0.10, 1.0)` |
| No context, and not required | `specificity` |
| No context, and **required** | `specificity × 0.3` |

The envelope boost is half the local one deliberately. A subject line is
evidence about an attachment, but weaker evidence than the words immediately
around the value — and confidence is what a reviewer's `min_confidence`
threshold filters on, so the difference has to be expressible.

The last row is worth reading twice: a context-required pattern that finds no
context is not deleted, it is *heavily discounted*. It survives to be filtered
by threshold rather than silently discarded, which keeps the decision in the
operator's hands.

### Stage 8 — Deduplication

`deduplicate_overlapping`. Overlapping spans collapse to one, by these
tiebreakers in order:

1. Higher confidence wins.
2. At equal confidence, a **context-gated match with its context satisfied**
   beats an ungated one. When an analyst writes `carte assurance maladie
   TREM85120123`, the Quebec health-card pattern (specificity 0.55, gated)
   boosts to 0.75 and ties ISIN's raw 0.75 — but the gated match is strictly
   more informative, because the surrounding prose corroborates it. Without
   this rule, ISIN silently shadows every RAMQ card.
3. Then higher base specificity — which stops `JWT Token` (0.95) being
   swallowed by a nested `Bearer Token` (0.80) when both clamp to 1.0 in an
   `Authorization` header.
4. Then the longer match.

### Stage 9 — Override application

`crates/siphon-core/src/overrides.rs`, applied from a `LiveOverrides`
snapshot: disabled patterns, regex overrides, match-list bindings
(allow/block/mask/tag) and unique-count thresholds.

The snapshot is an `Arc<RwLock<…>>` cloned per request, so
`POST /v1/overrides/apply` swaps policy without a restart — an operator
drowning in a false positive at 3am does not need a deploy.

### Stage 10 — Emission

Sorted by confidence. Each `Match` carries text, category, sub_category,
confidence, span offsets **into the original text**, and metadata.

Two redaction views exist because two audiences do: `redacted_text()` shows
first 3 and last 3 characters — enough for an analyst to recognise a value
they already know — while `masked_text()` shows nothing.

This is also why the reported span is the *pre-normalization* one. When a
value arrived base64-encoded, `Match::text` is the base64, not the decoded
card. That looks wrong until you remember what the span is for: a redactor
has to overwrite the bytes that are actually in the document.

---

## 6. What happens to the findings

Our workbook has produced roughly 1,700 Visa findings at high confidence.

### 6.1 The verdict (mail path)

Each part gets a `PartOutcome`, and `siphon_mail::reconcile()` folds them into
one message verdict along a ladder:

```
Clean < Indeterminate < Flagged < Quarantine < Block
```

The ladder has one definition, in `crates/siphon-mail`, shared between the
milter that writes the rows and the API that reads them back — which is the
entire reason that crate exists as a library.

`Indeterminate` sitting *above* `Clean` is the fail-closed property in one
line: a message with one unreadable part and nine clean ones is not clean.

Our message reconciles to `Flagged`. Under `SIPHON_MILTER_ON_INDETERMINATE`
the milter stamps verdict headers and lets the MTA's own rules act — annotate,
don't block (`docs/architecture/email-dlp.md` §1). The scanner's job is to be
right about what is in the message; the MTA's job is to decide what that
means for delivery.

### 6.2 Persistence

`messages` and `message_parts` rows are written via `crates/siphon-mail`. Two
schema properties are load-bearing:

- `UNIQUE (message_uuid, mime_path)` makes an MTA retry **upsert** rather than
  duplicate. MTAs retry; this is normal, not exceptional.
- A partial unique index on `(tenant_id, ingest_key)` is what lets a
  redelivery resolve to the *same* `message_uuid` in the first place. This is
  also why `messages.tenant_id` is `NOT NULL DEFAULT 'default'` where
  scans/findings allow NULL — it participates in that index, and NULL never
  equals NULL.

On the API path, `persist_scan` is idempotent on `scan_id` — `ON CONFLICT (id)
DO NOTHING` — and **never on content**. An earlier content-hash window dropped
genuinely distinct scans, including across tenants. Two people sending the
same card number is two events.

### 6.3 Audit

`crates/siphon-core/src/audit.rs` appends to a tamper-evident HMAC-SHA256
chain when `SIPHON_AUDIT_SIGNING_KEY_HEX` is set, plus an in-memory ring
buffer.

`SIPHON_AUDIT_LOG_PATH` is **required to start in production** — an in-memory
ring is not a durable audit trail — and startup is refused without it unless
`SIPHON_DEV_MODE=true`.

### 6.4 Counters

Clean scans store no findings row, so counting findings tells you nothing
about how much traffic was inspected. `scan_rollup` carries aggregate counters
per (hour, tenant, channel), flushed every `SIPHON_ROLLUP_FLUSH_SECS`. A pod
killed mid-window loses at most that much *counting*; findings are unaffected.

`GET /v1/stats/throughput` is the denominator side of every detection metric.

---

## 7. The four ways a file can come back "clean"

This is the section to reread. All four print the same thing to a user, and
they mean entirely different things.

| # | Meaning | How you can tell |
|---|---|---|
| 1 | **Read in full, nothing in it.** | `warnings` empty, `format` is a real reader, text non-empty. |
| 2 | **Read in full, and there was no text.** An image with no barcode; an empty part. | `warnings` empty, text empty. Genuinely inspected. |
| 3 | **Not read — and it said so.** Corrupt archive, unparseable PDF, exceeded the scanner cap. | `warnings` non-empty, or `format == "unparsed"`, or `Err`. Never reconciles to clean on the mail path. |
| 4 | **Not read, and it did not say so.** | *There is no signal.* This is the bug class. |

Everything in §4.2 exists to keep row 4 empty. The `damaged` slot of the
conformance matrix is the standing test that it stays that way.

---

## 8. How this is kept true

`scripts/conformance.sh` asks the same five questions of every capability
Siphon advertises:

| Slot | Question |
|---|---|
| `clean` | Well-formed, nothing sensitive: does it read, and stay quiet? |
| `single` | One planted value in the obvious place: is it found? |
| `structural` | One planted value where the format lets you hide it — a second sheet, a later archive entry, an attachment |
| `damaged` | Truncated or corrupt: does the reader **say so** rather than report a faithful clean read? |
| `evasive` | A format-specific bypass — encoded body, nested container, split value |

Plus a `disguise` capability that is not a format at all but the arbitration
*between* formats (§3), asserting both directions: content must win when the
name lies, and stay out of the way when the name is honest.

Coverage is enforced — anything in `supported_extensions()` that is neither
covered nor listed in `KNOWN_GAPS` with a reason fails the run. Gaps are
declared rather than hidden: a case wrapped in `gap(...)` keeps its
expectation as written, does not fail the build, and prints its reason on
every run; if it starts passing, that is reported too, so the entry gets
removed rather than outliving the bug it described.

Three gaps stand today, and they are all on this path:

- **`json/evasive`** — `\uXXXX` escapes are not decoded by the normalizer, so
  a value spelled that way in a first-class input format passes through
  unread.
- **`mbox/damaged`** — a malformed `From ` line yields zero characters with
  no warning. That is row 4 of §7, and the one place it is currently
  reachable.
- **`xlsx/evasive`** — whitespace normalization collapses the cell separator
  from §4.1, so two adjacent 8-digit cells still read as one card. Recorded
  rather than fixed, because the fix is not local: that normalization is what
  defeats a whole class of evasion.

---

## Appendix: the same file through the other three doors

**CLI** (`siphon scan Q3-forecast.xlsx`) — §3 through §5 unchanged. Output is
formatted per `--format {text,json,csv,sarif}`, filtered by
`--min-confidence` and `--categories`. Exit code carries the verdict.

**siphon-fs** (`POST /scan`, multipart) — bearer auth first
(`SIPHON_API_KEY`; the service refuses to start without one), then rate
limiting per IP *and* per key, then the body/per-file caps of §2, then §3–§5.
The response reports findings *and* per-file warnings, so a caller can
distinguish §7's rows 1 and 3. Note siphon-fs serves no TLS of its own — it
relies on the mesh, and emits no HSTS header, because HSTS over plaintext is
ignored per RFC 6797.

**siphon-icap** (`RESPMOD`/`REQMOD` on port 1344) — peer allowlist
(`SIPHON_ICAP_ALLOWED_NETS`, required), then the body cap
(`SIPHON_ICAP_MAX_BODY_BYTES`, 10 MB — **larger bodies pass through
unscanned**), then §3–§5. `SIPHON_ICAP_ACTION` decides between annotate and a
403 to the proxy, above `SIPHON_ICAP_MIN_CONFIDENCE`.

That pass-through-when-too-large is the one door that fails *open* by default,
and it is worth knowing which one it is.
