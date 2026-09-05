# Email DLP — message model, context envelope, verdicts

**Status:** design, not implemented.
**Scope:** the mail path only — inbound and outbound SMTP. Everything here is
additive; no existing pod changes behaviour until the milter is built.

Siphon today ingests via HTTP (`siphon-api`), file upload (`siphon-fs`), and
HTTP proxy (`siphon-icap`). Email is the gap, and it is the channel that
matters for displacing an incumbent DLP product. This document is the design
we intend to build against, written before implementation because two of its
decisions — the context envelope and the part identifier — change APIs that
are awkward to revise later.

Volume this is designed for: **~1.5×10⁹ messages/year** (~133/sec sustained
during business hours, 400–550/sec peak) producing **~500k detections/month**
— a hit rate around 0.4%.

---

## 1. Enforcement model: annotate, don't block

Siphon does not hold or reject mail. It inspects a message and stamps a
verdict into the headers; the MTA's existing rules decide what happens next.

```
X-Siphon-Result:     clean | flagged | quarantine | block | indeterminate
X-Siphon-Categories: SSN,Credit Card
X-Siphon-Findings:   3
X-Siphon-Scan-Id:    <uuid>
```

This keeps enforcement where the mail team already manages it, and keeps
Siphon out of the delivery-critical path beyond a bounded inspection window.

`X-Siphon-Scan-Id` is not decoration. It is the join key from a quarantined
message back to the stored findings, which is what makes a quarantine review
a lookup instead of a re-scan.

> **Note:** `siphon-icap`'s flag mode is *not* reusable here. Its
> `response_flagged` writes `X-DLP-*` onto the **ICAP response to the proxy**
> and reflects the HTTP headers back untouched — it annotates the protocol
> conversation, not the message. Email requires headers written into the
> message itself, which is a milter operation.

### Transport

A **milter** (`siphon-milter`, new crate). Postfix and Sendmail both speak it,
header add/replace is first-class in the protocol, and it avoids Siphon having
to be a queueing MTA.

The milter is **synchronous**: the MTA holds the message while we decide,
under a bounded timeout (~30s typical for Postfix). Everything in §4 follows
from that deadline.

---

## 2. Message model

A message is not one scan. It is a tree of parts, each independently
scannable, whose results reconcile into one verdict.

### 2.1 MIME is a tree, not a list

Real messages nest: `multipart/mixed` wrapping `multipart/alternative`;
`message/rfc822` for a forwarded mail, which is an entire message inside a
part; a ZIP attachment that expands into fifty entries.

So parts are identified by a **MIME path** (`"1"`, `"1.2"`, `"2.1.4"`), not an
integer index. The path is stable across MTA retries, which an ordinal is not,
and it makes the parts table self-referential for archive expansion.

### 2.2 Schema

```sql
messages (
  id              UUID PRIMARY KEY,     -- internal identity
  tenant_id       TEXT NOT NULL,
  direction       TEXT NOT NULL,        -- inbound | outbound
  rfc_message_id  TEXT,                 -- indexed attribute, NOT the key
  sender          TEXT,
  recipients      TEXT[],
  subject_hash    BYTEA,
  received_at     TIMESTAMPTZ NOT NULL,
  part_count      INT NOT NULL,
  parts_completed INT NOT NULL DEFAULT 0,
  verdict         TEXT,
  verdict_at      TIMESTAMPTZ
)

message_parts (
  id             UUID PRIMARY KEY,
  message_uuid   UUID NOT NULL REFERENCES messages(id),
  parent_path    TEXT,                  -- NULL at top level; archive/rfc822 nesting
  mime_path      TEXT NOT NULL,         -- "2.1.4"
  content_type   TEXT,
  filename       TEXT,
  content_hash   BYTEA,
  scan_id        UUID,                  -- joins to scans / findings
  status         TEXT NOT NULL,         -- pending|scanned|skipped_oversize|error
  UNIQUE (message_uuid, mime_path)
)
```

**Do not key on RFC Message-ID.** It is client-supplied, forgeable, sometimes
absent, and not reliably unique. Internal UUID is the identity; Message-ID is
an indexed attribute for investigator lookup.

`UNIQUE (message_uuid, mime_path)` is the idempotency guard: an MTA retry
re-derives the same paths and upserts rather than duplicating.

### 2.2a What makes `message_uuid` the same on a retry

**Built in siphon-api 2.9.0** (`migrations/0010_messages.sql`,
`src/messages.rs`). Implementing it surfaced a gap in the paragraph above.

`UNIQUE (message_uuid, mime_path)` only guards a retry if `message_uuid` is
*the same* on that retry, and §2.2 does not say how it becomes so. Mint a
fresh UUID per delivery attempt and the constraint protects nothing: the retry
writes a whole new message with a whole new set of parts, and both survive.

That matters more than it first appears. Under the fail-closed default of
§4.4, **retries are the normal operating mode, not an edge case** — every
tempfail, which is every timeout, extraction failure and oversize part, comes
back as a redelivery.

So `messages` carries an **`ingest_key`**: an identifier supplied by the MTA
that is stable across delivery attempts of one queued message — Postfix's
queue ID, the `{i}` macro. A partial unique index on
`(tenant_id, ingest_key)` lets `resolve_message` upsert and return the
existing UUID. The internal UUID is still the identity; the ingest key is only
how a redelivery finds it again.

Three details that are easy to get wrong:

- **`DO UPDATE`, not `DO NOTHING`.** `ON CONFLICT DO NOTHING ... RETURNING`
  returns *no row* on conflict, so a retry would come back empty and mint a
  second message anyway. `DO UPDATE` always returns the row.
- **`tenant_id` is `NOT NULL DEFAULT 'default'`** here, unlike the nullable
  `tenant_id` on `scans` and `findings`. In a unique index NULL never equals
  NULL, so two retries on the default tenant would each insert. Tenant is part
  of identity (§6) and identity columns cannot be nullable.
- **No ingest key means no retry protection.** A caller that cannot supply one
  gets a plain insert. That is the honest outcome — a false match would attach
  one message's parts to another — but it is worth knowing before wiring an
  MTA that cannot provide a stable id.

Known limit: Postfix reuses queue IDs over long periods (they derive from
inode and time). With `enable_long_queue_ids=yes` a collision is remote, and
retention prunes rows long before reuse becomes plausible — but this is a
practical guarantee, not a mathematical one.

Verified against a real Postgres 16, not just by reading the DDL: retry
resolves to the same UUID and creates no second row; the same queue ID under a
different tenant stays a separate message; a null ingest key inserts
separately; both CHECK constraints reject invalid values; a part retry updates
in place; two parts with identical `content_hash` both survive;
`parts_completed` counts only scanned parts and is stable across repeated
reconciliation; deleting a message cascades to its parts; and
`prune_messages()` reports both counts and leaves recent messages alone.

### 2.3 Why this exists beyond email

Sender, recipient, and message become first-class dimensions, which is exactly
the investigation pivot the findings schema cannot currently serve — `scans`
has no notion of a parent message, so there is nothing to group parts by.

---

## 3. The context envelope

**This is the decision that must be made before the milter is built.**

`siphon-core` gates 174 of its 583 patterns (~30%) on nearby context
keywords, and context matching slices a byte window *inside the single
scanned text* (`context/mod.rs`: `&text[range_start..start]`). Scan parts
independently and each part only sees itself.

The failure this produces:

> **Body:** "Payroll details attached — SSN and DOB as requested."
> **Attachment:** a spreadsheet of bare 9-digit numbers.

As one blob, the keywords open the gate and the SSNs fire. As separate parts,
the attachment is bare digits with no nearby keyword, so pipeline stage 6
**skips the context-gated patterns entirely**. A false negative created purely
by how the work was split, across 30% of the pattern set.

### Options

| | Approach | Cost |
|---|---|---|
| **1** | **Context envelope** — pass body text, subject and filenames as an additional context source for every part's scan | Core API change: context sourced from a string separate from the scanned text |
| 2 | Message-level second pass over concatenated text, gated categories only | Doubles work on the gated set; reintroduces the §5 memory problem on large messages |
| 3 | Accept the gap; rely on the 409 ungated patterns | Free, but knowingly weakens a third of the corpus on the channel being built |

**Decision: option 1.** It is the only one that keeps parts independently
scannable — which §4 depends on — while preserving gated detection. It
requires `ScanConfig` (or the scan entry point) to accept context text
distinct from the scanned text; today the two are the same `&str`.

Option 3 is defensible for high-specificity patterns that self-validate
(card numbers via Luhn), and is the acceptable fallback if the API change
slips. It should be a recorded decision, not a default.

### 3.1 The envelope was quadratic in part count — fixed in siphon-core 2.8.0

Option 1 shipped, and carried a cost the table above did not anticipate.

Correctness requires a part never supply its own context: an envelope
including the scanned part would promote a local keyword to envelope evidence
and score it as though it came from elsewhere. `context_envelope(exclude_path)`
implemented that by rebuilding the envelope per part, and
`scan_text_with_config` then built an Aho-Corasick index over it per part.
Both are linear in message size and ran once per part, so a message cost
**O(parts × message bytes)**.

Attachments hid it. A part with a filename contributes only that filename to
the envelope, so a 1000-attachment message has an ~11 KB envelope. It is
*inline* text parts that put the whole message in every envelope — and a
`multipart/mixed` of a thousand `text/plain` parts is ordinary, legal MIME
that any client can send.

That was never only a latency problem. Combined with the fail-closed default
(§4.4), a handful of such messages occupies every worker, and a scanner that
is merely busy tempfails the entire mail flow: a cheap message becomes a mail
outage.

**The fix:** `ParsedMessage::envelope_index()` builds the envelope and its hit
index **once per message**, recording each part's byte range. Excluding a part
is then a range filter at query time — the same shape of question proximity
gating already asks — so a message costs `O(message)` once plus `O(1)` per
part. Scan with `ScanConfig::shared_envelope`, taking a per-part view with
`for_key(&part.path)`.

Measured in one process by `cargo run --release --bin mail_bench`, which runs
both paths back to back on the same messages (inline text parts, 30 KB each):

| Inline parts | Message | Rebuilt | Shared | Shared per part | Speedup |
|---|---|---|---|---|---|
| 50 | 1.5 MB | 0.51 s | 0.10 s | 2.08 ms | 4.9× |
| 100 | 3 MB | 1.89 s | 0.20 s | 2.00 ms | 9.5× |
| 200 | 6 MB | 7.26 s | 0.40 s | 1.98 ms | 18.3× |
| 400 | 12 MB | 28.10 s | 0.81 s | 2.03 ms | 34.6× |

Rebuilt per-part cost doubles as part count doubles; shared per-part cost is
flat, which is what "the quadratic is gone" looks like. Extrapolated to the
accepted ceiling (1000 inline parts, 30 MB): **~176 s → ~2 s.**

The benchmark keeps both paths rather than deleting the old one, and asserts
they produce the same finding count at every size — a faster envelope that
decides something different is not a fix. `context_envelope` remains for
scanning a single part in isolation, where there is no message-wide pass to
amortise against.

The gain is not confined to pathological input, because every multi-part shape
was rebuilding the envelope once per part: a 2 MB CSV attachment went
225 ms → 152 ms, a 1 MB PDF 71 ms → 50 ms, a 200-part message 91 ms → 49 ms,
and single-worker mixed throughput 82 → 113 msg/s.

Capping envelope size would also have bounded the cost, but it silently drops
context, which is the exact failure §3 exists to prevent.

---

## 4. Fan-out and reconciliation

### 4.1 Default to one pod per message

`siphon-core` already fans its 583 patterns across cores with rayon
*within a single scan* (`scanner/mod.rs`: `active_patterns.par_iter()`). One
scan of one part already saturates a pod's CPU, and `/scan/batch` iterates
items sequentially for that reason — concurrent parts on one pod would
contend for the same rayon pool.

So distributing parts across pods buys nothing for a typical email and adds a
network hop plus coordination. **Scan all parts of a message on one pod by
default.**

### 4.2 Distribute only above a work threshold

Total work per message is bounded by the 30 MB message cap (§5), so the
threshold is computable: sum decoded part sizes and distribute only above a
byte/time budget derived from the milter deadline.

For scale: twenty 1.5 MB attachments at ~200 ms extraction each is ~4 s
sequential — comfortably inside a 30 s timeout. Distribution is the
exception, not the common path.

### 4.3 Verdict aggregation

Verdict is the maximum severity across parts, with one addition:
**`indeterminate` is a real verdict, not a synonym for `clean`.** If nineteen
attachments scan clean and one times out or is skipped as oversized, that
message has not been cleared.

This matches how the scan rollup already counts: `oversize_skipped` and
`scan_errors` are deliberately excluded from `scans_total`, so content that
was never inspected cannot inflate the denominator and flatter the detection
rate. The same principle applies to a delivery decision.

### 4.4 Partial failure is a policy, not an accident

Today the system fails open — oversized ICAP bodies pass through unscanned
(`"icap: body exceeds limit, passing through unscanned"`). For mail, whether
`indeterminate` delivers, quarantines, or defers must be an explicit
configured policy. Fail-open on a delivery decision should be chosen, not
inherited.

**Decision: configurable, defaulting to fail closed.**

```
SIPHON_MILTER_ON_INDETERMINATE = defer | quarantine | deliver
                                 ^ default
```

| Value | Milter reply | Effect |
|---|---|---|
| `defer` (default) | SMTP `451 4.7.1` tempfail | Sender's MTA retries. Nothing is lost, nothing is delivered uninspected. |
| `quarantine` | accept + quarantine | Message is held for a human. Requires somewhere to hold it. |
| `deliver` | accept + annotate | Fail open. Delivered with an `X-Siphon-Verdict: indeterminate` header. |

`defer` is the default because it is the only option that is wrong in a
recoverable direction. A deferred message is retried for days before it
bounces, and the sender is told; a delivered-uninspected message is a silent
miss, which is the failure this product exists to prevent.

It is not free, and the cost is the reason this is configurable rather than
fixed: **under fail-closed, scanner unavailability is mail unavailability.**
If the scanner is down or saturated, every message tempfails. That trade is
right for a deployment where an uninspected message is the worse outcome, and
wrong for one where mail must flow regardless — that judgement belongs to the
operator, not to us. What must not happen is the choice being made implicitly
by whatever the code happened to do, which is the ICAP situation above.

Two consequences follow and are not optional:

1. **Anything that lets a cheap message occupy a worker for minutes is a
   remote mail outage under this default, not a performance problem.** The
   quadratic envelope of §3.1 was exactly that and is fixed; the same test
   applies to whatever is added next. Per-message work must stay bounded by
   the ingest cap rather than by message structure.
2. **`milter_default_action` must agree with this setting.** If the MTA is
   configured to `accept` on milter failure, it fails open on timeout no
   matter what this says — the MTA gets the last word, and a disagreement
   here is a silent bypass. Under the default, the MTA needs
   `milter_default_action = tempfail`.

Which failures count as indeterminate: milter or scan timeout, extraction
failure, text beyond `MAX_INPUT_SIZE`, an encrypted or nested archive entry,
a MIME structural warning (including hitting `max_parts`), and scanner error.
Not: a part that scanned and found nothing.

### 4.5 The deadline, measured

§4.2 assumed 30 s. Measured (`src/bin/mail_bench.rs`, release build, 4 cores,
mail-shaped corpus — parse, extract, scan, aggregate), with the shared
envelope of §3.1:

| Shape | p50 | p95 | max |
|---|---|---|---|
| 2 KB notification | 0.2 ms | 0.5 ms | 1.0 ms |
| 60 KB reply thread | 2.5 ms | 3.0 ms | 3.4 ms |
| Real XLSX attachment | 13.0 ms | 15.2 ms | 16.3 ms |
| 400 KB HTML newsletter | 15.4 ms | 18.2 ms | 19.6 ms |
| 1 MB PDF invoice | 50.3 ms | 56.5 ms | 57.4 ms |
| 2 MB payroll CSV | 152 ms | 155 ms | 155 ms |
| 200-part message | 49 ms | 51 ms | 51 ms |
| 1000 parts, 30 MB total | 1.96 s | — | — |
| 30 MB plain text (at cap) | 1.98 s | 2.05 s | 2.05 s |

Attachment cost is dominated by extraction, not scanning, and extraction is
path-based — there is no bytes-in entry point — so every attachment pays a
temp-file round trip. Worth a bytes-in extractor API if attachment-heavy flows
turn out to matter; not worth it at these numbers alone.

Under concurrency, on the assumed mix:

| Workers | p50 | p95 | p99 | msg/s |
|---|---|---|---|---|
| 1 | 2.4 ms | 48 ms | 153 ms | 113 |
| 2 | 3.3 ms | 75 ms | 241 ms | 145 |
| 4 | 4.1 ms | 126 ms | 272 ms | 167 |
| 8 | 5.0 ms | 215 ms | 602 ms | 172 |

Throughput flattens past the core count while p95/p99 keep climbing — the
familiar shape of a saturated queue. Concurrency should be bounded near the
pod's CPU limit rather than left open; admitting work past that point buys no
throughput and spends the latency budget on queueing. (Measured on a 4-core
box; the 4- and 8-worker p99s move a few hundred ms between runs. The trend is
solid, the individual figures are not.)

**Recommendation: 10 s.**

The bound is a single large text — 30 MB of plain text, 2.0 s idle and 2.7 s
under load — not message structure. That is what §3.1 changed: before the
shared envelope the worst contended message was a 1000-part structural case at
14.6 s and the worst *accepted* one projected to ~256 s, so no timeout worked;
now part count is roughly free and the worst case is bounded by
`MAX_INPUT_SIZE`, which does not grow with how a message is assembled.

10 s is ~4× that contended worst case, leaving room for a slower pod than the
one measured, and ~40× the mixed-flow p99, so ordinary mail cannot reach it.

Sizing note: a timeout is set by the worst message the system *accepts*, not
the typical one — the MTA waits for whatever we agree to look at. Timing out
on typical mail is a misconfiguration; the worst accepted case is the real
bound.

Fail-closed makes a tight timeout affordable. When timeout means tempfail,
being wrong costs a retry and some delivery latency, not an uninspected
delivery — so the number can be set near real worst-case service time instead
of being inflated to cover the tail "just in case".

The measurement is reproducible; the mix is not. Message-size distribution
varies enormously between organisations, and the mix in `mail_bench` is a
placeholder for a histogram from the deployment's own logs. Per-shape numbers
do not depend on it.

---

## 5. Size limits

**Message cap: 30 MB.** Applied at ingest, before parsing.

**Scanner text cap: 30 MB** — the same number, as of siphon-core 2.7.0. This
section previously argued the scanner cap had to stay lower, and listed the
work required to close the gap. That work has landed:

1. **`u32` offsets** (siphon-core 2.5.0) — halved the dominant allocation.
2. **Pod memory limits raised** (chart 2.4.0) — api and fs now request 512Mi
   with a 2Gi limit.
3. **Cap raised** (siphon-core 2.7.0).

Chunked scanning with overlap was on that list and was **not** needed. It
remains the right answer if the cap ever goes materially higher, and the
boundary-overlap problem it has to solve is still the real design work.

The estimate this section used to carry — "0.5–1 GB for a 30 MB scan" — was
too pessimistic. Measured peak RSS for a single scan:

| Scanned text | Peak RSS | Wall time |
|---|---|---|
| 5 MB | 189 MB | 0.79 s |
| 9 MB | 211 MB | 1.18 s |
| 20 MB | 279 MB | 2.16 s |
| **30 MB** | **336 MB** | **3.08 s** |

Roughly 5.5 MB of RSS per MB of input. The 2Gi limit fits about five
concurrent maximum-size scans; the previous 1Gi fit two.

Both caps being one number does not make them one limit. Ingest bounds the
*message*; `MAX_INPUT_SIZE` bounds *one part's extracted text*. A 30 MB
message whose attachment expands past 30 MB of text still exceeds the scanner
cap, and that part is reported not scanned — never clean.

> **Implementation note:** the cap once lived in several independent places —
> `MAX_INPUT_SIZE` in `siphon-core/src/validation.rs`, a hardcoded
> `10 * 1024 * 1024` in the `/scan/batch` handler, and a stale second `pub
> const` in `siphon-core/src/scanner/mod.rs` that disagreed with enforcement
> by 3x once the real cap moved. All three are now the one constant, with the
> scanner path a re-export so it cannot drift again. New callers should use
> `siphon_core::validation::MAX_INPUT_SIZE` and never compare against a
> literal.

---

## 6. Deduplication

Siphon currently skips persisting a scan when the same `input_hash` was seen
**within the last 60 seconds**, with no tenant and no message dimension
(`db.rs`, `persist_scan`). At attachment granularity this is not an edge
case — it is the steady state:

- Corporate signature images and logos are attached to nearly every message.
- Standard disclaimer PDFs repeat across the entire mail flow.
- The same newsletter or template reaches many recipients at once.

Scanned as parts, these collapse against *unrelated messages* continuously, so
most parts in the flow would be discarded before storage. Under a milter this
stops being a reporting gap and becomes a **delivery decision made on content
that was never scanned** — a trivially reproducible bypass: send the same
attachment twice within a minute.

**Correct semantics:**

| Scope | Behaviour |
|---|---|
| Within one message | Dedupe by `content_hash` — scan once, attribute the result to every part carrying those bytes. Legitimate optimisation. |
| Across messages | **No content-based dedup.** Idempotency comes from `UNIQUE (message_uuid, mime_path)`, which suppresses retries without suppressing distinct messages. |
| Across tenants | Never. Tenant is part of identity. |

**The 60-second window is gone.** `persist_scan` is idempotent on `scan_id`
(`ON CONFLICT (id) DO NOTHING`) and never on content, with tests asserting the
statement is not keyed on `input_hash` — there is no Postgres in the test
environment, so the statement text is the only available regression guard.
This section previously listed the fix as a prerequisite; it landed in
siphon-api 2.8.0.

`message_parts` follows the same rule: `UNIQUE (message_uuid, mime_path)`, and
`content_hash` is recorded but never used as a cross-message key. Two parts
carrying identical bytes both persist — verified — because collapsing them is
precisely the bypass described above.

---

## 7. Metrics

Detection rate needs a denominator, and storing a `scans` row per message
would mean ~1.5×10⁹ rows/year recording that nothing was found — 99%+ of the
table, none of it an identified event.

The `scan_rollup` table (migration `0009`) counts all scanned traffic per
`(hour, tenant, channel)`; identified events keep full rows. Mail adds
`channel = 'smtp'`. Derived per bucket:

```
detection rate = scans_with_findings / scans_total
findings/scan  = findings_total      / scans_total
coverage gap   = oversize_skipped    / (scans_total + oversize_skipped)
```

That last one matters most for mail: it quantifies how much traffic passed
without inspection, which is precisely the question a 30 MB cap and a
fail-open path raise.

---

## 8. Build order

1. ~~**Dedup fix** (§6)~~ — done, siphon-api 2.8.0.
2. ~~**Context envelope API** (§3)~~ — done, siphon-core 2.4.0; made linear in
   2.8.0 (§3.1).
3. ~~**Message/parts model** (§2)~~ — done, siphon-api 2.9.0. Schema,
   reconciliation and retention; nothing writes it yet.
4. **`siphon-milter`** (§1) — transport, header injection, verdict policy.
   The only step left, and now unblocked: the deadline is measured (§4.5), the
   `indeterminate` policy is decided (§4.4), the MIME layer and context
   envelope are on `main`, and the storage its retries depend on exists
   (§2.2a).
5. ~~**Size limits** (§5)~~ — done: `u32` offsets in siphon-core 2.5.0, pod
   memory in chart 2.4.0, scanner cap raised in 2.7.0.

---

## 9. Open questions

- ~~**Milter deadline**~~ — resolved in §4.5: **10 s**. Still needs the mail
  team's confirmation that 10 s fits their `smtpd_milters` budget alongside
  any other milters in the chain.
- ~~**`indeterminate` policy**~~ — resolved in §4.4: configurable, default
  `defer`. Open sub-question: `quarantine` needs somewhere to hold messages,
  which does not exist yet — until it does, that value should be rejected at
  startup rather than silently behaving as `defer`.
- ~~**Envelope index sharing**~~ — resolved in §3.1, siphon-core 2.8.0.
- **Per-item coverage** — if audit requires proving every message was
  inspected, that is ~1.5×10⁹ ledger entries/year. Feasible as a compact
  append-only table (hash, timestamp, verdict) at roughly 75 GB/year
  partitioned, but it must be a separate structure from findings and is
  painful to retrofit.
- **Recipient fan-out** — the MTA may invoke the milter once per message or
  once per recipient. Which one determines whether `recipients` is an array on
  one row or multiple message rows.
