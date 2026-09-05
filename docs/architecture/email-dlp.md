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

### 3.1 The envelope is quadratic in part count — fix before shipping

Option 1 shipped, and carries a cost the table above did not anticipate.

Correctness requires a part never supply its own context: an envelope
including the scanned part would promote a local keyword to envelope evidence
and score it as though it came from elsewhere. `context_envelope(exclude_path)`
implements that by rebuilding the envelope per part, and
`scan_text_with_config` then builds an Aho-Corasick index over it per part.
Both are linear in message size and run once per part, so a message costs
**O(parts × message bytes)**.

Measured with `cargo run --release --bin mail_bench`, inline text parts of
30 KB each:

| Inline parts | Message | Verdict latency | Per part |
|---|---|---|---|
| 50 | 1.5 MB | 0.72 s | 14.3 ms |
| 100 | 3 MB | 2.65 s | 26.5 ms |
| 200 | 6 MB | 10.35 s | 51.7 ms |
| 400 | 12 MB | 40.92 s | 102.3 ms |

Per-part cost doubles as part count doubles — clean quadratic growth.
Extrapolated to what the system already accepts (`MimeLimits::max_parts` =
1000, ingest cap 30 MB): **~256 s, more than four minutes, for one message.**
Extrapolated rather than measured; measuring it costs four minutes per
iteration, which is itself the finding.

Attachments hide this. A part with a filename contributes only that filename
to the envelope, so a 1000-attachment message has an ~11 KB envelope and
finishes in under 3 s. It is *inline* text parts that put the whole message in
every envelope — and a `multipart/mixed` of a thousand `text/plain` parts is
ordinary, legal MIME that any client can send.

**This blocks the milter.** Not for latency: for availability. Combined with
the fail-closed default (§4.4), a handful of such messages occupies every
worker, and a scanner that is merely busy tempfails the entire mail flow. A
cheap message becomes a mail outage.

The fix is to stop rebuilding per part. The envelope index should be built
**once per message** over the concatenation of all parts, recording each
part's byte range; "exclude this part" then becomes a range filter at gate
time rather than a rebuild — which is the same range machinery
`has_hit_in_range` already uses for proximity. That makes a message
O(message bytes) once plus O(1) per part.

Capping envelope size would also bound the cost, but it silently drops
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

1. **The quadratic in §3.1 must be fixed before this default ships.** Under
   fail-closed, a cheap message that occupies a worker for minutes is no
   longer a performance problem; it is a remote mail outage.
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
mail-shaped corpus — parse, extract, scan, aggregate):

| Shape | p50 | p95 | max |
|---|---|---|---|
| 2 KB notification | 0.4 ms | 0.7 ms | 1.8 ms |
| 60 KB reply thread | 3.4 ms | 3.8 ms | 4.4 ms |
| 400 KB HTML newsletter | 19.0 ms | 22.0 ms | 26.8 ms |
| Real XLSX attachment | 22.7 ms | 26.4 ms | 28.6 ms |
| 1 MB PDF invoice | 70.9 ms | 78.3 ms | 81.0 ms |
| 2 MB payroll CSV | 225 ms | 231 ms | 237 ms |
| 30 MB plain text (at cap) | 2.58 s | 2.64 s | 2.64 s |

Attachment cost is dominated by extraction, not scanning, and extraction is
path-based — there is no bytes-in entry point — so every attachment pays a
temp-file round trip. Worth a bytes-in extractor API if attachment-heavy flows
turn out to matter; not worth it at these numbers alone.

Under concurrency, on the assumed mix:

| Workers | p50 | p95 | p99 | msg/s |
|---|---|---|---|---|
| 1 | 3.1 ms | 72 ms | 222 ms | 82 |
| 2 | 4.1 ms | 110 ms | 326 ms | 107 |
| 4 | 5.1 ms | 182 ms | 336 ms | 123 |
| 8 | 6.9 ms | 358 ms | 908 ms | 131 |

Throughput flattens past the core count while p95/p99 keep climbing — the
familiar shape of a saturated queue. Concurrency should be bounded near the
pod's CPU limit rather than left open; admitting work past that point buys no
throughput and spends the latency budget on queueing. (Measured on a 4-core
box, so the 4- and 8-worker p99s are noisy across runs — 336 ms here, 468 ms
on a previous run. The trend is solid, the individual figures are not.)

**Recommendation: 10 s, once §3.1 is fixed.** Roughly 3× the worst contended
message once the quadratic is gone — 30 MB of plain text, measured at 3.4 s
under load — and ~30× the mixed-flow p99, so ordinary mail cannot reach it.

That "once" is load-bearing. Today the worst contended message is the
1000-part structural case at 14.6 s, and the worst *accepted* one is the
projected ~256 s; 10 s would tempfail both forever. Fixing the envelope makes
part count roughly free, which puts 30 MB of plain text back at the top —
that is the message the 10 s is sized for.

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

Fixing the existing 60-second window is a prerequisite for the mail path and
is worth doing independently — it is losing data on the current channels
today.

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

1. **Dedup fix** (§6) — small, independent, and losing data on live channels
   today. Prerequisite for anything mail-shaped.
2. **Context envelope API** (§3) — decide and land before the milter, since it
   changes the scan entry point.
3. **Message/parts model** (§2) — migration plus reconciliation logic.
4. **`siphon-milter`** (§1) — transport, header injection, verdict policy.
5. **Size limits** (§5) — 30 MB message cap; `u32` offsets; then revisit the
   scanner text cap.

---

## 9. Open questions

- ~~**Milter deadline**~~ — resolved in §4.5: **10 s**, blocked on the §3.1
  fix. Still needs the mail team's confirmation that 10 s fits their
  `smtpd_milters` budget alongside any other milters in the chain.
- ~~**`indeterminate` policy**~~ — resolved in §4.4: configurable, default
  `defer`. Open sub-question: `quarantine` needs somewhere to hold messages,
  which does not exist yet — until it does, that value should be rejected at
  startup rather than silently behaving as `defer`.
- **Envelope index sharing** (§3.1) — blocks the milter. Build the index once
  per message and make part exclusion a range filter.
- **Per-item coverage** — if audit requires proving every message was
  inspected, that is ~1.5×10⁹ ledger entries/year. Feasible as a compact
  append-only table (hash, timestamp, verdict) at roughly 75 GB/year
  partitioned, but it must be a separate structure from findings and is
  painful to retrofit.
- **Recipient fan-out** — the MTA may invoke the milter once per message or
  once per recipient. Which one determines whether `recipients` is an array on
  one row or multiple message rows.
