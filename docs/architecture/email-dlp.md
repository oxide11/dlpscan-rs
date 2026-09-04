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
| 3 | Accept the gap; rely on the 410 ungated patterns | Free, but knowingly weakens a third of the corpus on the channel being built |

**Decision: option 1.** It is the only one that keeps parts independently
scannable — which §4 depends on — while preserving gated detection. It
requires `ScanConfig` (or the scan entry point) to accept context text
distinct from the scanned text; today the two are the same `&str`.

Option 3 is defensible for high-specificity patterns that self-validate
(card numbers via Luhn), and is the acceptable fallback if the API change
slips. It should be a recorded decision, not a default.

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

---

## 5. Size limits

**Message cap: 30 MB.** Applied at ingest, before parsing.

The scanner's text cap is a **separate, lower** limit and must not simply be
raised to match. Normalization tracks a span offset **per output byte** in a
`Vec<usize>` — 8 bytes per input byte on 64-bit:

| Scanned text | Offset vector alone |
|---|---|
| 10 MB (today) | 80 MB |
| 30 MB | **240 MB** |

Stages hold incoming and outgoing offset vectors simultaneously, alongside the
text copies, with nested base64 decoding up to three layers. A single 30 MB
text scan realistically peaks at **0.5–1 GB** against a **1Gi** Helm limit —
one large message would OOM the pod.

This is mostly theoretical for mail, because the scanner sees *extracted
text*, and a 30 MB PDF or Office file extracts to a fraction of its raw size.
It bites on pathological input: 30 MB of plain text, or a high-expansion
archive.

Work required before raising the scanner cap:

1. **`u32` offsets instead of `usize`** — halves the dominant cost, provably
   safe for any sub-4 GB input. Cheapest win.
2. **Chunked scanning with overlap** for large text — bounds memory
   independent of input size. Overlap must exceed the longest pattern or
   matches are lost at chunk boundaries; that is the real design work.
3. **Raise pod memory limits** — needed regardless.

> **Implementation note:** the 10 MB limit is enforced in at least two
> independent places — `MAX_INPUT_SIZE` in `siphon-core/src/validation.rs`,
> and a hardcoded `10 * 1024 * 1024` inline in the `/scan/batch` handler.
> Changing the constant alone leaves the batch path at 10 MB.

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

- **Milter deadline** — what timeout is the mail team willing to configure?
  It sets the fan-out threshold in §4.2.
- **`indeterminate` policy** — deliver, quarantine, or defer?
- **Per-item coverage** — if audit requires proving every message was
  inspected, that is ~1.5×10⁹ ledger entries/year. Feasible as a compact
  append-only table (hash, timestamp, verdict) at roughly 75 GB/year
  partitioned, but it must be a separate structure from findings and is
  painful to retrofit.
- **Recipient fan-out** — the MTA may invoke the milter once per message or
  once per recipient. Which one determines whether `recipients` is an array on
  one row or multiple message rows.
