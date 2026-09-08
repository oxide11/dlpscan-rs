# ACEE on the Running page

The Running page in the C2 console reads every sensor as four axes —
**Availability, Coverage, Efficacy, Efficiency** — each judged against a
stated target. The vocabulary and the rules are the performance lens from
*Inside the Adversary's Loop: A Doctrine for Building, Measuring, and
Operating Modern Data Security Programs* (Moussa Noun, 2026, working draft
v0.2), chapter 7. This note says what each axis means for Siphon, what it
reads from, what it cannot read yet, and why the shape is what it is.

The code is `crates/siphon-api/src/sensors_api.rs` (the derivation, every
judgement a pure tested function), `crates/siphon-auth/src/telemetry.rs`
(what a sensor reports), and `console/src/routes/_c2/running.tsx` (the
rendering, which shows the working and makes no judgement of its own).

## Three rules the shape enforces

1. **A figure that was not measured is absent, never zero.** A sensor that
   predates the canary has no recall figure, not a failing one. A window in
   which nothing was expected has no availability figure, not 0 %. The
   console renders absence as `unverified`.
2. **The four axes are a vector, never a scalar.** No average, no composite
   score. The badge on an axis is the *worst* of its parts, and the worked
   example in the book (§7.7, the DLP whose dashboard read green) is about
   what averaging hides.
3. **Every reading carries its working and its target.** Numerator,
   denominator, target, gap. A percentage without those is a score; with
   them it is something an operator can act on and an auditor can check.

The target is the reference, not the prior period. A figure can rise every
week and still be short of what the obligation requires.

## The four axes, on Siphon

| Axis | The book asks | What the page reads | What it cannot read |
|---|---|---|---|
| Availability | deployed ∧ running ∧ **operational** | expected list; heartbeat slots received ÷ expected; the sensor's reported *posture* | — |
| Coverage | reach against matrix, environment, and each auditor's frame | **at depth**: items scanned ÷ items seen, per sensor; expected sensors operational ÷ expected, program-wide | the environment: mail flows, proxies, paths that have no sensor at all |
| Efficacy | recall and precision, separately; recall from synthetic injection | **canary** recall on the live path; analyst precision; the latest evadex adversarial run | recall against the real threat distribution — one fixture proves the path, not the recall |
| Efficiency | six cost dimensions | compute (ms/scan, ms/MB), operator attention (verdicts reviewed), false positives (count) | license, maintenance, opportunity cost, false-positive *blast radius* |

### Availability is deployed ∧ running ∧ operational

The first cut of the page reported heartbeat slots and called it
availability. Section 7.2 of the book opens with the DLP agent that fell
back silently to permit-all: running, reachable, and protecting nothing.
Every Siphon sensor has such a mode.

| Sensor | Whole job | Less than its whole job |
|---|---|---|
| siphon-icap | `SIPHON_ICAP_ACTION=block` | `flag`: annotates and lets the proxy pass it |
| siphon-smtp | annotates, `SIPHON_SMTP_ON_INDETERMINATE=defer` | `deliver`: fails open |
| siphon-api | all pipeline stages enabled | a stage toggled off via `PATCH /v1/pipeline/stages` |
| siphon-fs | `SIPHON_ON_FORMAT_MISMATCH=flag` or `reject` | `ignore`: reads by content, records nothing |

So the heartbeat now carries a **posture**: what the sensor does with a
finding (`block`, `annotate`, `advisory`), what happens when it cannot
decide (`closed`, `open`, `not_applicable`), and why it is degraded if it
is. The receiver judges it:

- **block** is ok. **advisory** is ok by design: siphon-api and siphon-fs
  answer a scan and the caller acts; that is a role, not a degradation.
- **annotate** is a warning, always — including for the milter when it
  fails closed. Enforcement is then delegated to something this side cannot
  see: Postfix's rules on the stamped header, the proxy's handling of a
  flagged body. The page says "delegated, not verified here" rather than
  claiming the mark is honoured.
- **fails open** is a warning whatever else is true. **degraded** is a
  warning that names why.
- A sensor that has not reported a posture (built before the field) leaves
  the axis **unmeasured**, never met.

A stale or gone sensor is a gap whatever its slot ratio says. An audit-only
sensor is a gap whatever its slot ratio says. That is the book's 99.5 %
that was 76 %.

### Coverage is at depth

Every sensor already knew when it passed something through unread — an ICAP
body over the size cap or binary, a file whose extracted text exceeds the
scanner limit, an archive entry it could not open, a message over the
ingest cap — and none of it was counted. `unscanned_total` is that count,
distinct from `errors_total` (tried and failed). Coverage at depth is
scans ÷ (scans + unscanned): of what reached the sensor, how much it read.

Coverage against the **environment** — the mail flow with no milter, the
proxy with no ICAP service, the share nobody uploads from — cannot be
measured from inside a sensor, and the page says so in words rather than
showing a number. Coverage against the **matrix** is the program-level
figure: expected sensors that are healthy and operational ÷ expected. A
sensor never heard from counts against it. The expected list is
`SIPHON_SENSORS_EXPECTED`, defaulting to all four.

### Efficacy is recall and precision, separately

Never F1. The book's reason (§7.4) is that a composite hides which side is
short, and the two have different remedies.

**Precision** is analyst verdicts on the sensor's findings, 7 days: true ÷
ruled. Unmeasured until someone rules on something, which is honest — a
sensor whose findings nobody reviews has unknown precision.

**Recall** cannot be read from operational counts; a false negative is what
nobody saw. The book's source is synthetic injection at threat cadence. The
smallest honest form of that is the **canary**: once per heartbeat each
sensor scans a fixed fixture with two planted values through its own
deployed path — siphon-fs through extraction from a temp file, siphon-api
with its live overrides and disabled stages, the milter and ICAP at their
configured confidence floor — and reports whether every planted category
came back. The window figure is heartbeats whose canary passed ÷ heartbeats
that ran one, target 100 %. One fixture proves the path finds what it is
for. It does not prove recall is high, and the tile says so.

The wider net is **evadex**, the adversarial harness, whose ingested runs
carry detected ÷ variants against a corpus built to evade. That is
program-wide (evadex drives the scanner, not a sensor) and is shown in the
header with no target, because nobody has yet said what it should be. The
conformance matrix at CI cadence is the third source, and it never touches
a deployed binary — which is exactly why the canary exists.

The old "detection rate" tile is gone. Findings per scan is a base rate of
the traffic, and under this vocabulary it would be read as efficacy.

### Efficiency is three of six

The book's six cost dimensions are compute, license, operator attention,
false-positive blast radius, maintenance and opportunity. Telemetry can
carry compute (ms per scan, ms per MB, errors per scan), operator attention
(verdicts reviewed) and false positives as a count. The tile shows those
and names the other three as unmeasured, rather than reporting a third of
the cost as the cost. There is no target on this axis; there is no
objective to derive one from.

## Targets

ACEE reads a value against what the objective specified. Siphon has no
objectives layer, so the targets are **declared defaults**, overridable per
deployment, and the response says which it is using:

| Variable | Default | Reads |
|---|---|---|
| `SIPHON_SENSORS_TARGET_AVAILABILITY` | 0.99 | heartbeat slots, 24 h |
| `SIPHON_SENSORS_TARGET_COVERAGE` | 0.95 | at depth per sensor; against the matrix program-wide |
| `SIPHON_SENSORS_TARGET_PRECISION` | 0.80 | analyst verdicts, 7 d |
| `SIPHON_SENSORS_TARGET_CANARY` | 1.0 | canary passes, 24 h |
| `SIPHON_SENSORS_EXPECTED` | all four | the matrix |

An unparseable target refuses to start: a target the operator set and we
silently replaced would judge the fleet against a number nobody chose.
When an objectives layer exists (book, chapter 2–3: requirements →
objectives → capabilities, each with its cadence and scope) these should
come from it. Until then a default that says it is a default is the honest
position.

## The response

`GET /v1/sensors`, `schema_version: 2`. The version is bumped whenever a
field's meaning changes, per the book's rule (§5.3) that a metric's
definition changes only with an explicit version. Every axis is a
`Reading`:

```json
{ "value": 0.9969, "numerator": 2871, "denominator": 2880,
  "target": 0.99, "gap": 0.0069, "state": "met",
  "basis": "heartbeat slots received ÷ slots expected" }
```

`state` is `met`, `gap`, `no_target` (a figure with nothing to judge it by)
or `unmeasured`. The overall of an axis is the worst of its parts; the
overall of a sensor is not computed, because that would be the scalar.

## What this phase leaves out, and why

- **OODA.** siphon-smtp and siphon-icap are loops in the book's sense
  (chapter 8). Phase timing means measuring the Act boundary — the MTA
  acting on the stamped header, the proxy on the block — which Siphon does
  not own. Its own design.
- **Environment coverage.** Needs an inventory of flows Siphon does not
  have. Said in words on the page rather than faked.
- **Severity-weighted efficacy** (§7.4). The canary is two categories; a
  weighted corpus is the conformance matrix's job on the live path, later.
- **Efficiency's other three dimensions.** Not telemetry.
