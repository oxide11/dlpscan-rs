# Handoff: Siphon-C2 Console

## Overview

Siphon-C2 is the operator console for **`oxide11/dlpscan-rs`** — a Rust DLP scanning
engine that runs as two Kubernetes Deployments (`siphon-api`, `siphon-fs`) behind
`crates/siphon-api`'s HTTP surface. This bundle contains a complete high-fidelity
prototype of the console: 21 surfaces across a verb-led information architecture
(Overview → Operate → Configure → Validate → Settings). There are no stubs — every
navigation entry resolves to a designed screen.

The prototype's defining property is that it is **grounded in the real backend**.
Every screen was built by reading the repository, and several screens exist
specifically to surface behaviour the API hides — silent extraction gaps, config
changes that are never audited, override fields that are parsed and then ignored.
Those are documented as **Backend findings** below. They are not design fiction;
they are defects the console makes visible, and some of them should be fixed in
the backend rather than papered over in the UI.

## About the Design Files

The files in this bundle are **design references created in HTML** — prototypes
showing intended look, structure, and behaviour. They are not production code to
copy directly.

The task is to **recreate these designs in the target codebase's existing
environment** using its established patterns, component library, routing, and
data layer. `dlpscan-rs` already carries a `ui/` directory with `ui/lib/api.ts`,
so that is the natural home; if the console is instead built fresh, choose the
framework that fits the team and implement the designs there.

Specifically:

- The prototype is a single HTML file plus nine Babel-transpiled JSX files loaded
  at runtime. **Do not ship this arrangement.** It exists so the design could be
  built and reviewed quickly in a browser with no build step.
- All data in the prototype is **hardcoded fixture data** at the top of each
  surface file (`SD_ROWS`, `FS_EXTRACTORS`, `OV_DIFF`, and so on). The values were
  chosen to represent real states — including the awkward ones — and they document
  the shapes each screen needs. They must be replaced with real API calls.
- The design system is expressed as CSS custom properties in the `<style>` block.
  Port the tokens; do not port the class names verbatim if the target codebase has
  its own conventions.

## Fidelity

**High-fidelity.** Final colors, typography, spacing, component states, and
interaction behaviour. Recreate the UI faithfully using the codebase's existing
libraries. The visual system is deliberately narrow and the narrowness is the
design — see *Design principles* before substituting anything.

## Design principles

These constrain every screen. Violating them is how the console degrades.

1. **Two colors carry meaning, and only two.** A single emerald (`--brand`,
   `#1a6f4d`) for good/confirmed, a single red (`--signal-attn`, `#c2362e`) for
   needs-attention. Everything else is monochrome. No violet, cyan, amber, or
   magenta is assigned semantics anywhere. If a new state needs a color, the
   answer is a badge, a dot, or a border — not a new hue.
2. **Diff before apply.** No mutation is committed from the surface that composes
   it. Edits accumulate as drafts, a sticky `.diff-bar` reports the count, and a
   modal shows the exact before/after plus which pods will receive it. This
   applies to Patterns, Policies, Lists, and Overrides.
3. **Multi-pod first.** There is no "the scanner." There are 9 pods across 2
   Deployments, and they can disagree. Every finding, config value, and capability
   is attributed to a pod (`PodId`) or a Deployment. A value that is uniform says
   so explicitly; a value that is not shows the drift.
4. **Absence is a state.** The console distinguishes "zero findings" from "the
   extractor that would have produced findings was not in the build." This is the
   single most important idea in the prototype and it recurs on File scan, Scan
   Diff, Pods, and Pipeline.
5. **Mono is for data only.** IDs, offsets, config keys, hashes, code. Never for
   prose, labels, or headings.
6. **No decoration.** No gradients, no shadows except the two defined for menus
   and modals, no icons that repeat the adjacent word, no illustrations.

## Design Tokens

Ported verbatim from the prototype's `:root`. Both themes ship; the theme is set
by `data-theme` on `<body>` and toggled from the header.

### Color — light (`[data-theme="light"]`)

| Token | Value | Use |
| --- | --- | --- |
| `--bg-page` | `#fafafa` | App background |
| `--bg-surface` | `#ffffff` | Cards, tables, header, sidebar |
| `--bg-subtle` | `#f5f5f4` | Inset chips, badge fills, bar tracks |
| `--bg-hover` | `#f5f5f4` | Row and nav hover |
| `--bg-sunk` | `#ededec` | Recessed wells |
| `--line-subtle` | `#ececeb` | Row dividers inside a card |
| `--line` | `#e2e2e0` | Card and input borders |
| `--line-strong` | `#d4d4d2` | Hovered input border |
| `--line-bold` | `#b5b5b3` | Hovered button border |
| `--ink` | `#0a0a0a` | Body text |
| `--ink-strong` | `#171717` | Headings, emphasized values |
| `--ink-soft` | `#525252` | Mono data in tables |
| `--ink-muted` | `#737373` | Secondary text, captions |
| `--ink-faint` | `#a3a3a3` | Placeholders, nav group labels, empty cells |
| `--brand` | `#1a6f4d` | Brand emerald — confirmed/good |
| `--brand-strong` | `#155b3f` | Brand text on soft fill |
| `--brand-soft` | `#ecf6f0` | `badge--ok` fill, selection |
| `--brand-onbrand` | `#ffffff` | Text on brand fill |
| `--signal-attn` | `#c2362e` | Needs attention |
| `--signal-attn-bg` | `#fdecea` | `badge--attn` fill, attention banners |

### Color — dark (`[data-theme="dark"]`)

`--bg-page` `#0a0a0a` · `--bg-surface` `#131313` · `--bg-subtle` `#1a1a1a` ·
`--bg-hover` `#1f1f1f` · `--bg-sunk` `#050505` · `--line-subtle` `#1f1f1f` ·
`--line` `#2a2a2a` · `--line-strong` `#383838` · `--line-bold` `#525252` ·
`--ink` `#fafafa` · `--ink-strong` `#ffffff` · `--ink-soft` `#d4d4d2` ·
`--ink-muted` `#a3a3a3` · `--ink-faint` `#737373` · `--brand` `#2a9268` ·
`--brand-strong` `#34a87a` · `--brand-soft` `#0f2419` ·
`--signal-attn` `#ef6b62` · `--signal-attn-bg` `#2a0e0c`

### Typography

Five sizes, three weights, two families. This is the whole scale — there is no
sixth size.

| Token | Size | Weight | Line-height | Letter-spacing | Use |
| --- | --- | --- | --- | --- | --- |
| `--t1` | 24px | 600 | 1.25 | −0.01em | Page title (`.t1`) |
| `--t2` | 18px | 600 | 1.25 | −0.005em | Section title (`.t2`) |
| `--t3` | 13px | 400 | 1.5 | — | Body, table cells, buttons (`.t3`) |
| `--t4` | 12px | 400 | 1.5 | — | Meta, secondary, `.muted` (`.t4`) |
| `--t5` | 11px | 500 | 1.5 | 0.04em, uppercase | Caption / eyebrow labels (`.t5`) |

- `--font-sans`: `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif`
- `--font-mono`: `'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace` — 12px, used only for data
- Weights in use: 400 body, 500 emphasized/`.strong`, 600 headings. No 700.
- Nav group labels: 11px, `--ink-faint`, `letter-spacing: 0.08em`, uppercase.
- Numeric table columns use `font-variant-numeric: tabular-nums` (`.num`).

### Spacing — 4pt grid

`--s1` 4 · `--s2` 8 · `--s3` 12 · `--s4` 16 · `--s5` 20 · `--s6` 24 ·
`--s7` 32 · `--s8` 40 · `--s9` 64

### Shape, shadow, chrome

- Radius: `--r-1` 4px (badges, small controls), `--r-2` 6px (buttons, icon
  buttons), `--r-3` 8px (modals). Cards use 5px directly — a deliberate
  in-between value, keep it.
- Shadows: exactly two. Dropdown `0 8px 24px rgba(0,0,0,.08), 0 2px 6px rgba(0,0,0,.04)`;
  dark `0 8px 24px rgba(0,0,0,.5), 0 2px 6px rgba(0,0,0,.3)`. Nothing else casts.
- `--header-h` 52px · `--nav-w` 240px (collapses to a 56px icon rail)
- Page container: `padding: 32px 40px`, `max-width: 1180px`
- Transitions: 80ms on button background/border. Nothing animates longer than
  120ms anywhere in the console.

## Information architecture

A single flat surface list grouped into five sections. The grouping is by **verb** —
what the operator is doing — not by system component. There is no "Engineering"
section; infrastructure lives under Settings.

```
Overview
  Posture ................. activity     ✅ built
Operate
  Pods .................... pods         ✅ built   badge 9
  Findings ................ findings     ✅ built   badge 12
  Live Scan ............... livescan     ✅ built
  File scan ............... filescan     ✅ built
  FP Troubleshooter ....... fp           ✅ built
Configure
  Patterns ................ patterns     ✅ built
  Policies ................ policies     ✅ built
  Lists & Profiles ........ lists        ✅ built
  Overrides ............... overrides    ✅ built
  Plugins ................. models       ✅ built
  Fingerprints ............ fingerprints ✅ built
  Integrations ............ integrations ✅ built
Validate
  Pipeline ................ pipeline     ✅ built
  Test corpus ............. corpus       ✅ built
  Adversarial tests ....... tests        ✅ built
  Scan Diff ............... diff         ✅ built
  Compliance .............. compliance   ✅ built
  Audit log ............... audit        ✅ built
Settings
  Health .................. health       ✅ built
  Settings ................ settings     ✅ built
  Profile ................. profile      ✅ built
```

Routing in the prototype is a single `surface` state string switching a component
map. In the target app these are routes; the string ids above are usable as path
segments.

## Shared primitives

Four components carry the console's identity. Build these first — every surface
depends on them.

### `PodId({ id, size })`

Renders a pod identifier as a mono chip with a deterministic color derived from
the pod name, so the same pod is the same color on every screen. `size="small"`
for table cells and inline prose. Never render a bare pod name as plain text.

### `Confidence({ value })`

A 0–1 confidence score as a short segmented meter plus the numeric value at two
decimals. The meter is monochrome; it does not turn red at low values, because
low confidence is not an error — the policy floor decides that. Used on Findings,
Live Scan, File scan, Scan Diff.

### `LiveStamp({ ago, paused, onTogglePause })`

The "how stale is this" control: a relative age, a pulse dot, and a pause toggle.
Every polling surface carries one in `.page-actions`. Paused state must be
visually obvious — an operator reading stale numbers is the failure mode.

### `DiffModal` + `.diff-bar`

The diff-before-apply pair. `.diff-bar` is `position: sticky; bottom: 16px`,
appears only when drafts exist, and reports the count plus which pods are
affected. `DiffModal` shows field-level before/after. Both are required wherever
mutation exists; see *Design principles* #2.

### Component atoms

- `.btn` — 30px tall, 12px horizontal padding, 6px radius, 1px `--line` border.
  Variants: `--primary` (`--ink-strong` fill), `--brand`, `--ghost` (transparent).
- `.badge` — 11px, 4px radius, `0.02em` tracking. Variants: `--neutral` (subtle
  fill + border), `--ok` (`--brand-soft`/`--brand-strong`), `--attn`
  (`--signal-attn-bg`/`--signal-attn`).
- `.card` — `--bg-surface`, 1px `--line`, 5px radius, no shadow.
- `.tbl` — full width, collapsed borders, 13px. Header cells are `.t5` style with
  a `--line` bottom rule; body cells 12px vertical padding with `--line-subtle`
  dividers; rows hover to `--bg-hover`.
- `.tabs` / `.tab` — inner navigation. 8px vertical padding, 20px gap, 2px
  transparent bottom border that becomes `--ink-strong` when `.active`.
- `.kv` — two-column key/value grid, key in `.t5` caption style.
- `.attn-dot` — 7px `--signal-attn` circle, precedes any inline warning sentence.

## Screens

Below, each built surface with its purpose, layout, and the API it maps to. Layout
measurements are the prototype's; all screens sit inside the 1180px page
container.

### Posture (Overview)

**Purpose.** The landing surface. Not a feed of what happened — an answer to
"is Siphon working, and what do I fix next." Replaced an earlier Activity log
whose fixtures were fabricated (ML model promotions, tokenization vaults,
per-tenant streams) and contradicted the grounded surfaces.

**Layout, top to bottom.**

0. **Announcements** (`<Announcements />`, `surfaces/announcements.jsx`) — see
   its own section below. Renders above the page header because a lockout
   outranks the page title.
1. **Three pillar cards** (`.pst-grid`, 3 columns collapsing to 1 at 980px).
   Each `.pst-pill` is a button: label, state badge, a plain-language reading,
   and a footer counting sub-metrics needing attention. Clicking one opens its
   sub-metric table below the row (accordion — one at a time). The open card
   takes a `--ink-strong` border. Defaults open on **Efficacy**, the worst.
2. **Sub-metric table** — metric, value (mono), state (`ok`/`attn`), reading.
   Six rows per pillar.
3. **Needs fixing** — `.fix-row` grid (`110px minmax(0,1fr) 150px`): severity
   badge, title + evidence, and the surface to go fix it on.
4. **Volume & flow** — `.flow-row` grid (`190px 130px 74px minmax(0,1fr)`):
   stage, bar, count, and an attrition column naming what was lost and why.

**The three pillars are questions, not scores.**

| Pillar | Question | State |
| --- | --- | --- |
| Availability | Can the fleet answer at all? | degraded |
| Coverage | Is everything being looked at, with everything compiled in? | degraded |
| Efficacy | When it does look, does it catch? | **unverified** |

**Each pillar carries a percentage with a named denominator — and there is
still no composite score.** The distinction matters. Every figure measures the
one thing captioned beneath it in `.t5` and nothing else:

| Pillar | Figure | Denominator |
| --- | --- | --- |
| Availability | 99.94% | ready pod-minutes over 24h |
| Coverage | live (~98.4%) | extractable parts that reached the scanner this hour |
| Efficacy | 75.0% | evasion techniques at or above target — 9 of 12 |

A weighted roll-up of the three would be invented, because the engine reports
booleans, counts and pod state — the same discipline the Compliance screen
applies. Coverage's figure is computed from the live feed, not stated as a
constant.

`unverified` remains a real third state alongside the number: Efficacy's 75%
covers only what **is** measured, and per-label recall has no figure at all
while `held_out_recall_test` is skipping for want of a corpus. Showing Efficacy
as a green 98.8% would report the absence of a measurement as a good
measurement, so the badge contradicts the number on purpose. A short line under
the pillar row says this in the UI rather than leaving it to a reader.

**The surface is live.** A 1-second clock drives a rate strip, the throughput
chart and the volume flow, seeded from the grounded hourly totals (2 324
requests, 4 102 scan units, 389 findings, 371 delivered). Rates are means over
a trailing 10–20 samples so a single noisy second never reads as a spike, and
the underlying noise is deterministic (hash-based, not `Math.random`) so the
feed looks organic without churning on every render.

- **Rate strip** (`.pst-live`, wrapping flex row of hairline-separated tiles):
  scan units/min, requests/min, findings/min, scan p99, parts skipped/min —
  each with a 60-second `.pst-spark` sparkline. Skipped parts render in
  `--signal-attn`.
- **Throughput chart** (`.pst-chart`): a rolling 3-minute window at 1s
  resolution. Two SVG polylines — scan units/min in `--ink-soft` over a filled
  area, findings/min in `--brand` — plus `--signal-attn` ticks along the
  baseline marking parts skipped on `siphon-fs-04`. The two series are on
  independent scales (they differ ~9×), which the legend states as "own scale"
  rather than leaving the reader to assume a shared axis.
- **Pause freezes the data, not the clock.** `LiveStamp` keeps counting the
  staleness while the feed holds, and the strip drops to 62% opacity. An
  operator reading stale numbers is the failure mode, so paused state is loud.
- Live sub-metrics inside the pillars (latency, parts skipped, findings
  blocked) carry a pulsing `.pst-tick` dot so a live value is never mistaken
  for a snapshot.
- Volume flow totals are derived from the live rate rather than restated as
  constants, so the flow moves with the chart above it, and each row shows its
  per-minute rate beside the rolling-hour total.

**"Needs fixing" is ordered by silent evidence loss, not by component
severity.** A defect that returns `200` and drops the finding outranks one that
fails loudly, because nothing downstream can tell it happened. Three severity
classes: `silent loss` (returns success, drops the evidence), `data loss`
(fails loudly, data already gone), `gap` (measurable weakness, nothing lost
yet). The three `silent loss` rows are the unaudited config changes, the
barcode-less `siphon-fs-04`, and the unmeasured recall.

**The flow section's point is where evidence dies.** Seven stages from 2 324
scan requests down to 371 events delivered. Of four attrition points, exactly
one is legitimate — validation rejecting 1 435 raw matches is the filter working,
and it renders muted rather than red. The other three are marked with
`.attn-dot`: 31 parts never extracted, 23 findings never written (21
duplicate-suppressed, 2 write errors discarded), 18 never delivered to the SIEM.
Only the middle one is recoverable from Postgres.

**API.** `/v1/k8s/pods`, `/v1/capabilities`, `/v1/findings/stats`,
`/v1/evadex/summary`, corpus suite results, adapter delivery counters. The
pillar states are derived client-side — no endpoint returns a posture.

---

### Announcements (page-top, all surfaces)

**Purpose.** Broadcast between admins, and mutation lockouts — so a second
admin does not start editing a policy another one is mid-change on.

**Mount.** Written standalone and exported to `window`; currently rendered at
the top of Posture. **It should mount in the app shell above every surface** — a
lockout needs to warn you wherever you are, not only on the landing page. That
is a one-line change and the component takes no page-specific props (just
`me`, the current admin, for holder-vs-other rendering).

**One banner, not a stack.** Collapsed it is a single `.annb-bar` row: severity
badge, the most urgent item's title, a count of surfaces currently read-only, a
live-ticking age, a `+N more` chip, and a caret. Clicking expands
`.annb-body` — a 238px left rail of all active items beside the selected one's
detail. Nothing is shown twice, and the collapsed height is one row regardless
of how many announcements are active. Items sort by severity
(`lock` → `progress` → `notice`), so the lead is always the worst.

**Header indicator** (`<AnnBell go={go} />` in the shell header). Reads the same
item set as the banner, so the header cannot claim a lock the page does not
show. Renders `⚠` in `--signal-attn` when a lock is held (`⌁` otherwise) with
a status dot; clicking opens a 326px popover listing every active item with its
age, plus "Open on Posture →" which navigates. This is how an admin on any
surface learns a lockout is in effect — the banner alone only warns you on the
landing page.

**Three kinds:**

| Kind | Rail dot | Actions |
| --- | --- | --- |
| `lockout` | `--signal-attn` | View their diff · Request handoff (or Force release when stale); Release lock if you hold it |
| `in progress` | `--ink-strong` | Watch rollout |
| `notice` | `--ink-faint` | Dismiss |

A lock in the lead gives the whole banner a `--signal-attn` border and tints
the bar. Lockouts and in-progress items are **not dismissible** — only notices
are. Each detail lists the surfaces it makes read-only as `.ann-chip` mono
chips, and ages tick live on a 1-second clock (`held` / `running` / `posted`).

**The lock is advisory, and the UI says so.** The engine has no lock API:
overrides go through `/v1/overrides/*` and ConfigMap edits, neither of which
takes a holder or a lease, and Kubernetes resolves concurrent writes as
last-write-wins. So the lock coordinates admins **in this console** and cannot
stop a direct API call or a `kubectl` edit. The composer states that at the
point where an admin opts into locking, not in a tooltip.

**Two consequences of having no lease, both surfaced.**

1. **A lock can be abandoned** — closed tab, lost session — and nothing expires
   it. The console flags one held past 15 minutes as `may be abandoned` by age
   rather than silently releasing it, because silently releasing would be the
   same class of defect the rest of the console exists to expose.
2. **Force-releasing leaves no audit record.** `CONFIG` is absent from
   `VALID_EVENT_TYPES` and `siphon-api` drops the event, so breaking another
   admin's lock is unattributable. The stale-lock warning says this immediately
   above the Force release button.

**Empty state.** The component returns `null` when nothing is active — no
placeholder, no "all clear" row. A page-top banner that is always present stops
being read.

---

### Pods (Operate)

**Purpose.** Fleet truth. Nine pods grouped by their two Deployments, with the
capability drift that makes scans non-reproducible.

**Layout.** Two Deployment sections (`siphon-api`, `siphon-fs`), each a card with
a pod table: pod id (`PodId`), phase, ready, restarts, image tag, node. Below each
table, a capability flag row per distinct image, and a coverage-gap alert when the
flags are not uniform.

**Key state.** `siphon-fs-04` runs an image built without the `barcode` feature.
Two pods run `1.9.2-rc` while the rest run stable. The `siphon-fs` ConfigMap is 2
revisions behind `siphon-api`'s.

**Pod logs drawer** (`surfaces/pod-logs.jsx`). Expanding a pod row reveals its
capability flags **and** that pod's log lines. This replaced a top-level Logs
surface, which was removed: every actionable thing in a log line is already a
first-class surface (audit events → Audit, delivery failures → Integrations,
skipped parts → File scan, config drift → Overrides, restarts → Pods), the
engine ships a SIEM forwarder so the durable copy lives in Splunk or Datadog,
and `kubectl logs` beats anything the console would build. What survived is the
narrow case that actually needed a home: you are looking at one pod, something
is wrong with it, and you want its lines without leaving the row.

Scoping to a single pod is what makes the three things a real log tool needs
cheap to do honestly:

- **Structured field filtering, not substring grep.** Siphon logs through
  `tracing` with structured fields, and a grep over the rendered message throws
  that structure away then tries to recover it with a regex. Fields render as
  `key value` pairs; clicking one adds a filter condition, and a field selector
  (`level`, `event`, `target`, `finding`, `scan`, `duration_ms`) adds them by
  hand. Conditions show as removable chips.
- **Correlation to the finding or scan the line belongs to.** A line carrying a
  `finding` or `scan` id gets a `.pl-corr` button that navigates to that
  surface — `extractor.missing` jumps to the File scan row it broke,
  `siem.retry` to Integrations, `config.reload` to Overrides.
- **A severity histogram.** 15 two-minute buckets, stacked by level with error
  in `--signal-attn`. Clicking a bar **actually filters** the lines to that
  bucket; buckets with no rendered lines are disabled rather than clickable
  and inert. The footer states that the histogram counts the whole ring buffer
  while the list renders only the most recent, so a bar showing volume you
  cannot expand is explained rather than looking broken.

**What the drawer says about durability.** The ring buffer is 30 minutes,
per-pod, and lost on restart — `siphon-fs-02` restarted 3 times today, so its
earlier lines are simply gone. The durable copy is whatever the SIEM adapter
delivered, which is **not** everything: 3 retries then a drop, no dead-letter
queue.

**API.** `/v1/k8s/pods` (`PodSummary`: phase, ready, restarts, image, node),
`/v1/capabilities`, `/v1/k8s/deployments/{name}/rollout`, Cargo.toml features,
`src/audit.rs` + `src/siem.rs` for the log drawer.

---

### Findings (Operate)

**Purpose.** Queryable history, not a live tail. Time-ranged, filterable,
exportable.

**Layout.** Filter row (time range, category, action, pod, confidence floor) over
a `.tbl` of findings: timestamp, category badge, matched value (mono), pod,
policy, `Confidence`, action badge. `.tabs` for All / Needs review / Blocked /
Low confidence. A "why history is incomplete" panel sits below the table.

**Configurable table** (`surfaces/findings-table.jsx` holds the engine;
`fdCell` in `findings.jsx` holds presentation). 17 fields, 9 shown by default.

**Every field declares its provenance**, because three unlike things were
previously rendered as peers — a `.fd-srcpill` on the header and in the column
panel marks which:

| Provenance | Meaning | Consequence |
| --- | --- | --- |
| `stored` | a real column in `findings`/`scans` | filterable server-side, exportable |
| `metadata` | a key in the `metadata` JSONB | legitimately empty on direct scans; nothing validates the key |
| `derived` | computed in this console | not stored, not exportable |

Sender and Recipient were one `Sender → Recipient` column; they are now
**separate fields** so each can be sorted, filtered and grouped on
independently.

**Toolbar** (`surfaces/findings-toolbar.jsx`): search, range, filter builder,
min-severity, group-by, columns — then a saved-views row beneath.

- **Search** — one input across **every** field, not only the shown ones: an
  analyst searching an address finds it with the Sender column hidden.
  `fdSearchHit` returns which fields matched, so the UI can say where the hit
  was.
- **Range picker** — the five presets plus an absolute UTC window
  (`datetime-local` from/to). The button shows the resolved window, and the
  popover restates it as concrete timestamps. **Presets are relative to the
  newest row, not wall clock**, so a quiet fleet or a fixture does not silently
  empty the table. A custom window reaching past the retention edge is
  **clamped** and says so — `prune_findings` has already deleted those rows, so
  the emptiness would otherwise read as an absence of activity.
- **Filter builder** — ANDed conditions, each `{field, operator, value}`.
  Operators are offered per field type, so a confidence column is never asked
  to "contain" anything: text gets contains/is/is not/starts with/is empty/is
  not empty, numeric gets ≥ ≤ = ≠, boolean gets is yes/is no. Conditions on a
  `derived` field warn that they narrow the page already returned rather than
  the query — a real distinction, since severity cannot be pushed down to SQL.
  The per-column header inputs still apply on top.
- **Saved views** — a view captures columns, sort, grouping and every filter, so
  "outbound card numbers by recipient" is one click instead of six. Persisted
  with the rest of the prefs, per admin.
- Every active filter — search, condition, or column input — appears as a
  removable chip in one `.fd-fbar` row reading "Showing rows where …", with a
  single Clear all.
- **Sort** — click any header. Cycles desc → asc → unsorted. The arrow is a CSS
  triangle (no glyph dependency) and appears on hover for unsorted columns.
  Sorting uses `fdValue`, not the rendered cell, so Sender sorts by address
  rather than by its two-line block.
- **Filter** — a second header row gives every column its own input. Substring
  match, except numeric and severity columns which accept `>=0.9`, `<0.8`,
  `=1`, and boolean columns which take `y`/`n`. Active filters surface as
  removable `.fd-fchip` chips above the table with a Clear all.
- **Group** — a select over any `group:true` field currently shown: Sender,
  Recipient, Data element, Category, Action, Pod, Scanner, Context, Severity.
  Groups sort by size, collapse on click, and each header carries a severity
  tally so a large group is not automatically the urgent one. **A metadata
  group whose key is missing says why** — "not provided · scanned directly, so
  the gateway supplied no sender" — rather than rendering an unexplained empty
  bucket.
- **Preferences persist per admin** — visible columns, their order, sort and
  grouping — under `localStorage` key `siphonc2.findings.prefs`, namespaced by
  the current user. **Restore defaults** appears in the controls whenever the
  layout differs from default, and again in the column panel. The panel states
  plainly that the engine has no user-settings endpoint, so the layout follows
  the browser profile and not the account across devices — worth replacing with
  a real per-user settings store when one exists.
- The column panel reorders with arrows and groups the available fields by
  provenance, so adding Sender reads as a different kind of act from adding
  Category.

**Footer, not cards.** Four explainer cards below the table were four blocks of
prose competing with the data. Same content, now:

- A `.fd-tfoot` row pairing the result count with a **category strip** —
  clickable `.fd-cat` chips carrying each category's volume that filter the
  table on click and light up when active. The old "By category" stats card is
  gone; the numbers became a control.
- `.fd-notes` — four `<details>` disclosures, each a one-line summary the
  analyst can read at a glance and expand only when needed: severity is
  derived; sender and recipient are not schema; history is incomplete by
  design; `context_required` is always NULL. Collapsed by default, capped at
  96ch, CSS-triangle carets.

**Behaviour to preserve.** The disclosures are not optional. They name the three
reasons a finding may be absent — 60-second per-pod duplicate suppression,
discarded background write errors, retention pruning — and that severity is
absent from the export because it does not exist in the database. Export carries
a warning that `matched_text` is the sensitive value being exported. `reveal`
buttons on masked values appear on row hover only.

**API.** `crates/siphon-api/src/db.rs`, `migrations/0002_findings.sql`,
`0004_retention.sql`, `/v1/findings*`.

---

### Live Scan (Operate)

**Purpose.** A working scanner. Paste text, watch the real pipeline run.

**Layout.** `.ls-grid` — `minmax(0,1fr) 420px`, 20px gap, collapsing to one
column under 1200px. Left: a mono textarea (min-height 190px) with inline
`.ls-mark` highlights on matched spans, plus a normalization view showing the
offset map. Right: the stage list with per-stage checkboxes (stages are
toggleable, which is the teaching mechanism), a tally row (`.ls-tally`, 22px mono
values), and the findings list (`.ls-find`).

**Behaviour.** Real normalization with an offset map back to the source, keyword
prefilter, then the validate/context/gate/confidence gauntlet. Turning a stage
off re-runs the scan and shows what that stage was catching.

**API.** `/scan`, `/scan/stream`, `docs/architecture/pipeline.md`.

---

### File scan (Operate)

**Purpose.** siphon-fs multipart. Which extractor produced the text a finding was
matched in — and where an extractor was **absent** rather than empty.

**Layout.** Header tally (4 columns: files/hour, parts extracted, parts skipped,
extract p50) with an attention line naming `siphon-fs-04`. Then `.tabs`:

- **Queue** — `.ls-grid` split. Left: a `.tbl` of recent uploads (file, size, pod,
  parts, extractor chain, findings, state badge); selecting a row drives the
  right column. Right: the **extraction tree** — each part indented by depth
  (16px per level), with extractor badge and char output; a part whose extractor
  was missing shows `no output` in `--signal-attn` and a `badge--attn`. When the
  selected file has an extraction gap, a second attention card explains the cause
  and offers "Re-queue on a barcode-capable pod."
- **Extractors** — 7 rows: name, feature flag, crate, file types, p50, pod
  coverage (`3/4 pods` in `badge--attn` when not uniform), behaviour note. Plus a
  capability-drift card tying back to Pods.
- **Limits** — 6 config keys with value, unit, and on-breach behaviour. Only
  `max_file_bytes` gets `badge--ok` ("explicit"); every other row gets an
  `.attn-dot` because it degrades silently.

**The point of the screen.** `extractor_for(mime)` returns `None` when a feature
is compiled out, and a `None` extractor yields an empty part list —
indistinguishable from a genuinely empty image, with nothing logged at warn level.
A QR-carried card number on `siphon-fs-04` returns `200` with zero findings.

**API.** `POST /v1/scan/file`.

---

### FP Troubleshooter (Operate)

**Purpose.** Given a false positive, show why it matched and what would suppress
it without collateral damage. Ranked fix suggestions, best one marked with
`.fix[data-best]`.

**API.** `docs/architecture/pipeline.md`, `context-matching.md`,
`/v1/scan/explain`.

---

### Patterns (Configure) — catalog + full pattern page

**Files.** `surfaces/patterns-data.jsx` (definitions + baseline store),
`surfaces/patterns.jsx` (grouped catalog), `surfaces/pattern-page.jsx`
(full-page detail).

**The grounding rule, which is load-bearing.** Every regex and
`case_insensitive` value was read from
`crates/siphon-core/src/patterns/mod.rs`, and each pattern cites its line
(`mod.rs:21`) on the Definition tab. **Patterns whose definitions were not read
are absent from the catalog rather than approximated** — 18 of 562, and the
screen says so in a footer disclosure. A surface whose entire argument is "a
wrong specificity key silently demotes a pattern" cannot itself print invented
regexes inside a block styled as repo source. Keyword lists follow the same
rule: `kw` is populated only where `context/keywords.rs` was actually read
(Card Expiry `keywords.rs:397`, Ticker Symbol `keywords.rs:934`); elsewhere the page states the real table
carries 5,000+ entries across six languages and shows none.

**The model.** `PatternDef` carries `category`, `sub_category`, `regex`,
`case_insensitive`, `specificity`, `context_required` — no id, no state, no
validator, **no baseline**. Two facts drive everything:
`pattern_specificity()` is a hardcoded match over `sub_category` ending in
`_ => DEFAULT_SPECIFICITY` (0.40), so a missing key demotes silently; and
`>= 0.85` runs always while below it needs a keyword nearby, with dedup on an
overlapping span going to the higher score — so a mis-scored pattern **displaces
the correct finding**.

**Catalog organization.** Default grouping is by **gate**, not category or
name: always-run vs keyword-gated is the single fact that decides whether a
pattern can fire at all, and it splits the catalog into two piles that fail in
different ways. Category, Baseline and Flat are alternatives. Groups collapse,
and each header carries its count plus how many of its members are in the
baseline. Columns include 90-day hits and false positives, with the FP cell
turning red above 20%.

**Baseline.** A diamond toggle per row (and a large one on the detail page)
marks a pattern as part of the accepted floor. It is explicitly **not an engine
field** — the marks live in the overrides document, persisted per workspace to
`localStorage` under `siphonc2.patterns.baseline`, and a footer disclosure says
so. Its purpose is making **drift** reviewable: the stat strip counts drift
against the accepted set, and a banner fires when an **always-run pattern sits
outside the baseline** — something firing on every scan unit that nobody has
signed off on.

**Pattern page** (replaces the old row expansion — clicking a row opens a full
page with a breadcrumb back). A four-metric hero: would-have-fired 90d,
reviewed false positives, precision, validator. Then four tabs:

- **90-day history** — the point of the page. Counted from findings already in
  Postgres, so it is a *replay of what the pattern did produce*, not a
  simulation, and it inherits the same gaps as any findings query (duplicate
  suppression, discarded write errors, retention pruning) — stated inline.
  Sample hits are a real table: finding id, value, surrounding text, **keyword
  distance**, pod, and a true/false-positive review verdict, each row linking
  into Findings. The keyword-distance column is what the proximity control acts
  on, so tuning has something to aim at.
- **Gate & keywords** — a proximity slider (10–200 chars). Moving it
  **re-derives the whole page**: hero counts, precision, the diff line, and
  which sample hits survive. Tightening Card Expiry 50c → 20c takes it from
  188 hits / 63 false to 145 / 30, precision 66.5% → 79.3%, and drops the 38c
  false positive out of the sample list while keeping the 14c one — which is
  the honest answer, not a flattering one. Below it, the real keyword chips
  with their source line, and the five-gate ladder with non-applicable steps
  muted rather than hidden.

  **Two independent gates, three states.** This is the easiest thing on the
  screen to get wrong, and an earlier version did: it branched the "no
  proximity" card on `!context_required`, which made prefilter-gated patterns
  claim they were always-run while the gate ladder on the same tab said a
  keyword was required. The facts are separate — `specificity >= 0.85` decides
  whether the **prefilter** is skipped; `context_required` decides the distinct
  step-4 **proximity** check:

  | State | Condition | What the page shows |
  | --- | --- | --- |
  | Always-run | `spec >= 0.85` | "No keywords, no proximity" — the table is never consulted; no keyword section, no slider |
  | Prefilter + proximity | `spec < 0.85` and `ctxReq` | keyword section scoped to the entry, proximity slider, ignored-field caveat |
  | Prefilter only | `spec < 0.85` and `!ctxReq` | "Prefilter-gated, but no proximity window" — keywords decide **whether** the regex runs, but their distance is not checked, so there is nothing to tune |

  The third state is four of the 18 patterns (PAN, SWIFT/BIC, ICD-10 Code,
  Bech32) and it must not be collapsed into either neighbour. Its card names
  both levers explicitly: raising specificity to 0.85 removes the prefilter
  gate; setting `context_required` is what adds a distance requirement.

  **Keywords are scoped to the pattern, and shown wherever they can decide
  firing** — that is `spec < 0.85 || ctxReq`, not `ctxReq` alone. The section
  is titled "Context keywords for <sub_category>" and carries its source line,
  with the sub-label reading "within Nc of the match" or "anywhere in the scan
  unit" depending on which gate applies. Always-run patterns get no section at
  all. Where an entry was not read from source the copy says so, because
  inventing keywords would misrepresent which text opens the gate.
- **Test** — runs **only this pattern's regex** against pasted text, with
  matched spans highlighted, and says plainly that there is no keyword gate, no
  validator, no confidence floor and no dedup, so a highlight is a candidate
  and not a finding. Rust `\x{…}` escapes are mapped to JS equivalents; if the
  regex uses syntax the browser cannot compile, the panel says so and points to
  Live Scan instead of failing silently.
- **Definition** — the regex with its source line, the `.kv` of real fields,
  the scoring rationale where the repo documents one, and dedup rivals with who
  wins (including `tie · source order`, since declaration order is not a
  stable contract).

**The proximity control's honest caveat.** `proximity_chars` and
`context_keywords` **are** accepted by the overrides document and parsed
without error — and then **ignored** by the scanner, which uses the compiled-in
`CONTEXT_KEYWORDS` table and `DEFAULT_PROXIMITY = 50` regardless. So the
control and its diff are real; the effect is not, until the engine honours the
field. A red card states this directly under the slider. Everything above it is
a projection over recorded findings, which is exactly why it can be shown
honestly while the write cannot.

**Mutation.** No pattern-mutation endpoint exists. Baseline marks and proximity
edits are drafts in the overrides document reaching pods on reload, so changes
raise a `.diff-bar` rather than saving directly.

**API.** `crates/siphon-core/src/patterns/mod.rs`,
`crates/siphon-core/src/models.rs` (`PatternDef`, `pattern_specificity`,
`is_context_required`), `crates/siphon-core/src/context/keywords.rs`,
`crates/siphon-api/src/main.rs:1746-1807` (per-pattern keyword/proximity
resolution), `src/plugins.rs`, `tests/audit_spec.rs`.

---

### Policies (Configure)

**Purpose.** Rule ordering and what each policy actually enforces.

**Layout.** Master/detail. Left rail of policies with state badge and the
Deployments they are deployed to. Right: the selected policy's version, state,
scope, fire count, and its rules in priority order — each with name, priority
badge, condition, action. Below, per-Deployment ConfigMap revisions with a
"2 revisions behind" attention badge where they diverge.

**Behaviour to preserve.** When two rules share a priority, an `.attn-dot` line
warns that they resolve in declaration order — easy to change by accident.

**API.** `src/policy.rs`, `rulesets/`.

---

### Lists & Profiles (Configure)

**Purpose.** The real `MatchList` / `ListKind` model, and which bindings are
actually enforced.

**Layout.** Master/detail over `.tabs` for Lists and Profiles. List detail: id,
kind badge (`ListKind`: keyword, domain, email, hash, ip, url, path, other),
owner, updated, suppression count, entries, and the policies binding it.

**Behaviour to preserve.** A binding declared on a policy but absent from
`active_list_bindings` renders as **"Declared, not enforced"** with an
`.attn-dot`: the policy carries it for audit, but no pod acts on it. Profiles
that are defined but unreferenced are called out as such.

**API.** `crates/siphon-core/src/overrides.rs` (`MatchList`, `ListKind`),
`src/profiles.rs`.

---

### Overrides (Configure)

**Purpose.** "What is actually enforced right now" versus what is on disk.

**Layout.** A drift banner (`.ov-banner--drift` when current ≠ disk), a stats row
(`.ov-stats`, auto-fit 140px minimum, each stat a `.ov-stat` with a 2px left
rule), then the override table with three states per key: loaded-and-current,
loaded-but-changed-on-disk, and **on-disk-not-loaded**. Reload versus rolling
restart is a per-Deployment choice, and the modal says which pods each affects.

**Behaviour to preserve.** Three corrections the prototype documents: some
override fields are silently ignored (`context_keywords`, `proximity_chars`);
list bindings are documentation-only unless present in `active_list_bindings`; and
a heads-up that the two `1.9.2-rc` pods will receive changes and a rollback leaves
them on new values until redeploy.

**API.** `/v1/overrides/*` (which already implements diff-before-apply server
side — use it).

---

### Pipeline (Validate)

**Purpose.** Specimen-traced pipeline. Pick an input; the 20 stages light up or
gray out according to the real gating logic.

**Layout.** Specimen picker, then the 20 stages as `.trace` rows — active stages
carry `data-hot` (`--brand-soft` fill), skipped stages are `--ink-faint`. Each
stage expands to its gating reason and the evasion techniques it defeats.

**Key specimens.** ASCII plaintext, base64 payload, homoglyph + zero-width, Morse
in 6KB, QR on `siphon-fs-04` (which has no barcode extractor).

**Gating logic to reproduce.** ASCII gate on normalization stages 7–10;
alt-pass size/match/budget preconditions; per-image extractor features.

**API.** `docs/architecture/pipeline.md`, `context-matching.md`, `HANDOFF.md`.

---

### Test corpus (Validate)

**Purpose.** The material that verifies Siphon, and how much of the verification
is actually running. Four corpora, nine annotation labels, eight CI suites.

**Layout.** Header tally (corpora declared / complete & verified / files missing /
suites skipping) with the attention line below it, then `.tabs`:

- **Corpora** — `.ls-grid` split. Left: the four corpora with scope
  (committed vs fetched), size, contents, state. Right: the selected corpus's
  gates and file count; for `canada_contact_v1`, the per-file checksum manifest
  showing which of its 9 files are on disk.
- **Label coverage** — the committed labelled set by category, with an
  **examples-per-label** column that turns red below 1.2; then the "what 80/80
  recall does not mean" card; then the Canada corpus's 9 annotation labels as
  `.sd-bar` rows over 27 102 samples.
- **Suites** — the eight suites with what each gates, its corpus, duration and
  last result, each with a `.sd-why` sub-row. Then three cards: *A red check is
  ambiguous*, *Floors, not values*, *Not a fleet activity*.
- **Provenance** — sources with licences and ingest decisions, the QA result
  `.kv`, data policy, chunk audit, and the 32 noncanonical postal values.

**The point of the screen.** `fetch-corpus.sh` exits `0` when neither
`SIPHON_CORPUS_DIR` nor `SIPHON_CORPUS_BASE_URL` is set, and
`held_out_recall_test` **skips** rather than fails. So a fork — or a
misconfigured CI variable — produces a fully green build with per-label detection
recall entirely unmeasured. The behaviour is deliberate (it keeps a fork green)
but nothing in CI reports the difference between *passing* and *not run*. This is
"absence is a state" applied to testing.

**Also surfaced.**

- **80 positives over 73 sub-categories is n≈1 per label.** `detection_quality`
  asserts 80/80 and is a real regression gate, but per-label a pass means its
  single example matched — nothing measures generalisation. `FUTURE.md §1` names
  this as the top-priority gap.
- **Present-but-corrupt is worse than absent**, and the script agrees: it verifies
  even when nothing was missing, deletes offending files on mismatch, and exits
  non-zero rather than leaving a corrupt corpus in place.
- **A red `public_records_test` is ambiguous.** It pins known defects at today's
  numbers, so a failure means detection got worse *or* got better and the baseline
  is stale. The suite cannot tell them apart.
- **Recall floors sit below measured values**, so recall can fall some distance
  before anything goes red and the size of that slack is unreported.
- **These suites run in CI against a build, not against the nine pods.** A green
  corpus gate says the code detects correctly; it says nothing about whether a
  pod has the extractors compiled in to reach that code. Fleet behaviour is Scan
  Diff's question.
- Label coverage is uneven by construction — `EMAIL_ADDRESS` appears on 47% of
  samples because the sources publish one for fewer than half their records, so
  the thinnest label carries the loosest measurement.
- Licensing is handled as a first-class state: the McGill directories are public
  but excluded because no bulk/training licence was verified — **public visibility
  was not treated as reuse permission**, and the exclusion is recorded rather than
  silently omitted.

**API / source.** `tests/corpus/**`, `scripts/fetch-corpus.sh`,
`.github/workflows/ci.yml`, `FUTURE.md §1`. Note this surface reads the
repository and CI, not the running fleet — the only screen that does.

---

### Adversarial tests (Validate)

**Purpose.** Per-technique bypass rate over time.

**Layout.** `.ev-hero` two-column summary, then a bar row per technique
(`.ev-bar` track with `.ev-bar-f` fill, `data-bad` turning it `--signal-attn`),
each with percentage, run-over-run delta (`.ev-delta[data-up|data-down]`), and an
expandable detail region (`.ev-detail`, indented 174px) naming the pipeline stage
that defends it.

**Key state.** `context_removal` 46.9% (worst), `morse_code` 60.0% against a 70%
target, nested encoding 12 bypasses all at depth 4+. The 2,400-variant run only
persists 2,000 rows — the summary is complete but the row list is truncated, and
the UI says so.

**API.** `migrations/0007_evadex.sql`, `db.rs persist_evadex_run`,
`/v1/evadex/*`.

---

### Scan Diff (Validate)

**Purpose.** Run one input through two configurations and align the results. Three
axes, because three different questions use the same tool: *is the fleet
answering consistently* (pod vs pod), *what would this draft policy change*
(policy version), *what would promoting these staged patterns change* (pattern
set).

**Layout, top to bottom.**

1. `.sd-setup` — two `.sd-seg` segmented controls (6px radius, 1px `--line`,
   internal 1px dividers; active segment `--bg-subtle` + weight 500): the compare
   axis, and the input specimen.
2. `.sd-head` — a 3-column grid (`minmax(0,1.4fr) 1fr 1fr`, 20px gap, in a
   bordered 5px-radius surface): the specimen with size and composition, then
   Side A and Side B each with a `.t5` label, the target (a `PodId` when the axis
   is pods), and a one-line qualifier. Sides are separated by a `--line-subtle`
   left rule; under 1000px the grid stacks and the rules become top rules.
3. `.sd-verdict` — one sentence sized to the divergence, `--signal-attn` bordered
   and filled when anything diverges, with a "Divergent only" checkbox pushed
   right.
4. The alignment table (`.sd-tbl`). Columns: pattern (mono, strong), location
   (mono, muted), **A**, **B**, status. A and B cells (`.sd-cell`) each carry an
   action badge (`block` → `badge--attn`, otherwise `badge--neutral`) and a
   `Confidence`; an absent finding renders `no finding` in `--ink-faint`. When
   the status is `changed`, both cells get a 1px `--signal-attn` outline offset
   1px. Every divergent row is followed by a `.sd-why` sub-row: the divergent row
   drops its bottom border and its bottom padding to 6px, and the sub-row carries
   the `↳ reason` in `.t4 muted` with the real divider. Status badges:
   `same` (neutral), `action changed` (attn), `only in A` (attn),
   `only in B` (ok), `missing in B` (attn).
5. `.ls-grid` footer split. Left: **Corpus replay** — the same comparison over
   2,400 saved scan units as three `.sd-bar` rows (grid
   `minmax(0,1fr) 120px 60px`, 6px track, fill tinted by tone: `ok` → brand,
   `attn` → red, default `--ink-faint`), then the largest divergence cluster.
   Right: two explanatory cards — *How the join works* and *Not comparable*.

**The join.** Findings are matched on `(pattern_id, byte_offset)` within the same
extracted part. Where extraction itself differs — a part that exists on one side
and not the other — there is no offset to match on, so the row is reported as a
missing **part** rather than a missing finding. That is why the barcode gap
reports `missing in B` and not a confidence change. **The API does not do this
join; the console does.** Two `POST /v1/scan` calls, then align client-side.

**What can't be diffed.** Duplicate suppression is per-pod and windowed at 60s, so
a repeat scan inside the window returns fewer findings for reasons unrelated to
configuration — both sides must be run with fresh pod-local caches. And
`/v1/scan` reports no per-part `skipped[]`, so an extraction gap is inferred from
the part manifest rather than read from the response.

**Notable states in the fixture data.** Under the policy axis, `pci-strict v13`
raises the PCI confidence floor to 0.90 — which silently discards the
homoglyph-recovered match at 0.72, meaning **the draft policy makes a
normalization evasion succeed**. That row is the reason this screen exists.

---

### Audit log (Validate)

**Purpose.** The audit trail as a hash chain, not a table.

**Layout.** Per-event rows carrying `signature` / `prev_signature`. Verified links
render as solid `--brand` connectors; broken links render as dashed
`--signal-attn`. The ring-buffer-versus-file distinction is explicit.

**Two defects surfaced.** `CONFIG` is absent from `VALID_EVENT_TYPES` while
`siphon-api` emits it under `if let Ok`, so **override and policy changes are
never audited**. And `/v1/audit` cannot verify the chain, because the ring-buffer
handler receives events before signatures are set.

**API.** `crates/siphon-core/src/audit.rs`, `docs/enterprise/audit.md`.

---

### Health · Settings · Profile

Cluster health, `siphonrc` configuration with RBAC, and the user's own profile
and session. **API.** `src/config.rs`, `src/rbac.rs`, `docs/siphonrc.schema.json`.

---

### Plugins (Configure)

**Purpose.** The nav entry was originally "Models." That was a misconception —
there is no ML in this engine. `src/plugins.rs` is a registry of per-`sub_category`
validators and match-list post-processors; `crates/siphon-core/src/models.rs` is
the data model plus the `sub_category` → base-confidence table. The screen was
renamed to **Plugins** to match what exists.

**Layout.** `.tabs` for Validators / Post-processors / Base confidence, each a
`.tbl` with an explanatory card beside it.

**Two properties drive the whole screen.**

1. **Both registries are process-global `static Mutex` state, registered in-process
   at startup.** There is no runtime registration API, so the console can only
   *show* what is compiled in. Every control is read-only by construction, and
   saying so explicitly is the design.
2. **Validators and post-processors handle panics differently.** A panicking
   validator is caught and treated as a rejection — **fail-closed**, so a crashing
   plugin silently suppresses every match in its `sub_category`. A panicking
   post-processor is caught, logged at error, and **skipped** — fail-open, so the
   match list passes through untransformed. That asymmetry is invisible in the API
   and is stated on the screen.

**Also surfaced.** Validators are keyed by `sub_category` string and looked up with
a plain map get, so a key no pattern emits registers cleanly, reports no error, and
never runs — the screen lists these as **dead keys**. And a lookup miss keeps the
match, which means "no validator" and "validator passed" are the same outcome.

**API.** `src/plugins.rs`, `crates/siphon-core/src/models.rs`.

---

### Fingerprints (Configure)

**Purpose.** Document similarity, not pattern matching. Backed by
`crates/siphon-core/src/lsh.rs` — a MinHash/LSH `DocumentVault` that registers
known sensitive documents and answers "is this text similar to one of them."

**Layout.** `.tabs` over vault tables: registered vaults with their parameters
(`n`-shingle · hashes · bands), document counts, thresholds, and 24-hour hit
rates; plus a parameter-reading card that explains the pipeline in one paragraph.

**Behaviour to preserve.**

- **The vault is per-process and JSON-file backed.** Registering a document on one
  pod does not register it on the other eight. This is the multi-pod-first problem
  in its sharpest form and the screen leads with it.
- **The vault stores signatures, never plaintext.** A stolen vault file leaks doc
  ids, sensitivity labels, and metadata — not content. Worth stating as the
  positive it is.
- **Similarity is estimated from signature agreement, not true Jaccard.** At 128
  hashes the standard error is roughly 1/√128 ≈ 8.8%, so a 0.80 threshold carries
  real slop.
- **LSH banding sets a floor the query threshold cannot lower.** With 16 bands of 8
  rows the S-curve crossover is (1/16)^(1/8) ≈ 0.71. Passing a lower threshold to
  `query()` looks like it widens the search, but candidate generation still comes
  only from band collisions — so it silently under-reports.
- **Short text falls back to character shingles.** Text shorter than
  `shingle_size` words produces signatures that are not comparable with
  word-shingled documents.
- **`register()` fails silently when full.** The doc comment claims it returns
  false at `MAX_DOCUMENTS` (100 000); the signature returns `()`. It logs a warn
  and does nothing, so the caller believes the document is protected.

**API.** `crates/siphon-core/src/lsh.rs` (`DocumentVault`, `SimilarityMatch`).

---

### Integrations (Configure)

**Purpose.** Where findings go after they are found — SIEM adapters and webhooks.

**Layout.** Header tally with an attention line, then `.tabs` for Adapters and
Webhooks. Adapter rows carry the env vars that configure them, the resolved
target, and configured/active/HTTPS state. A delivery-behaviour `.kv` card states
retries and what happens on exhaustion.

**The central correction.** The console cannot test a connection, because the
backend has no health check for adapters — `create_siem_from_env()` reads env vars
and instantiates an adapter; it does not connect and does not authenticate. So
**"configured" means "an env var is set," never "this works."** The screen never
claims otherwise and offers no "Test connection" button it cannot honour.

**Also surfaced.**

- `DLPSCAN_SIEM_TYPE` is a single scalar, so **exactly one adapter is active per
  pod** — no fan-out to two destinations, and the value can drift between pods.
- Config is env-var-only and read at process start, so changing a destination
  is a **rolling restart**, not a reload. The screen offers no Apply.
- `DLPSCAN_SIEM_ALLOW_HTTP` is read once at startup and cached, so the displayed
  value is the *startup* value and may differ from the current environment.
- Retry is 3 attempts at 200/400/800ms, then the event is **dropped** with a log
  line. There is no dead-letter queue and no durable buffer, so SIEM downtime
  loses events permanently — one webhook in the fixture has been failing since
  09:14 with 0 delivered.
- Syslog is plaintext UDP by design; HTTPS is enforced by default on the
  HTTP-based adapters.

**API.** `src/siem.rs`, `src/webhooks.rs`, `docs/enterprise/siem.md`.

---

### Compliance (Validate)

**Purpose.** Four frameworks, one pass condition each. Read-only, because the
engine reports booleans — not scores.

**Layout.** A window selector, the four frameworks as a `.tbl` (framework, status,
pass condition, finding count, largest contributor, reading), then **"A pass is not
a proof"** — the caveat set — and an evidence table marking what the report does
and does not carry.

**The real model.** `framework_failing_categories()` hardcodes eight category
strings: PCI-DSS fails on *Credit Card Numbers* / *Primary Account Numbers*;
HIPAA on *Medical Identifiers*; SOC2 on *Generic Secrets* / *Cloud Provider
Secrets* / *Code Platform Secrets*; GDPR on *Contact Information* / *Personal
Identifiers*. A framework passes when the count in each of its categories is
exactly zero. There are no scores, no control counts, no partial credit, and no
requirement numbering anywhere in the codebase — a console that displayed a
compliance percentage would be inventing it.

**Why a pass is weak, and stated as such.** Every condition is a finding count
equal to zero, so **anything that stops a finding from being written also produces
a pass**:

- 60-second per-pod duplicate suppression collapses a busy hour of identical
  violations into one row.
- Retention pruning deletes findings past the edge, so a window reaching past it
  moves frameworks toward PASS over time.
- `siphon-fs-04`'s missing barcode extractor produced no text, no findings, and no
  error — a HIPAA pass cannot distinguish "no medical identifiers" from "never
  looked."
- Framework matching is **exact category-string equality**, so a custom pattern
  filed under a category outside those eight strings cannot fail any framework.
- The count ignores outcomes entirely: a finding that was *blocked* at the
  boundary fails a framework exactly as hard as one that was merely logged.

**Not in the report.** Policy version at export time is not recorded, so a report
cannot say which configuration produced its findings.

**API.** `src/compliance.rs` (`ComplianceReporter`, `ComplianceReport`,
`check_compliance`), `docs/enterprise/compliance.md`.

## Interactions & Behavior

- **Navigation.** Sidebar item click sets the surface. Active item: `--bg-hover`
  fill, `--ink-strong` text, weight 500, and a 2px `--ink-strong` left rail
  pseudo-element. The sidebar collapses to a 56px icon rail via the header
  button; the brand block reflows to vertical when collapsed. Collapse state
  should persist.
- **Theme.** `data-theme` on `<body>`, toggled from the header. Persist the
  choice.
- **Command palette.** `.cmdk` in the header with a `⌘K` affordance — designed as
  a target, not implemented in the prototype.
- **Inner tabs.** `.tab` click switches panel content within a surface. Not
  routed in the prototype; route them in the real app so a tab is linkable.
- **Nested pages.** Patterns opens a full pattern page over the catalog.
  Re-selecting a surface in the sidebar returns it to its **root view** (App
  passes a `navSeq` counter that the surface resets on), so clicking "Patterns"
  while a pattern page is open goes back to the catalog instead of appearing to
  do nothing. Any future nested page should follow the same contract.
- **Master/detail.** Policies, Lists, and File scan use a left rail or table that
  drives a detail pane. Selection is local state; the detail pane never scrolls
  independently of the page.
- **Row selection.** Selected table rows take `--bg-subtle`. Hover is
  `--bg-hover`. Rows that are not clickable must reset `cursor: default` —
  `.tbl tbody tr` sets `pointer` globally.
- **Drafts and diffs.** Editing a pattern, rule, list, or override marks it dirty
  in local state; dirty rows tint `--brand-soft` and gain a `draft` badge; the
  `.diff-bar` appears with the count. Discard clears drafts; Review opens
  `DiffModal`; only the modal commits.
- **Polling and pause.** Live surfaces show a `LiveStamp` with a pause toggle. The
  prototype's ages are static strings; wire them to real poll timestamps.
- **Stage toggles.** On Live Scan, each pipeline stage has a checkbox that re-runs
  the scan with that stage disabled. This is the surface's core interaction, not a
  debug affordance.
- **Transitions.** 80ms on button background and border. Nothing else animates.
  There are no page transitions, no skeleton shimmer, no spinners longer than a
  frame.
- **Loading and error states.** Not designed in the prototype — a known gap.
  Follow the existing app's conventions, keeping them monochrome and quiet:
  degraded data should read as a stated fact, not a colored alert.
- **Responsive.** `<meta name="viewport" content="width=device-width,
  initial-scale=1">`. The console is a desktop tool and stays one at full
  width; below that it degrades in three deliberate steps rather than
  reflowing continuously:

  | Breakpoint | What changes |
  | --- | --- |
  | 1180px | page gutters tighten (`--s6`/`--s5`) |
  | 900px | sidebar becomes an off-canvas drawer behind a hamburger; command palette loses its shortcut hint; any card wrapping a table gains `overflow-x: auto` |
  | 680px | every remaining two-column block stacks; type scale steps down (`.t1` 24→20px); the palette collapses to its icon |

  Component-level breakpoints predate these and still apply: 1200px
  (`.ls-grid`), 1100px (`.fd-grid`), 1000px (`.sd-head`, `.pl-phase`,
  `.ev-hero`), 980px (`.pst-grid`, `.flow-row`, `.fix-row`, `.annb-body`,
  `.fd-colgrid`).

  **Data tables are never reflowed into cards.** A findings row means something
  *as a row* — the columns scroll horizontally instead, because a stacked
  "Sender: … Recipient: …" card destroys the comparison that makes the table
  worth reading. The card scrolls, not the page.

  **The drawer.** `.sidenav` goes `position: fixed` and translates off-canvas;
  `[data-nav-open="1"]` on `.shell` slides it in over a scrim, and selecting a
  nav item closes it. Inside the drawer the collapsed icon-rail state is
  **overridden back to full labels** — a 52px rail inside a drawer the user
  just opened on purpose is the wrong tradeoff — and the collapse control is
  replaced by a close button.

  **One trap worth knowing.** The shell's `1fr` content column is
  `minmax(auto, 1fr)`, which refuses to shrink below its min-content width, so
  a single wide child pushes the entire layout past the viewport — at phone
  size *and* at desktop widths where a wide table lands. Both shell columns are
  `minmax(0, 1fr)` on the **base** rule (not only at a breakpoint), with
  `min-width: 0` on `main`, `.page` and the header; overflow is then handled
  locally by the blocks that own it (tables scroll, control bars wrap). Verified
  at 390px, 820px and 924px with zero document overflow.

## State Management

Per-surface local state in the prototype; in the real app most of it becomes
server state with a caching layer.

**Global (app shell):** `surface` (route), `theme`, `navCollapsed`.

**Per-surface UI state:** active inner tab, selected master row (`sel`), filter
values, `paused`, and — where mutation exists — a `drafts` map of
`id → changed fields` plus modal open state.

**Server state, by surface:**

| Surface | Reads | Writes |
| --- | --- | --- |
| Posture | pod state, capabilities, finding + delivery counters, evadex summary, corpus suite results | — |
| Pods | `/v1/k8s/pods`, `/v1/capabilities`, per-pod log ring buffer | rollout restart |
| Findings | `/v1/findings` (paged, rate-limited), `/v1/findings/stats` (cached, lags) | export; column/sort/group prefs to `localStorage` |
| Live Scan | `/scan`, `/scan/stream` | — |
| File scan | `/v1/scan/file`, part manifest | upload, re-queue on a chosen pod |
| Patterns | `/v1/patterns` | staged edits → apply |
| Policies | policy list + rules + ConfigMap revisions | rule edits → apply |
| Lists & Profiles | `MatchList` + profiles + `active_list_bindings` | list edits → apply |
| Overrides | `/v1/overrides` current + on-disk | apply, reload, rolling restart |
| Pipeline | pipeline definition + specimen trace | — |
| Test corpus | corpus manifests + checksums, CI suite results | fetch, verify checksums |
| Adversarial tests | `/v1/evadex/runs`, `/v1/evadex/summary` | trigger run |
| Scan Diff | two `POST /v1/scan` calls, corpus replay job | save regression case |
| Plugins | validator + post-processor registries (per pod, read-only) | — |
| Fingerprints | `DocumentVault` per pod, JSON-backed | register / unregister a document |
| Integrations | env-derived adapter config per pod, webhook delivery state | — (restart-only) |
| Compliance | findings query over a window + framework booleans | export JSON / HTML / text |
| Audit | `/v1/audit` (chain unverifiable server-side) | — |

**Transitions worth naming.** Draft → reviewed → applied → propagating →
enforced. The last two are distinct and both are visible: an applied config is not
enforced until every pod in the Deployment has picked it up, and the console shows
the gap rather than optimistically claiming success.

## Backend findings

Discovered while building, and surfaced in the UI. Several are worth fixing in the
engine rather than accommodating forever.

1. **Config changes are never audited.** `CONFIG` is missing from
   `VALID_EVENT_TYPES`; `siphon-api` emits it inside `if let Ok`, so it is dropped
   silently. Override and policy changes leave no audit record.
2. **`/v1/audit` cannot verify its own chain.** The ring-buffer handler receives
   events before signatures are set.
3. **Missing extractors are indistinguishable from empty input.**
   `extractor_for(mime)` returns `None` when a feature is compiled out; the scan
   returns `200` with zero findings and no warn-level log.
4. **`/v1/scan` has no per-part `skipped[]`.** A truncated or partially extracted
   scan is byte-identical in the response to a complete one.
5. **Some override fields are parsed and ignored.** `context_keywords` and
   `proximity_chars` are accepted and have no effect.
6. **Policy `list_bindings` are documentation-only** until merged into
   `active_list_bindings`.
7. **`context_required` is hardcoded to `None`** on insert, so the column is
   always NULL — do not filter on it.
8. **Evadex runs truncate at 2,000 rows** while the summary covers the full run —
   the row list and the aggregate disagree by construction.
9. **Duplicate suppression is per-pod and 60s-windowed**, which makes repeat scans
   non-comparable unless caches are fresh.
10. **The `siphon-fs` ConfigMap lags `siphon-api`'s** by 2 revisions in the
    observed state; nothing surfaces this in the API.
11. **`DocumentVault::register()` fails silently at capacity.** Its doc comment
    says it returns false when full; the signature returns `()`. At
    `MAX_DOCUMENTS` (100 000) it logs a warn and does nothing, so the caller
    believes the document is protected. Should return a `Result`.
12. **LSH banding sets a similarity floor the query threshold cannot lower.** With
    16 bands of 8 rows, candidates only surface above ≈0.71 regardless of the
    threshold passed to `query()` — a lower threshold silently under-reports
    rather than widening the search.
13. **The document vault is per-process.** Registering a fingerprint on one pod
    protects nothing on the other eight, and there is no fleet-wide registration
    path.
14. **Compliance framework matching is exact category-string equality** against
    eight hardcoded strings. A custom pattern categorised outside that set cannot
    fail any framework, and the check ignores whether the finding was blocked or
    merely logged.
15. **Validators fail closed, post-processors fail open.** Both catch panics; a
    panicking validator drops the match, a panicking post-processor is skipped and
    the list passes through. The asymmetry is deliberate but undocumented.
16. **SIEM adapters have no health check and no dead-letter queue.**
    `create_siem_from_env()` never connects or authenticates, so "configured"
    cannot imply "working"; and after 3 retries an event is dropped with only a
    log line. `DLPSCAN_SIEM_TYPE` is also a single scalar, so a pod can forward to
    exactly one destination.
17. **An absent corpus produces a green build.** `fetch-corpus.sh` exits 0 with no
    source configured and `held_out_recall_test` skips, so detection recall can be
    entirely unmeasured with every check passing. CI should distinguish *passed*
    from *not run*.
18. **The labelled set is n≈1 per sub-category** — 80 positives over 73
    sub-categories — so `detection_quality` cannot support a recall claim per
    label, only a regression signal.
19. **`public_records_test` baselines pin known defects**, making a red run
    ambiguous between a regression and an improvement that stales the baseline.
20. **There is no mutation lock and no lease.** Nothing in the API takes a
    holder for a config change, so two admins editing the same policy resolve
    as last-write-wins with no warning to either. Console-level locking can only
    ever be advisory until the engine offers a lease.

## Assets

- **Fonts.** Inter (400/500/600) and JetBrains Mono (400/500), loaded from Google
  Fonts in the prototype. Self-host or use the codebase's existing loader.
- **Icons.** Unicode glyphs (`⏱ ▦ ◫ ⏿ ⚯ ▤ ⊘ ⌘ ⇄ ≡ ⊞ ⧉ ↗ ⑂ ⊕ ⇋ ✓ ≣`) chosen to
  avoid an icon dependency in a throwaway prototype. **Replace these** with the
  target codebase's icon set — glyph metrics are inconsistent across platforms
  and several will render as boxes on Windows.
- **Brand mark.** Inlined as a base64 PNG in the sidebar; inverted in dark mode
  via `filter: invert(1) brightness(1.05)`. Swap for the real asset.
- No illustrations, photography, or decorative imagery anywhere.

## Files

| File | What it is |
| --- | --- |
| `Siphon-C2 v2.html` | The prototype. Design tokens and all shared CSS in the `<style>` block; shell, nav, primitives, and 8 surfaces inline at the bottom. |
| `surfaces/*.jsx` | One file per larger surface, loaded as Babel-transpiled scripts. Fixture data at the top of each file documents the shape that screen needs. |
| `github.md` | Repo association, the screen → repo-file map, and the running sync record. **The screen map is the authoritative index** of which backend files each surface was built from. |
| `C2 Build Plan.html` | Endpoint inventory mapped to console surfaces, with gaps and the build order that produced this prototype. |
| `Siphon-C2 Wireframes.html` | Earlier low-fidelity exploration. Superseded — for context only. |

### Reading order

1. This README.
2. `github.md` — the screen map tells you which Rust files back each screen.
3. `Siphon-C2 v2.html` — tokens, then `NAV`, then the primitives
   (`PodId`, `Confidence`, `LiveStamp`, `DiffModal`).
4. `surfaces/scandiff.jsx` and `surfaces/filescan.jsx` — the two screens that best
   demonstrate the "absence is a state" principle. Then `surfaces/fingerprints.jsx`
   and `surfaces/compliance2.jsx`, which apply it to per-pod vault drift and to
   what a framework pass does not prove.
5. `C2 Build Plan.html` — what is not built and why.

### Suggested build order

Primitives and shell → Pods → Findings → Overrides (establishes
diff-before-apply) → Patterns and Policies (reuse it) → Live Scan → File scan →
Pipeline → Scan Diff → Test corpus → Adversarial tests → Audit → Compliance → Plugins →
Fingerprints → Integrations → Posture → Settings. Posture comes last of the
screens because every pillar reads from a surface built before it. Scan Diff comes late because it
depends on the scan plumbing being real; Compliance comes after Findings because
it is a query over them; Plugins and Integrations are read-only and can land any
time after the shell.
