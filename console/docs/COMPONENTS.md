# Siphon-C2 — component contract

The build spec for the console. `Siphon-C2 Kit.html` is the rendered
companion — open it beside this file; it shows every state described here.

**Read the four hard rules first.** They are the reason the console is
legible, and every one of them is cheap to break by accident.

---

## Hard rules

1. **Two colors carry meaning in chrome, and only two.** One emerald for
   good/confirmed, one red for needs-attention. Everything else in the
   interface is monochrome. A new *state* gets a badge, a dot, or a border —
   never a new hue. Tailwind's default palettes are unset in `tokens.css`, so
   `bg-blue-500` fails to compile. That is the enforcement mechanism, not an
   inconvenience to work around.

   There are exactly two exceptions: the **severity** and **classification**
   scales. They are *ordinal scales applied to data*, not accents applied to
   chrome, and they never appear in navigation, buttons, or panel furniture. A
   scale earns hues because rank is the information; an accent does not.
2. **Diff before apply.** No mutation is committed from the surface that
   composed it. Edits accumulate as drafts, a sticky bar counts them, and a
   `ConfirmDialog` shows the server-computed diff plus which pods receive it.
   Patterns, Policies, Lists, Overrides — no exceptions.
3. **Absence is a state.** "Zero findings" and "the extractor that would have
   produced findings was not in the build" are different facts and get
   different components (`EmptyState` vs `AbsenceNote`). Before rendering any
   zero, check capabilities. This is the single most important idea in the
   design.
4. **Mono is for data only.** Ids, offsets, config keys, hashes, regexes,
   code. Never prose, labels, or headings.

Two more that are almost as load-bearing:

- **Detail is hidden by default.** Sections collapse to one line that carries
  its own summary — the count, the state, the reason to open it. A closed
  disclosure whose label is just a noun is a bug.
- **URL state, not component state.** Filters, sort, range, tab, selected row
  live in typed TanStack Router search params. A pasted URL reproduces a
  colleague's exact view.

And one that governs every number on screen:

- **No percentage without its fraction; no fraction without a named unit; no
  stat without its trend.** 96.6% reads identically whether it is 28/29 or
  12,516/12,956, and those warrant different responses. See `Pillar`.

---

## Stack

| Layer | Pick |
| --- | --- |
| Build | Vite — static output, no runtime |
| Language | TypeScript, strict |
| UI | React 19 |
| Server state | TanStack Query |
| Table | TanStack Table + TanStack Virtual |
| Routing | TanStack Router (typed search params) |
| Styling | Tailwind v4, CSS-first tokens |
| Primitives | Vendored into `src/ui/`; Radix only where noted |
| Palette | cmdk |
| Tests | Vitest + Playwright |

Serve the built bundle from the Rust binary (`rust-embed` + a static handler
in siphon-api). One artifact, one image, one SBOM. Node exists at build time
and never reaches production.

**Not used, deliberately:** Next.js (no SSR need; a Node runtime in a
static-Rust-binary product is a product decision, not just infra), Redux or
Zustand (~95% of state is server state with a freshness problem), runtime
CSS-in-JS, GraphQL (one first-party REST API), any component library with a
required theme provider.

---

## Security

**Do not put the bearer token in `localStorage`.** Admin endpoints return
unredacted matched values, so an XSS in this console is credential theft
against those same endpoints. Terminate auth at the proxy with an httpOnly,
`SameSite=Strict` cookie, or hold a short-lived token in memory only.

`MaskedValue` renders masked by default. Reveal is component-local, dies with
the unmount, is never persisted or put in the URL, and fires an audit event.

The only thing that persists to `localStorage` is per-admin column
preferences, with a restore-defaults path.

---

## Routes

Eight. Each is a question an operator asks. The v2 prototype's 21 verb-led
surfaces are all still here — reparented as tabs, sheets, or sections.

| Route | The question | Absorbs |
| --- | --- | --- |
| `/` | Is it healthy, and what needs me? | Posture, Announcements (page-top banner) |
| `/findings` | What did it catch? | Findings, stats strip, saved views |
| `/scan` | What would it do with *this*? | Live Scan, File scan, Scan Diff, FP troubleshooter, Pipeline |
| `/patterns` | What can it detect? | Patterns catalog, pattern detail |
| `/policies` | What are we telling it to do? | Policies, Lists & Profiles |
| `/running` | What is actually running right now? | Overrides drift, Pods, pod logs |
| `/assurance` | Can I prove any of this? | Compliance, Adversarial tests, Test corpus, Audit chain |
| `/settings` | How is it wired? | Config, RBAC, Integrations, Plugins, Fingerprints |

Sub-views are tabs with a typed `?tab=` param. A detail view that deserves a
URL is a child route; a detail view read *beside* a list is a `Sheet`.

---

## Components

`local` = write it, own it, no dependency. `radix` = wraps one Radix
primitive because focus trap / portal / dismiss layer / roving tabindex are
where real accessibility bugs hide. `tanstack` / `cmdk` = as named.

### Primitives

**`Button`** — `src/ui/button.tsx` · local
```ts
type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'  // default 'default'
  size?: 'sm' | 'md'                                    // default 'md' (30px); sm = 24px
  loading?: boolean          // spinner + disabled + aria-busy
  icon?: React.ReactNode     // leading; omit children for icon-only
}
```
At most one `primary` per view. `danger` is outline, never filled. `loading`
comes from the TanStack mutation, never from local `useState`.

**`Badge`** — `src/ui/badge.tsx` · local
```ts
type BadgeProps = { tone?: 'neutral' | 'ok' | 'attn' | 'muted' | 'count'; dot?: boolean }
```
`ok` and `attn` are the only colored tones. Badge text is a state, not a
sentence — two words maximum.

**`Severity`** — `src/ui/severity.tsx` · local
```ts
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
<Severity level={f.severity} />                 // pill — detail views, alerts
<Severity level={f.severity} variant="bare" />  // rail + word — table cells

export const SEVERITY_ORDER: Severity[] = ['info','low','medium','high','critical']
export const atLeast = (a: Severity, b: Severity) =>
  SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b)
```
Severity is **ordinal, so the ramp has to read as a rank**: grey → blue →
yellow → orange → red, the sequence operators already carry from every other
security tool. Informational is grey so the bulk of traffic stays quiet, and
**critical is red and the only solid fill in the console** — it escalates by
weight as well as hue, so it wins against the four tints without being louder.

**Color never carries the level alone.** Every instance renders its word, and
the four-bar rail gives an ordinal cue that survives grayscale, color
blindness, and a printed export — which matters because blue-vs-grey and
yellow-vs-orange are exactly the pairs that collapse under deuteranopia.

Severity is **derived, never stored** — the engine emits a confidence score
and a category. Derive it in one place (`lib/severity.ts`) and expose the
inputs on hover; "why is this critical?" must have an answer.

In lists, render `bare`. The solid fill more than once per viewport destroys
its meaning.

**`Classification` / `RegimeList` / `ClassificationStrip`** — `src/ui/classification.tsx` · local
```ts
type Classification = 'public' | 'internal' | 'confidential' | 'restricted'
type Regime = 'pci' | 'phi' | 'pii' | 'sox' | 'gdpr'
type LabelSource = { kind: 'asserted' | 'inferred'; authority: string; verified: boolean }

<Classification tier={a.classification} source={a.labelSource} />
<RegimeList regimes={a.regimes} />
```
Classification answers *how sensitive is this data*; severity answers *how
urgently does this need a human*. They are independent — Restricted data
handled correctly is not an incident — so **they must not share a visual
language.** Classification is a different *shape*: square-cornered, uppercase
mono, left edge bar, in a slate-to-violet ramp **deliberately clear of
severity's blue** so one hue never means two things. A Restricted label can
never read as an alert.

**Regulatory regimes are categorical, not ordinal**, so they stay monochrome.
PCI is not "worse than" PHI, and coloring both is how a two-color system
becomes a twelve-color one.

`source` is required in detail views: a classification is either asserted by
an upstream label (MIP, Purview, a filesystem tag) or inferred by this engine
from what it matched. Those are different levels of trust, and an asserted
label the engine never verified must say so.

If the tenant's taxonomy has different tier names, remap onto these four; do
not add a fifth.

**`Field` / `Input` / `Select` / `Checkbox` / `Switch`** — `src/ui/field.tsx` · local
```ts
type FieldProps = { label: string; hint?: string; error?: string; children: ReactElement }
type InputProps = React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }
```
`Field` generates the id and wires `aria-describedby` / `aria-invalid`. Do not
pass your own id. Machine values set `mono`.

**`MonoValue` / `MaskedValue` / `Kbd`** — `src/ui/mono.tsx` · local
```ts
<MonoValue value={f.id} truncate="middle" copy />
<MaskedValue value={f.matched_value} mask="pan" onReveal={audit.reveal} />
```

### Composites

**`PageHeader`** — local. One per route. The description is where a screen
states its own limits (retention edge, cache lag, what it cannot show).

**`Card`** — local. Bordered box, three optional slots, no shadow, **no
nesting**. A card in a card should have been a plain section.

**`Disclosure`** — local, native `<details>`. The load-bearing
simplification: no JS, no state, ⌘F finds text in closed sections. Shared
`name` makes a group mutually exclusive. Never nest.
```ts
<Disclosure label="Governance" summary={<Badge tone="attn">Never audited</Badge>} />
```

**`Tabs`** — radix. Selection is a search param.

**`DataTable`** — tanstack. The reason React is in this stack.
```ts
<DataTable
  columns={findingColumns}    // ColumnDef<Finding>[]; each declares provenance
  data={rows}
  state={{ sorting, columnVisibility, grouping }}   // from search params
  virtual                     // required over ~200 rows
  isLoading={q.isPending}     // skeleton rows, not a spinner swap
  emptyState={<EmptyState … />}
  onRowActivate={…}
/>
type Provenance = 'column' | 'metadata' | 'derived'
```
Rows scroll horizontally inside the card; they never reflow into stacked
cards — a findings row only means something as a row. Keyboard: `J`/`K` move,
`↵` opens, `X` selects. Every column declares provenance: a metadata JSONB
key can be legitimately empty, a derived column cannot be exported, and the
UI must say which.

**`Toolbar`** — local. Search, ANDed typed filters, range, view controls. No
state of its own. Range presets resolve against the newest row, not wall
clock — otherwise a quiet fleet reads as an empty table. The range picker
clamps at the retention edge and reports requested-vs-clamped.

**`KeyValue`** — local. `<dl>` of facts about one thing; replaces the
paragraph. Rows may carry a `provenance` note.

**`DiffView`** — local. Hunks are **server-computed** (`/v1/overrides/diff`).
A client-side diff can disagree with what the server will write, and this is
the last thing an operator reads before changing enforcement. Always names
the target deployment, pod count, and mechanism (reload vs rolling restart),
plus the consequence in plain words.

**`Pillar`** — local. A headline number with a **named denominator**, never a
composite score.
```ts
type PillarProps = {
  label: string
  numerator: number | null    // null ⇒ renders `unverified`, never 0
  denominator: number | null
  unit: string                // REQUIRED — a denominator with no name is a score
  format?: 'pct' | 'count' | 'ratio'
  delta?: { pct: number; period: string } | null   // null ⇒ no trend shown
  polarity?: 'higher-better' | 'lower-better' | 'neutral'   // default 'higher-better'
  note?: string
}
```
Three rules, each with a failure behind it:

- **Always show the numerator and denominator as real counts.** A percentage
  alone hides its sample size. The fraction is not supplementary detail; it is
  what makes the percentage safe to act on.
- **Always show the change, with arrow and color decoupled.** The arrow is
  derived from `Math.sign(delta.pct)` — what the number did. The color is
  derived from `polarity × sign` — whether that is good. Never conflate them:
  a rising evidence-attrition metric must arrow **up** and read **red**.
  ```ts
  const tone = polarity === 'neutral' || pct === 0 ? 'flat'
    : (pct > 0) === (polarity === 'higher-better') ? 'better' : 'worse'
  ```
  Deltas compare periods of equal length, state the period in the copy, round
  to one decimal, and clamp flat below ±0.05% — an indicator that twitches on
  noise trains operators to ignore it. No comparable prior period means
  `delta={null}` plus the reason, never a fabricated 0%.
- **`numerator === null` renders the word `unverified`**, with no trend at
  all. There is no zero fallback and nothing to compare.

**`EmptyState` / `AbsenceNote`** — local. See hard rule 3.

**`Banner`** — local, mounted in `AppShell` above every route.
`kind: 'lockout' | 'progress' | 'notice'`; only notices dismiss. The lock is
advisory and the copy says so — the engine has no lock API, so it coordinates
admins but cannot stop a direct `/v1/overrides` call, which Kubernetes
resolves last-write-wins. A lock held past 15 minutes is flagged
possibly-abandoned rather than silently expired.

### Overlays

**`ConfirmDialog`** — radix. The only place a change commits. States the
consequence, not the action.

**`Sheet`** — radix. Right drawer for detail read beside a list. If it
deserves a URL it is a route.

**`Menu` / `Tooltip`** — radix. **A tooltip may not carry information
required to complete a task** — unreachable by touch and by many keyboard
paths. If it matters it is a hint or a provenance note.

**`CommandPalette`** — cmdk. The real navigation: routes, pods, pattern ids,
global actions. Sources are registered per-route, not hardcoded, so the
palette stays complete as screens are added.

**`Toast`** — radix. Confirms an async mutation landed. Never for errors that
need action — those render inline where the fix is.

### Shell

**`AppShell`** — local.
```tsx
<AppShell>            {/* __root.tsx */}
  <BannerStack />
  <Outlet />
  <CommandPalette />
  <ToastViewport />
</AppShell>
```
Sidebar → off-canvas drawer at 900px; full stack with reduced type scale at
680px. Queue depth is the only number in the nav.

The logo slot takes the real Polygon Cyber mark — `assets/logo-mark.png`
(1304×1462, transparent; `assets/octopus-64.png` is a pre-scaled 64px copy) —
at a **22px cap height, never smaller**: the hexagon lattice behind the
octopus turns to mud below that. The mark is mid-tone teal on transparent, so
it holds on both the light and dark header with no second file and no
inversion filter. Do not substitute a colored square, a glyph, or a
re-drawn SVG.

---

## Theming

One place. `tokens.css` maps Tailwind utility names to CSS variables that
point at a raw layer swapped by `[data-theme]` on `<html>`. So `bg-surface`,
`text-ink` and `border-line` are correct in both themes with **no `dark:`
variant anywhere in component code**.

A `dark:` utility in a component means a value escaped the token layer. Add a
token; do not branch the component.

Focus is one ring, defined once in `tokens.css`. Do not restyle it per
component — keyboard is a primary input mode here.

---

## Not in the kit

Considered and rejected. These are answers, not gaps.

| Absent | Because |
| --- | --- |
| Accordion | `Disclosure` with a shared `name` is the native accordion |
| Breadcrumbs | Eight routes, one level deep |
| Avatar / user chrome | A handful of named operators; a name in text is enough |
| Icon set | Five inline SVGs. An icon repeating the adjacent word is noise |
| Progress bar | Skeletons for loading, in-button spinner for mutations |
| Client state store | See stack notes |
| Chart library | One sparkline, one throughput line, both hand-drawn SVG |
| Toast for errors | A dismissible error is a lost error |
| Theme provider | `data-theme` + the token layer |
| A second accent color | The visual system *is* that this did not happen. Severity and classification are ordinal scales on data, not accents |
| A fifth classification tier | Four steps is the edge of glanceable; past that every scheme collapses to "sensitive" and "not" |
| Colored regulatory regimes | Categorical, not ordinal. PCI is not worse than PHI |
| A composite posture score | The engine reports booleans and counts. A blended number is one nobody can act on |

---

## Fixture data

Every value in the prototype was chosen to represent a real state, including
the awkward ones, and documents the shape each screen needs — but it is all
hardcoded and must be replaced with real API calls. The backend findings the
console deliberately surfaces (CONFIG absent from audit event types,
`context_required` always NULL, `proximity_chars` parsed then ignored,
process-global plugin and fingerprint registries, extractor coverage gaps,
`_ => DEFAULT_SPECIFICITY` silently absorbing typos) are documented in
`design_handoff_siphon_c2/README.md`. They are defects the console makes
visible, not design fiction — several should be fixed in the engine rather
than papered over in the UI.
