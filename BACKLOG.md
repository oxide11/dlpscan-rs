# Backlog

Items deliberately pushed out of the PR they came up in, with enough context
that whoever picks them up next has the working memory the original author
had. Sorted by component; within a component, no implied order — pick
whichever has the most leverage at the time.

When a PR notes something as "out of scope this commit," that line belongs
here. When an item lands, delete its bullet (its history is in `git log` and
`CHANGELOG.md`).

## siphon-api

- **Multi-key role mapping.** RBAC enforcement landed in `siphon-api 2.2.0`
  on a single-key model: a configured `SIPHON_API_KEY` resolves every
  authenticated request to `Role::Admin`; the open-dev fallback (no key
  configured) maps to `Role::Operator`. The schema for finer-grained
  resolution is already in `siphon::rbac::resolve_role` — what's missing
  is the wiring to feed it a `HashMap<key_hash, Role>` parsed from a
  JSON file or a Kubernetes Secret. Shape: a new `SIPHON_API_KEYS_PATH`
  env var pointing at a JSON document like
  `[{"key_sha256": "<hex>", "role": "analyst", "label": "ops-team"}, …]`,
  loaded at startup into a `HashMap<[u8; 32], Role>` on `AppState`. The
  bearer-key compare in `auth_middleware` then becomes a constant-time
  lookup that yields the matching `Role` (falling back to the existing
  single-key Admin path when only `SIPHON_API_KEY` is set, for back-compat).
  Adding new key types (e.g. mTLS client cert SHA → role) is a sibling
  resolver under the same plumbing. (Source: claude/cross-cutting-rbac PR.)

## siphon-ir

- **Drag-to-reorder columns in the Findings Queue.** The `visibleCols` array
  in localStorage `ir:queueColumns` is currently unordered with respect to
  the registry — toggling a column on inserts at its natural position in
  `FINDINGS_COLUMNS`. Letting the analyst drag headers to reorder is a
  shape change: `visibleCols` becomes meaningfully ordered, and the panel
  needs a drag handle per checkbox. (Source: claude/ir-findings-queue PR.)

- **Sort support for `user` / `filename` / `hash` columns.** The registry
  marks these `sortable: false` because `makeFindingComparator` doesn't know
  how to compare them. Teach the comparator the metadata-key fan-out
  (`md.user || md.sender || md.recipient || …` for user, etc.) and flip
  the registry flag. (Source: claude/ir-findings-queue PR.)

- **Surface-file extraction of `FindingsQueue` into
  `docs/wireframes/ir/surfaces/findings.jsx`.** The IR side of
  `siphon-ir.html` is one ~10k-line `<script type="text/babel">` block —
  the c2-side surface-split pattern (sync-shared.sh markers) doesn't apply
  cleanly until that mega-block is split. Doing the extraction is its own
  structural refactor PR; doesn't need to ride along with feature work.
  (Source: claude/ir-findings-queue PR.)

- **Pin the Findings Detail facts box to a deterministic min-height.**
  The detail-header refactor stopped the page header from jumping on
  prev/next, but the new "finding facts" box still grows/shrinks vertically
  as chip wrapping changes between findings, which can shove the document
  preview a row or two up/down. Add a `min-height` based on the worst-case
  chip set (or a CSS `aspect-ratio` lock). Defer until the analyst flags
  the vertical jump as a real problem; the horizontal jump (which was the
  reported bug) is fixed. (Source: claude/ir-detail-header-fix PR.)

- **Custom queues for the Findings Queue.** The grouping registry
  (`GROUP_BY_OPTIONS`) currently exposes four canned modes: user, document,
  scan, hash. The roadmap also asks for "custom queues" — a saved
  combination of (filter set + grouping + sort + visible columns) the
  analyst can name and recall. Treat this as a new top-level concept on
  the queue page (a "Saved queues" select alongside the existing controls)
  with its own localStorage key like `ir:queueCustomQueues = [{name, snapshot}]`.
  (Source: claude/ir-findings-grouping PR.)

- **Continuation marker on group headers spanning page boundaries.** When
  a group spans pages 3–6, page 4 currently shows the same header it
  shows on page 3 with no signal that the group started earlier. Worth
  adding a small "(continued)" annotation — knowable via `pageRows[0]`'s
  group key matching some same-key row on a previous page (or just
  `page > firstPageOf(groupKey)`). Cosmetic; defer until an analyst notes
  the ambiguity.
  (Source: claude/ir-findings-grouping PR.)

- **Move Timeline from Analyze → Correlate.** Today the IR surface
  registry has Timeline under the Analyze workspace; conceptually it
  belongs with Correlate (it cross-references findings by ts + span,
  same lens as Pivots / IOC Lookup). The move is one line in
  `IR_SURFACES` plus any default-surface-picker that hardcodes
  `timeline` as Analyze's default. Verify nothing reads the workspace
  attribute of the timeline entry from outside the registry before
  flipping. (Source: roadmap.)

- **Case export with redaction (Evidence workspace).** Analysts need
  to package a set of cases as a single bundle for second-line review
  / audit handoff, with sensitive values redacted before the bundle
  leaves the analyst's hands. The export should: walk the selected
  cases' findings, apply a redaction pass to every matched span (the
  same redactSpan helper the DocumentPreview's "copy redacted" button
  uses), bundle the redacted text + metadata + chain-of-custody log
  into a zip + signed manifest. Lives under
  `Evidence → Export Bundle` (the existing surface; today it's a
  Stub). (Source: roadmap.)

- **Redaction tool in the Evidence top menu.** Standalone surface
  for ad-hoc redaction work that doesn't ride a case-export flow:
  paste text, select redaction strategy (replace with X's,
  category-named placeholder, hash, tokenize), preview, copy. Reuses
  the highlight engine (applyHighlights) to mark what got redacted
  and expose a side-by-side view. Sibling to the existing
  Crypto Workbench under Analyze, but lives in Evidence per the
  roadmap layout. (Source: roadmap.)

- **Real metadata extraction for the Forensics surface.** The
  ForensicsSurface ships with FORENSICS_FIXTURE today — six mock
  files with realistic Office RSID / PDF Creator-Producer / XMP
  metadata. The cluster computation is real (sharedField +
  computeAuthorClusters), but the data is hand-rolled. Wire to a
  real source by adding a siphon-fs endpoint that returns the
  metadata for a finding's source document: parse the OOXML
  `core.xml` / `app.xml` / `document.xml` (RSIDs live in the
  document XML's `w:rsid*` attributes), the PDF Info dict + XMP
  packet, and stamp the result into the finding's metadata. The
  surface's data shape is already aligned with what the parser
  would return. (Source: claude/ir-forensics-surface PR.)

- **Forensics: Pivot from a finding to its file's metadata.** When
  the analyst drills into a finding from the queue, give them a
  "Inspect file metadata" jump that opens Forensics with that
  file pre-selected and the cluster panel scoped to it. Mirrors
  the irPivotToQueue pattern from the Who/What panels.
  (Source: claude/ir-forensics-surface PR.)

- **Real document parsing inside the Document Preview chromes.** The
  image / PDF / Word / spreadsheet chromes all render synthesised content
  today: the image chrome is a mock canvas with overlay markers, the PDF
  and Word chromes wrap `<pre>{segs.map(renderSeg)}</pre>` in
  paper-styled containers, the spreadsheet chrome builds rows from
  `allFindings`. Each chrome is shaped so the synthesised body slots out
  for a parsed body when siphon-fs eventually serves
  `/v1/findings/{id}/payload`:
    - **PDF**: `pdf.js` to render the actual page with text-layer
      highlights anchored to siphon-fs's extracted-text offsets.
    - **DOCX**: `mammoth.js` to convert .docx to HTML, then highlight
      spans inside the rendered body.
    - **XLSX / CSV**: `SheetJS (xlsx)` to parse the workbook; map each
      finding's character span back to the (sheet, row, col) it came
      from and highlight at cell granularity.
  All three libraries are non-trivial in size; deferred until the backend
  serves real bytes. (Source: claude/ir-document-preview PR.)

- **Multi-page PDF rendering.** The PDF chrome currently shows a single
  synthesised page with a `page 1 of 1` indicator. Once real PDFs flow
  through the pipeline, paginate by parsed-text length (or by `pdf.js`'s
  natural page boundaries) and wire prev/next page navigation to the
  indicator. Schema doesn't change — `preview.body` becomes
  `preview.pages: string[]` or similar.
  (Source: claude/ir-document-preview PR.)

- **Per-cell spreadsheet match anchoring.** Today the spreadsheet chrome
  renders one row per finding (the primary plus every sameReq sibling)
  and highlights the entire `Value` column. The Excel-feel is right but
  the data shape is wrong — a real spreadsheet has rows of varying
  schema, and a finding's match span maps to a specific `(sheet, row,
  col)` in the source. Once siphon-fs extracts with row/col offsets,
  swap the synthesised rows for parsed rows and highlight cells whose
  offsets fall inside any finding span.
  (Source: claude/ir-document-preview PR.)

## deploy

- **Digest-pin every Dockerfile base image.** Today the Rust builders
  pin to `rust:1.95-bookworm`, the runtimes to `debian:bookworm-slim`,
  the nginx runtime to `nginx:1.27-alpine`, and the Node ui-builder to
  `node:22-alpine`. All but `debian:bookworm-slim` carry a major+minor
  pin; none carry a digest. For supply-chain hardening, pin each FROM
  by `image:tag@sha256:<digest>` so the build is reproducible against
  exactly one upstream snapshot. Recipe per image:
    1. `docker pull <image>:<tag>`
    2. `docker inspect --format='{{index .RepoDigests 0}}' <image>:<tag>`
    3. Append the resulting `@sha256:...` to the FROM line.
  Renovate / dependabot can keep digest pins fresh once they're set
  (the image-update flow opens PRs with the new digest). Today's
  major+minor pins still resolve to a known build; this is a "harder
  guarantee" upgrade rather than a fix.
  (Source: claude/deploy-dockerfile-pinning PR.)

- **Replicate the cargo dummy-build cache pattern to deploy/Dockerfile
  + deploy/Dockerfile.fs.** The same two-pass cache layer that
  Dockerfile.api now uses (stub workspace → real source) cuts CI build
  time substantially on src-only edits. Dockerfile.api was the first
  target because it pulls the heaviest dep graph (kube + k8s-openapi
  + the `k8s-roll` image stack). Once the pattern's been validated in
  CI, replicate verbatim into deploy/Dockerfile (root CLI image) and
  deploy/Dockerfile.fs. The stub-builder block is the same shape; only
  the `cargo build -p <name>` line differs per image.
  (Source: claude/deploy-dockerfile-pinning PR.)
