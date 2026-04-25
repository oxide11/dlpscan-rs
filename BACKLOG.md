# Backlog

Items deliberately pushed out of the PR they came up in, with enough context
that whoever picks them up next has the working memory the original author
had. Sorted by component; within a component, no implied order — pick
whichever has the most leverage at the time.

When a PR notes something as "out of scope this commit," that line belongs
here. When an item lands, delete its bullet (its history is in `git log` and
`CHANGELOG.md`).

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
