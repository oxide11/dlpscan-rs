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
