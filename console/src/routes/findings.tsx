import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { api, type Finding } from '../lib/api'
import { deriveFinding } from '../lib/severity'
import { Page, PageHeader, Card, KeyValue } from '../ui/layout'
import { DataTable } from '../ui/data-table'
import { Severity } from '../ui/severity'
import { Badge } from '../ui/badge'
import { Button } from '../ui/button'
import { Input, Select } from '../ui/field'
import { MaskedValue, MonoValue } from '../ui/mono'
import { EmptyState, AbsenceNote } from '../ui/empty'
import { Sheet } from '../ui/overlays'
import { useToast } from '../ui/toast'
import { useCommandSource } from '../ui/command-palette'

/** URL state, not component state — a pasted URL reproduces a colleague's view. */
interface Search {
  category?: string
  limit: number
  offset: number
  q?: string
  selected?: string
}

export const Route = createFileRoute('/findings')({
  validateSearch: (raw: Record<string, unknown>): Search => ({
    category: typeof raw.category === 'string' && raw.category ? raw.category : undefined,
    limit: Math.min(500, Math.max(25, Number(raw.limit) || 100)),
    offset: Math.max(0, Number(raw.offset) || 0),
    q: typeof raw.q === 'string' && raw.q ? raw.q : undefined,
    selected: typeof raw.selected === 'string' && raw.selected ? raw.selected : undefined,
  }),
  component: FindingsRoute,
})

function FindingsRoute() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const qc = useQueryClient()
  const toast = useToast()

  const setSearch = React.useCallback(
    (patch: Partial<Search>) => navigate({ search: (p) => ({ ...p, ...patch }) }),
    [navigate],
  )

  const categories = useQuery({
    queryKey: ['categories'],
    queryFn: api.categories,
    staleTime: 5 * 60_000,
  })

  const findings = useQuery({
    queryKey: ['findings', search.category, search.limit, search.offset],
    queryFn: () =>
      api.findingsPage({
        category: search.category,
        limit: search.limit,
        offset: search.offset,
      }),
    // Keeps the previous page on screen while the next loads, so paging does
    // not flash an empty table that reads as "no findings".
    placeholderData: keepPreviousData,
  })

  const feedback = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: 'tp' | 'fp' }) =>
      api.feedback(id, verdict),
    onSuccess: (_d, v) => {
      toast(`Marked ${v.verdict === 'tp' ? 'true' : 'false'} positive`)
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  // Memoized: the `?? []` fallback would otherwise be a fresh array on every
  // render, invalidating every downstream memo and re-rendering the table on
  // each keystroke in the filter box.
  const rows = React.useMemo(() => findings.data?.findings ?? [], [findings.data])

  // Client-side text filter over the fetched page only. Said plainly in the
  // UI rather than implied — the server has no text search endpoint, and a
  // filter that silently only covers the current page is a trap.
  const filtered = React.useMemo(() => {
    if (!search.q) return rows
    const needle = search.q.toLowerCase()
    return rows.filter(
      (f) =>
        f.category.toLowerCase().includes(needle) ||
        (f.sub_category ?? '').toLowerCase().includes(needle) ||
        f.id.toLowerCase().includes(needle),
    )
  }, [rows, search.q])

  const selected = React.useMemo(
    () => rows.find((f) => f.id === search.selected) ?? null,
    [rows, search.selected],
  )

  useCommandSource(() => [
    {
      id: 'findings:export-csv',
      group: 'Findings',
      label: 'Export current filter as CSV',
      run: () =>
        window.open(api.exportUrl({ format: 'csv', category: search.category }), '_blank'),
    },
    ...(categories.data ?? []).slice(0, 40).map((c) => ({
      id: `findings:cat:${c.category}`,
      group: 'Filter by category',
      label: c.category,
      hint: String(c.pattern_count),
      run: () => setSearch({ category: c.category, offset: 0 }),
    })),
  ])

  const columns = React.useMemo<ColumnDef<Finding, any>[]>(
    () => [
      {
        id: 'severity',
        header: 'Severity',
        accessorFn: (f) => deriveFinding(f).level,
        meta: { provenance: 'derived', width: 130 },
        cell: (ctx) => {
          const d = deriveFinding(ctx.row.original)
          return <Severity level={d.level} variant="bare" derivation={d} />
        },
      },
      {
        accessorKey: 'category',
        header: 'Category',
        meta: { provenance: 'column', width: 190 },
      },
      {
        accessorKey: 'sub_category',
        header: 'Pattern',
        meta: { provenance: 'column', width: 180 },
        cell: (ctx) => ctx.getValue() ?? <span className="text-ink-faint">—</span>,
      },
      {
        accessorKey: 'matched_text',
        header: 'Value',
        enableSorting: false,
        meta: { provenance: 'column', width: 220 },
        cell: (ctx) => {
          const v = ctx.getValue<string | null>()
          if (!v) return <span className="text-ink-faint">—</span>
          return <MaskedValue value={v} mask="generic" />
        },
      },
      {
        accessorKey: 'confidence',
        header: 'Confidence',
        meta: { provenance: 'column', width: 100, mono: true },
        cell: (ctx) => ctx.getValue<number>().toFixed(2),
      },
      {
        accessorKey: 'analyst_verdict',
        header: 'Verdict',
        meta: { provenance: 'column', width: 100 },
        cell: (ctx) => {
          const v = ctx.getValue<Finding['analyst_verdict']>()
          if (!v) return <span className="text-ink-faint">unreviewed</span>
          return <Badge tone={v === 'tp' ? 'attn' : v === 'fp' ? 'ok' : 'muted'}>{v}</Badge>
        },
      },
      {
        accessorKey: 'created_at',
        header: 'Seen',
        meta: { provenance: 'column', width: 160, mono: true },
        cell: (ctx) => new Date(ctx.getValue<string>()).toLocaleString(),
      },
    ],
    [],
  )

  const page = Math.floor(search.offset / search.limit) + 1

  return (
    <Page>
      <PageHeader
        title="Findings"
        description={
          <>
            Postgres-backed history. Retention is enforced server-side, so the oldest rows here
            are bounded by <code className="font-mono">SIPHON_FINDINGS_RETENTION_DAYS</code> — an
            empty range may mean pruned, not quiet.
          </>
        }
        actions={
          <>
            <Button
              onClick={() =>
                window.open(api.exportUrl({ format: 'csv', category: search.category }), '_blank')
              }
            >
              Export CSV
            </Button>
          </>
        }
        meta={
          <>
            <Select
              value={search.category ?? ''}
              onChange={(e) => setSearch({ category: e.target.value || undefined, offset: 0 })}
              className="w-56"
              aria-label="Category"
            >
              <option value="">All categories</option>
              {(categories.data ?? []).map((c) => (
                <option key={c.category} value={c.category}>
                  {c.category} ({c.pattern_count})
                </option>
              ))}
            </Select>
            <Input
              placeholder="Filter this page…"
              value={search.q ?? ''}
              onChange={(e) => setSearch({ q: e.target.value || undefined })}
              className="w-56"
              aria-label="Filter loaded rows"
            />
            {search.q && (
              <span className="text-t5 text-ink-muted">
                filtering the {rows.length} loaded rows, not the server
              </span>
            )}
          </>
        }
      />

      {findings.isError ? (
        <AbsenceNote
          what="the findings database"
          why={
            findings.error instanceof Error
              ? findings.error.message
              : 'The query to siphon-api failed.'
          }
          remedy={
            <Button size="sm" onClick={() => findings.refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Card
          bodyClassName="p-0"
          footer={
            <div className="flex items-center justify-between">
              <span>
                page {page} · showing {filtered.length} of {rows.length} loaded
              </span>
              <span className="flex gap-1.5">
                <Button
                  size="sm"
                  disabled={search.offset === 0}
                  onClick={() => setSearch({ offset: Math.max(0, search.offset - search.limit) })}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  disabled={rows.length < search.limit}
                  onClick={() => setSearch({ offset: search.offset + search.limit })}
                >
                  Next
                </Button>
              </span>
            </div>
          }
        >
          <DataTable
            columns={columns}
            data={filtered}
            virtual={filtered.length > 200}
            isLoading={findings.isPending}
            getRowId={(f) => f.id}
            onRowActivate={(f) => setSearch({ selected: f.id })}
            emptyState={
              <EmptyState
                title="No findings match"
                detail={
                  search.category
                    ? `Nothing in ${search.category} within the retained window.`
                    : 'The scanner has recorded no findings in the retained window. Every pattern that ran stayed quiet.'
                }
              />
            }
          />
        </Card>
      )}

      <Sheet
        open={!!selected}
        onOpenChange={(o) => !o && setSearch({ selected: undefined })}
        title={selected ? `${selected.category} · ${selected.sub_category ?? '—'}` : ''}
      >
        {selected && (
          <div className="flex flex-col gap-4">
            <KeyValue
              rows={[
                { key: 'Finding', value: <MonoValue value={selected.id} truncate="middle" copy /> },
                { key: 'Scan', value: <MonoValue value={selected.scan_id} truncate="middle" copy /> },
                {
                  key: 'Severity',
                  value: (() => {
                    const d = deriveFinding(selected)
                    return <Severity level={d.level} derivation={d} />
                  })(),
                  provenance: 'derived in console',
                },
                { key: 'Confidence', value: selected.confidence.toFixed(3) },
                {
                  key: 'Value',
                  value: selected.matched_text ? (
                    <MaskedValue value={selected.matched_text} />
                  ) : (
                    '—'
                  ),
                },
                {
                  key: 'Checksum',
                  value:
                    selected.validated === null || selected.validated === undefined
                      ? 'no validator for this pattern'
                      : selected.validated
                        ? 'passed'
                        : 'failed',
                },
                {
                  key: 'Context',
                  value: selected.has_context ? 'keyword nearby' : 'none found',
                },
                {
                  key: 'Gated',
                  value:
                    selected.context_required === null
                      ? 'unknown'
                      : String(selected.context_required),
                  provenance: 'engine always returns null — see ENGINE-NOTES',
                },
                { key: 'Tenant', value: selected.tenant_id ?? 'default' },
                { key: 'Seen', value: new Date(selected.created_at).toLocaleString() },
              ]}
            />

            <div className="flex items-center gap-2 border-t border-line-subtle pt-3">
              <span className="text-t4 text-ink-muted">Analyst verdict</span>
              <Button
                size="sm"
                loading={feedback.isPending}
                onClick={() => feedback.mutate({ id: selected.id, verdict: 'tp' })}
              >
                True positive
              </Button>
              <Button
                size="sm"
                loading={feedback.isPending}
                onClick={() => feedback.mutate({ id: selected.id, verdict: 'fp' })}
              >
                False positive
              </Button>
            </div>
            <p className="text-t5 text-ink-muted">
              Verdicts feed the per-category precision baselines and are the only training signal
              for the planned false-positive reranker.
            </p>
          </div>
        )}
      </Sheet>
    </Page>
  )
}
