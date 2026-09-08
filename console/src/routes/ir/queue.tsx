import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { api, type Finding } from '../../lib/api'
import { deriveFinding, SEVERITY_ORDER } from '../../lib/severity'
import { ageLabel } from '../../lib/cases'
import { Page, PageHeader, Card, KeyValue } from '../../ui/layout'
import { DataTable } from '../../ui/data-table'
import { Severity } from '../../ui/severity'
import { Badge } from '../../ui/badge'
import { Button } from '../../ui/button'
import { Select } from '../../ui/field'
import { MonoValue, Kbd } from '../../ui/mono'
import { EmptyState, AbsenceNote } from '../../ui/empty'
import { Sheet } from '../../ui/overlays'
import { useToast } from '../../ui/toast'
import { useCommandSource } from '../../ui/command-palette'

interface Search {
  limit: number
  offset: number
  category?: string
  /** `unreviewed` is the responder's default — this is a work queue. */
  show: 'unreviewed' | 'all'
  selected?: string
  unmask?: string
}

export const Route = createFileRoute('/ir/queue')({
  validateSearch: (raw: Record<string, unknown>): Search => ({
    limit: Math.min(500, Math.max(25, Number(raw.limit) || 100)),
    offset: Math.max(0, Number(raw.offset) || 0),
    category: typeof raw.category === 'string' && raw.category ? raw.category : undefined,
    show: raw.show === 'all' ? 'all' : 'unreviewed',
    selected: typeof raw.selected === 'string' && raw.selected ? raw.selected : undefined,
    unmask: typeof raw.unmask === 'string' && raw.unmask ? raw.unmask : undefined,
  }),
  component: QueueRoute,
})

/** "What's waiting to be triaged?" */
function QueueRoute() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const qc = useQueryClient()
  const toast = useToast()

  const setSearch = React.useCallback(
    (patch: Partial<Search>) => navigate({ search: (p) => ({ ...p, ...patch }) }),
    [navigate],
  )

  const me = useQuery({ queryKey: ['me'], queryFn: api.me, staleTime: 5 * 60_000 })
  const canPii = me.data?.permissions.includes('unmask_pii') ?? false
  const canPci = me.data?.permissions.includes('unmask_pci') ?? false
  const canUnmask = canPii || canPci
  const unmasking = !!search.unmask

  const categories = useQuery({
    queryKey: ['categories'],
    queryFn: api.categories,
    staleTime: 5 * 60_000,
  })

  const findings = useQuery({
    queryKey: ['ir', 'queue', search.category, search.limit, search.offset, search.unmask],
    queryFn: () =>
      api.findingsPage({
        category: search.category,
        limit: search.limit,
        offset: search.offset,
        unmask: search.unmask,
      }),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  })

  const verdict = useMutation({
    mutationFn: ({ id, v }: { id: string; v: 'tp' | 'fp' }) => api.feedback(id, v),
    onSuccess: (_d, vars) => {
      toast(vars.v === 'tp' ? 'Confirmed true positive' : 'Marked false positive')
      qc.invalidateQueries({ queryKey: ['ir'] })
    },
  })

  const all = React.useMemo(() => findings.data?.findings ?? [], [findings.data])

  // Worst first, then oldest. Filtering to unreviewed is the default because
  // this screen is a queue, not an archive — Findings in C2 is the archive.
  const rows = React.useMemo(() => {
    const base = search.show === 'all' ? all : all.filter((f) => !f.analyst_verdict)
    return base
      .map((f) => ({ f, rank: SEVERITY_ORDER.indexOf(deriveFinding(f).level) }))
      .sort((a, b) => b.rank - a.rank || a.f.created_at.localeCompare(b.f.created_at))
      .map((x) => x.f)
  }, [all, search.show])

  const selected = React.useMemo(
    () => all.find((f) => f.id === search.selected) ?? null,
    [all, search.selected],
  )

  // Keyboard triage: the whole point of a queue is getting through it without
  // reaching for the mouse. J/K/Enter come from DataTable; T and F are here.
  React.useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!selected || e.metaKey || e.ctrlKey || e.altKey) return
      const t = e.target as HTMLElement | null
      if (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return
      const k = e.key.toLowerCase()
      if (k === 't' || k === 'f') {
        e.preventDefault()
        verdict.mutate({ id: selected.id, v: k === 't' ? 'tp' : 'fp' })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selected, verdict])

  useCommandSource(() => [
    {
      id: 'ir:queue:toggle-reviewed',
      group: 'Queue',
      label: search.show === 'all' ? 'Show only unreviewed' : 'Show reviewed too',
      run: () => setSearch({ show: search.show === 'all' ? 'unreviewed' : 'all' }),
    },
    ...(categories.data ?? []).slice(0, 40).map((c) => ({
      id: `ir:queue:cat:${c.category}`,
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
      { accessorKey: 'category', header: 'Category', meta: { provenance: 'column', width: 180 } },
      {
        accessorKey: 'sub_category',
        header: 'Pattern',
        meta: { provenance: 'column', width: 170 },
        cell: (ctx) => ctx.getValue() ?? <span className="text-ink-faint">—</span>,
      },
      {
        accessorKey: 'matched_text',
        header: 'Value',
        enableSorting: false,
        meta: { provenance: 'column', width: 210 },
        cell: (ctx) => {
          const v = ctx.getValue<string | null>()
          return v ? <MonoValue value={v} truncate="end" copy /> : <span className="text-ink-faint">—</span>
        },
      },
      {
        id: 'age',
        header: 'Age',
        accessorFn: (f) => f.created_at,
        meta: { provenance: 'derived', width: 70 },
        cell: (ctx) => ageLabel(ctx.row.original.created_at),
      },
      {
        accessorKey: 'analyst_verdict',
        header: 'Verdict',
        meta: { provenance: 'column', width: 110 },
        cell: (ctx) => {
          const v = ctx.getValue<Finding['analyst_verdict']>()
          if (!v) return <span className="text-ink-faint">unreviewed</span>
          return <Badge tone={v === 'tp' ? 'attn' : v === 'fp' ? 'ok' : 'muted'}>{v}</Badge>
        },
      },
    ],
    [],
  )

  return (
    <Page>
      <PageHeader
        title="Queue"
        description={
          <>
            Unreviewed findings, worst and oldest first. A verdict here feeds the per-category
            precision baselines and is the only training signal the planned false-positive
            reranker has.
          </>
        }
        meta={
          <>
            <Select
              value={search.show}
              onChange={(e) => setSearch({ show: e.target.value as Search['show'] })}
              className="w-44"
              aria-label="Which findings"
            >
              <option value="unreviewed">Unreviewed only</option>
              <option value="all">All findings</option>
            </Select>
            <Select
              value={search.category ?? ''}
              onChange={(e) => setSearch({ category: e.target.value || undefined, offset: 0 })}
              className="w-56"
              aria-label="Category"
            >
              <option value="">All categories</option>
              {(categories.data ?? []).map((c) => (
                <option key={c.category} value={c.category}>
                  {c.category}
                </option>
              ))}
            </Select>
            {canUnmask && (
              <Button
                size="sm"
                variant={unmasking ? 'danger' : 'default'}
                onClick={() =>
                  setSearch({
                    unmask: unmasking
                      ? undefined
                      : [canPii && 'pii', canPci && 'pci'].filter(Boolean).join(','),
                  })
                }
              >
                {unmasking ? 'Hide values' : 'Show values'}
              </Button>
            )}
            {unmasking && (
              <Badge tone="attn" dot>
                disclosed · audited
              </Badge>
            )}
          </>
        }
      />

      {findings.isError ? (
        <AbsenceNote
          what="the findings database"
          why={findings.error instanceof Error ? findings.error.message : 'The query failed.'}
          consequence="An empty queue would mean nothing was measured, not that nothing is waiting."
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
              <span className="flex items-center gap-2">
                {rows.length} shown · <Kbd>J</Kbd>
                <Kbd>K</Kbd> move, <Kbd>↵</Kbd> open, <Kbd>T</Kbd>/<Kbd>F</Kbd> verdict
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
                  disabled={all.length < search.limit}
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
            data={rows}
            virtual={rows.length > 200}
            isLoading={findings.isPending}
            getRowId={(f) => f.id}
            onRowActivate={(f) => setSearch({ selected: f.id })}
            emptyState={
              <EmptyState
                title={search.show === 'unreviewed' ? 'Queue is clear' : 'No findings'}
                detail={
                  search.show === 'unreviewed'
                    ? 'Every finding in this page carries a verdict. Switch to "All findings" to review what was decided.'
                    : 'Nothing in the retained window matches this filter.'
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
        footer={
          selected ? (
            <div className="flex items-center gap-2">
              <Button
                variant="danger"
                loading={verdict.isPending}
                onClick={() => verdict.mutate({ id: selected.id, v: 'tp' })}
              >
                True positive <Kbd>T</Kbd>
              </Button>
              <Button
                loading={verdict.isPending}
                onClick={() => verdict.mutate({ id: selected.id, v: 'fp' })}
              >
                False positive <Kbd>F</Kbd>
              </Button>
            </div>
          ) : undefined
        }
      >
        {selected && (
          <KeyValue
            rows={[
              { key: 'Finding', value: <MonoValue value={selected.id} truncate="middle" copy /> },
              {
                key: 'Case',
                value: <MonoValue value={selected.scan_id} truncate="middle" copy />,
                provenance: 'the scan this arrived in',
              },
              {
                key: 'Severity',
                value: (() => {
                  const d = deriveFinding(selected)
                  return <Severity level={d.level} derivation={d} />
                })(),
                provenance: 'derived in the console',
              },
              { key: 'Confidence', value: selected.confidence.toFixed(3) },
              {
                key: 'Value',
                value: selected.matched_text ? (
                  <MonoValue value={selected.matched_text} copy />
                ) : (
                  '—'
                ),
                provenance: unmasking ? 'disclosed — recorded in the audit log' : 'redacted by the server',
              },
              {
                key: 'Checksum',
                value:
                  selected.validated == null
                    ? 'no validator for this pattern'
                    : selected.validated
                      ? 'passed'
                      : 'failed',
              },
              { key: 'Context', value: selected.has_context ? 'keyword nearby' : 'none found' },
              { key: 'Age', value: ageLabel(selected.created_at) },
              { key: 'Seen', value: new Date(selected.created_at).toLocaleString() },
              {
                key: 'Verdict',
                value: selected.analyst_verdict ?? 'unreviewed',
                provenance: selected.reviewed_at
                  ? new Date(selected.reviewed_at).toLocaleString()
                  : undefined,
              },
            ]}
          />
        )}
      </Sheet>
    </Page>
  )
}
