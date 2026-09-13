import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api, type AuditEvent } from '../../lib/api'
import { Page, PageHeader, Card, KeyValue } from '../../ui/layout'
import { Badge } from '../../ui/badge'
import { Button } from '../../ui/button'
import { MonoValue } from '../../ui/mono'
import { AbsenceNote } from '../../ui/empty'

export const Route = createFileRoute('/_c2/assurance')({ component: AssuranceRoute })

/* ─── safe accessors for unknown API shapes ─────────────────────────── */

function num(v: unknown): number | null {
  return typeof v === 'number' ? v : null
}
function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}
function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {}
}
function pct(v: number | null): string {
  return v === null ? '—' : `${(v * 100).toFixed(1)} %`
}

/** "Can I prove any of this?" */
function AssuranceRoute() {
  const evadexStats = useQuery({
    queryKey: ['evadex-stats'],
    queryFn: api.evadexStats,
    staleTime: 2 * 60_000,
  })

  const evadexRuns = useQuery({
    queryKey: ['evadex-runs'],
    queryFn: () => api.evadexRuns({ limit: 25 }),
    staleTime: 2 * 60_000,
  })

  const baselinesDelta = useQuery({
    queryKey: ['baselines-delta'],
    queryFn: api.baselinesDelta,
    staleTime: 2 * 60_000,
  })

  const audit = useQuery({
    queryKey: ['audit'],
    queryFn: api.audit,
    staleTime: 60_000,
  })

  const stats = obj(evadexStats.data)
  const runsPage = obj(evadexRuns.data)
  const runs = arr(runsPage.runs ?? evadexRuns.data)
  const delta = obj(baselinesDelta.data)
  const categories = arr(delta.categories ?? baselinesDelta.data)

  return (
    <Page>
      <PageHeader
        title="Assurance"
        description="The evidence surface: precision baselines, adversarial recall, and the HMAC audit chain."
      />

      {/* Adversarial stats banner */}
      <Card title="Adversarial recall">
        {evadexStats.isError ? (
          <AbsenceNote
            what="evadex stats"
            why={evadexStats.error instanceof Error ? evadexStats.error.message : 'Request failed.'}
            remedy={
              <Button size="sm" onClick={() => evadexStats.refetch()}>
                Retry
              </Button>
            }
          />
        ) : evadexStats.isPending ? (
          <p className="text-t4 text-ink-muted">Loading…</p>
        ) : (
          <>
            <KeyValue
              rows={[
                { key: 'Total runs', value: String(num(stats.total_runs) ?? '—') },
                { key: 'Detection rate', value: pct(num(stats.detection_rate)), provenance: 'evadex' },
                { key: 'Total evasions tested', value: String(num(stats.total_evasions) ?? '—') },
                { key: 'Last run', value: str(stats.last_run_at) ? new Date(str(stats.last_run_at)!).toLocaleString() : '—' },
                { key: 'Scanner label', value: str(stats.scanner_label) ?? '—' },
              ]}
            />
            {arr(stats.top_bypassed).length > 0 && (
              <div className="mt-4">
                <p className="mb-2 text-t5 text-ink-muted">Top bypassed techniques</p>
                <ul className="divide-y divide-line-subtle">
                  {arr(stats.top_bypassed).slice(0, 10).map((t, i) => {
                    const te = obj(t)
                    return (
                      <li key={i} className="flex items-center gap-3 py-1.5 text-t5">
                        <span className="flex-1 font-mono">{str(te.technique) ?? '—'}</span>
                        <span className="text-ink-muted">{num(te.bypass_count) ?? '—'} bypasses</span>
                        <Badge tone={
                          (num(te.detection_rate) ?? 1) < 0.5 ? 'attn' :
                          (num(te.detection_rate) ?? 1) < 0.8 ? 'warn' : 'ok'
                        }>
                          {pct(num(te.detection_rate))}
                        </Badge>
                      </li>
                    )
                  })}
                </ul>
              </div>
            )}
          </>
        )}
      </Card>

      {/* Run history */}
      <Card title="Recent evadex runs">
        {evadexRuns.isError ? (
          <AbsenceNote
            what="evadex run history"
            why={evadexRuns.error instanceof Error ? evadexRuns.error.message : 'Request failed.'}
            remedy={
              <Button size="sm" onClick={() => evadexRuns.refetch()}>
                Retry
              </Button>
            }
          />
        ) : evadexRuns.isPending ? (
          <p className="text-t4 text-ink-muted">Loading…</p>
        ) : runs.length === 0 ? (
          <p className="text-t4 text-ink-muted">
            No evadex runs recorded. Run{' '}
            <code className="font-mono">evadex scan --tier northam</code> and point it at this
            deployment via the bridge to populate this table.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-t5">
              <thead>
                <tr className="border-b border-line-subtle text-left text-ink-muted">
                  <th className="pb-2 pr-4 font-medium">Run ID</th>
                  <th className="pb-2 pr-4 font-medium">Tier</th>
                  <th className="pb-2 pr-4 font-medium">Date</th>
                  <th className="pb-2 pr-4 font-medium">Tested</th>
                  <th className="pb-2 pr-4 font-medium">Detected</th>
                  <th className="pb-2 font-medium">Rate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {runs.map((r, i) => {
                  const run = obj(r)
                  const rate = num(run.detection_rate)
                  return (
                    <tr key={str(run.run_id) ?? i} className="hover:bg-surface-raised/50">
                      <td className="py-1.5 pr-4">
                        <MonoValue value={str(run.run_id)?.slice(0, 8) ?? '—'} />
                      </td>
                      <td className="py-1.5 pr-4 text-ink-muted">{str(run.tier) ?? '—'}</td>
                      <td className="py-1.5 pr-4 font-mono text-ink-muted">
                        {str(run.created_at) ? new Date(str(run.created_at)!).toLocaleString() : '—'}
                      </td>
                      <td className="py-1.5 pr-4">{num(run.total) ?? '—'}</td>
                      <td className="py-1.5 pr-4">{num(run.detected) ?? '—'}</td>
                      <td className="py-1.5">
                        <Badge tone={
                          rate === null ? 'muted' :
                          rate < 0.5 ? 'attn' :
                          rate < 0.8 ? 'warn' : 'ok'
                        }>
                          {pct(rate)}
                        </Badge>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Baselines delta */}
      <Card title="Precision baselines">
        {baselinesDelta.isError ? (
          <AbsenceNote
            what="baselines"
            why={baselinesDelta.error instanceof Error ? baselinesDelta.error.message : 'Request failed.'}
            remedy={
              <Button size="sm" onClick={() => baselinesDelta.refetch()}>
                Retry
              </Button>
            }
          />
        ) : baselinesDelta.isPending ? (
          <p className="text-t4 text-ink-muted">Loading…</p>
        ) : categories.length === 0 ? (
          <p className="text-t4 text-ink-muted">
            No baselines recorded yet. Analyst verdicts on the Detections page feed this table.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-t5">
              <thead>
                <tr className="border-b border-line-subtle text-left text-ink-muted">
                  <th className="pb-2 pr-4 font-medium">Category</th>
                  <th className="pb-2 pr-4 font-medium">Baseline</th>
                  <th className="pb-2 pr-4 font-medium">Current</th>
                  <th className="pb-2 font-medium">Delta</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {categories.map((c, i) => {
                  const cat = obj(c)
                  const delta_val = num(cat.delta)
                  return (
                    <tr key={str(cat.category) ?? i}>
                      <td className="py-1.5 pr-4 font-medium">{str(cat.category) ?? '—'}</td>
                      <td className="py-1.5 pr-4 font-mono">{pct(num(cat.baseline))}</td>
                      <td className="py-1.5 pr-4 font-mono">{pct(num(cat.current))}</td>
                      <td className="py-1.5">
                        {delta_val === null ? (
                          <span className="text-ink-muted">—</span>
                        ) : (
                          <Badge tone={delta_val >= 0 ? 'ok' : 'attn'}>
                            {delta_val >= 0 ? '+' : ''}{(delta_val * 100).toFixed(1)} pp
                          </Badge>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Audit chain */}
      <Card title="Audit chain">
        {audit.isError ? (
          <AbsenceNote
            what="the audit ring"
            why={audit.error instanceof Error ? audit.error.message : 'Request failed.'}
            remedy={
              <Button size="sm" onClick={() => audit.refetch()}>
                Retry
              </Button>
            }
          />
        ) : audit.isPending ? (
          <p className="text-t4 text-ink-muted">Loading…</p>
        ) : !audit.data?.length ? (
          <p className="text-t4 text-ink-muted">
            Audit ring is empty — no events recorded since this pod started.
          </p>
        ) : (
          <ul className="divide-y divide-line-subtle">
            {(audit.data as AuditEvent[]).slice(0, 50).map((ev, i) => (
              <li key={ev.id ?? i} className="flex flex-col gap-0.5 py-2 text-t5">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-ink-muted">
                    {new Date(ev.timestamp).toLocaleString()}
                  </span>
                  <Badge tone="muted">{ev.event_type}</Badge>
                  {ev.actor && <span className="text-ink-muted">{ev.actor}</span>}
                  {ev.hash && (
                    <span className="ml-auto">
                      <MonoValue value={ev.hash.slice(0, 12)} />
                    </span>
                  )}
                </div>
                {ev.detail && (
                  <span className="text-ink-muted">{ev.detail}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </Page>
  )
}
