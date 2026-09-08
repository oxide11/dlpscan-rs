import { createFileRoute, Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Page, PageHeader, Card } from '../ui/layout'
import { Pillar } from '../ui/pillar'
import { Badge } from '../ui/badge'
import { Disclosure } from '../ui/disclosure'
import { AbsenceNote, EmptyState } from '../ui/empty'

export const Route = createFileRoute('/')({ component: Overview })

/**
 * "Is it healthy, and what needs me?"
 *
 * The landing page is a **work queue**, not a stats wall — the design decision
 * was queue + task count *or* stats + health, never both. Health is one line;
 * the rest of the page is what an operator has to do.
 */
function Overview() {
  const health = useQuery({
    queryKey: ['health', 'detailed'],
    queryFn: api.detailedHealth,
    refetchInterval: 60_000,
  })

  const unreviewed = useQuery({
    queryKey: ['findings', 'unreviewed-head'],
    queryFn: () => api.findingsPage({ limit: 100, offset: 0 }),
    refetchInterval: 60_000,
  })

  const h = health.data
  const db = h?.database
  const queue = (unreviewed.data?.findings ?? []).filter((f) => !f.analyst_verdict)

  return (
    <Page>
      <PageHeader
        title="Overview"
        description="What needs a person, and whether the engine behind these numbers is actually running."
        meta={
          health.isError ? (
            <Badge tone="attn" dot>
              engine unreachable
            </Badge>
          ) : health.isPending ? (
            <Badge tone="muted">checking…</Badge>
          ) : (
            <>
              <Badge tone="ok" dot>
                {h?.status ?? 'up'}
              </Badge>
              <span className="font-mono text-t5 text-ink-muted">v{h?.version}</span>
              <span className="text-t5 text-ink-muted">
                {h?.patterns_loaded?.toLocaleString()} patterns · {h?.categories_loaded} categories
              </span>
            </>
          )
        }
      />

      {health.isError && (
        <AbsenceNote
          className="mb-4"
          what="engine health"
          why="siphon-api did not answer /v1/health/detailed."
          consequence="A quiet console is not a quiet fleet. Nothing below was measured, so an empty queue here says nothing about whether the engine is catching anything."
        />
      )}

      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card>
          {/* `unreviewed.data` gates the numerator, not `isError`. While the
              query is in flight we do not know the count, and rendering 0 for
              "not yet known" is exactly the fake zero hard rule 3 forbids. */}
          <Pillar
            label="Awaiting review"
            numerator={unreviewed.data ? queue.length : null}
            denominator={unreviewed.data ? unreviewed.data.findings.length : null}
            unit="loaded findings"
            format="count"
            polarity="lower-better"
            delta={null}
            note="Verdicts feed precision baselines."
          />
        </Card>
        <Card>
          <Pillar
            label="Findings retained"
            numerator={db?.findings_count ?? null}
            // A true count, not a fraction. The retention window is the only
            // honest denominator here and the API does not report it.
            denominator={null}
            unit="rows in Postgres"
            format="count"
            polarity="neutral"
            delta={null}
            note={db?.connected ? undefined : 'Database not connected.'}
          />
        </Card>
        <Card>
          <Pillar
            label="Uptime"
            numerator={h ? Math.floor(h.uptime_seconds / 3600) : null}
            denominator={h ? 24 : null}
            unit="hours this day"
            format="count"
            polarity="neutral"
            delta={null}
          />
        </Card>
      </div>

      <Card title="Needs a person" bodyClassName="p-0">
        {unreviewed.isError ? (
          <div className="p-3">
            <AbsenceNote
              what="the review queue"
              why="The findings query failed, so the queue length is unknown."
            />
          </div>
        ) : unreviewed.isPending ? (
          // Skeleton rather than an empty body: a card that renders nothing
          // while loading reads as "nothing to do", which is the one wrong
          // conclusion this surface must never invite.
          <ul className="divide-y divide-line-subtle">
            {Array.from({ length: 4 }).map((_, i) => (
              <li key={i} className="px-3 py-2.5">
                <span
                  className="block h-2 animate-pulse rounded-full bg-sunk"
                  style={{ width: `${45 + i * 11}%` }}
                />
              </li>
            ))}
          </ul>
        ) : queue.length === 0 ? (
          <EmptyState
            title="Nothing waiting"
            detail="Every loaded finding carries an analyst verdict."
          />
        ) : (
          <ul className="divide-y divide-line-subtle">
            {queue.slice(0, 12).map((f) => (
              <li key={f.id} className="flex items-center gap-3 px-3 py-2 text-t4">
                <span className="min-w-0 flex-1 truncate">
                  {f.category}
                  <span className="text-ink-muted"> · {f.sub_category ?? '—'}</span>
                </span>
                <span className="font-mono text-t5 text-ink-muted">
                  {f.confidence.toFixed(2)}
                </span>
                <Link
                  to="/findings"
                  search={{ limit: 100, offset: 0, selected: f.id }}
                  className="text-t5"
                >
                  Review
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <div className="mt-4 rounded-2 border border-line bg-surface">
        <div className="px-3">
          <Disclosure
            label="Engine detail"
            name="overview"
            summary={
              <span className="text-t5 text-ink-muted">
                {db?.connected ? `db ${db.latency_ms ?? '—'} ms` : 'db not connected'}
              </span>
            }
          >
            <dl className="grid grid-cols-2 gap-1 text-t4">
              <dt className="text-ink-muted">Version</dt>
              <dd className="font-mono">{h?.version ?? '—'}</dd>
              <dt className="text-ink-muted">Patterns</dt>
              <dd className="font-mono">{h?.patterns_loaded ?? '—'}</dd>
              <dt className="text-ink-muted">DB latency</dt>
              <dd className="font-mono">{db?.latency_ms ?? '—'} ms</dd>
            </dl>
          </Disclosure>
        </div>
      </div>
    </Page>
  )
}
