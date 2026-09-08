import { createFileRoute, Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../lib/api'
import { deriveFinding, SEVERITY_ORDER } from '../../lib/severity'
import { deriveCases, medianReviewMinutes, ageLabel } from '../../lib/cases'
import { Page, PageHeader, Card } from '../../ui/layout'
import { Pillar } from '../../ui/pillar'
import { Severity } from '../../ui/severity'
import { Badge } from '../../ui/badge'
import { EmptyState, AbsenceNote } from '../../ui/empty'
import { Button } from '../../ui/button'

export const Route = createFileRoute('/ir/')({ component: Respond })

/**
 * "What needs me now?"
 *
 * A work queue, not a stats wall. The three numbers at the top exist to tell a
 * responder whether the backlog is growing and how fast the team is clearing
 * it; everything below is the actual list of things to pick up.
 */
function Respond() {
  const findings = useQuery({
    queryKey: ['ir', 'respond'],
    queryFn: () => api.findingsPage({ limit: 200, offset: 0 }),
    refetchInterval: 60_000,
  })

  const rows = findings.data?.findings ?? []
  const unreviewed = rows.filter((f) => !f.analyst_verdict)
  const cases = deriveCases(rows)
  const openCases = cases.filter((c) => c.reviewed < c.total)
  const mttr = medianReviewMinutes(rows)

  // Worst first, then oldest — a critical from an hour ago outranks a low from
  // yesterday, but among equals the one that has been waiting longer wins.
  // Severity is derived once per finding rather than inside the comparator,
  // which would recompute it O(n log n) times.
  const worklist = unreviewed
    .map((f) => ({ f, rank: SEVERITY_ORDER.indexOf(deriveFinding(f).level) }))
    .sort((a, b) => b.rank - a.rank || a.f.created_at.localeCompare(b.f.created_at))
    .slice(0, 12)
    .map((x) => x.f)

  return (
    <Page>
      <PageHeader
        title="Respond"
        description={
          <>
            The triage backlog, worst and oldest first. Counts cover the most recent{' '}
            {rows.length || '—'} findings the engine retained, not all of history — see Queue for
            the full range.
          </>
        }
        actions={
          <Button onClick={() => findings.refetch()} loading={findings.isFetching}>
            Refresh
          </Button>
        }
      />

      {findings.isError && (
        <AbsenceNote
          className="mb-4"
          what="the findings database"
          why={
            findings.error instanceof Error ? findings.error.message : 'The query failed.'
          }
          consequence="An empty queue here would mean nothing was measured, not that nothing is waiting."
        />
      )}

      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card>
          <Pillar
            label="Awaiting triage"
            numerator={findings.data ? unreviewed.length : null}
            denominator={findings.data ? rows.length : null}
            unit="findings loaded"
            format="count"
            polarity="lower-better"
            delta={null}
            note="Every one needs a true/false-positive call."
          />
        </Card>
        <Card>
          <Pillar
            label="Open cases"
            numerator={findings.data ? openCases.length : null}
            denominator={findings.data ? cases.length : null}
            unit="scans with findings"
            format="count"
            polarity="lower-better"
            delta={null}
            note="A case is one scan — see Cases for why."
          />
        </Card>
        <Card>
          {/* null, not 0, when nothing has been reviewed: "no data" and
              "instant" are different facts. */}
          <Pillar
            label="Median time to verdict"
            numerator={mttr === null ? null : Math.round(mttr)}
            denominator={null}
            unit="minutes, reviewed findings"
            format="count"
            polarity="lower-better"
            delta={null}
            note={mttr === null ? 'Nothing reviewed yet.' : undefined}
          />
        </Card>
      </div>

      <Card
        title="Pick up next"
        actions={
          unreviewed.length > worklist.length ? (
            <Link
              to="/ir/queue"
              search={{ limit: 100, offset: 0, show: 'unreviewed' }}
              className="text-t5"
            >
              {unreviewed.length - worklist.length} more
            </Link>
          ) : undefined
        }
        bodyClassName="p-0"
      >
        {findings.isPending ? (
          <ul className="divide-y divide-line-subtle">
            {Array.from({ length: 5 }).map((_, i) => (
              <li key={i} className="px-3 py-2.5">
                <span
                  className="block h-2 animate-pulse rounded-full bg-sunk"
                  style={{ width: `${40 + i * 10}%` }}
                />
              </li>
            ))}
          </ul>
        ) : findings.isError ? null : worklist.length === 0 ? (
          <EmptyState
            title="Queue is clear"
            detail="Every retained finding carries an analyst verdict. This is a real zero — the query succeeded."
          />
        ) : (
          <ul className="divide-y divide-line-subtle">
            {worklist.map((f) => {
              const d = deriveFinding(f)
              return (
                <li key={f.id} className="flex items-center gap-3 px-3 py-2 text-t4">
                  <Severity level={d.level} variant="bare" derivation={d} />
                  <span className="min-w-0 flex-1 truncate">
                    {f.category}
                    <span className="text-ink-muted"> · {f.sub_category ?? '—'}</span>
                  </span>
                  <Badge tone="muted">{ageLabel(f.created_at)}</Badge>
                  <Link
                    to="/ir/queue"
                    search={{ limit: 100, offset: 0, show: 'unreviewed', selected: f.id }}
                    className="text-t5"
                  >
                    Triage
                  </Link>
                </li>
              )
            })}
          </ul>
        )}
      </Card>
    </Page>
  )
}
