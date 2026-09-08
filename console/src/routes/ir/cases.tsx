import * as React from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../lib/api'
import { deriveCases, ageLabel, type Case } from '../../lib/cases'
import { Page, PageHeader, Card } from '../../ui/layout'
import { Severity } from '../../ui/severity'
import { Badge } from '../../ui/badge'
import { Button } from '../../ui/button'
import { Select } from '../../ui/field'
import { MonoValue } from '../../ui/mono'
import { Disclosure } from '../../ui/disclosure'
import { EmptyState, AbsenceNote } from '../../ui/empty'

interface Search {
  show: 'open' | 'all'
}

export const Route = createFileRoute('/ir/cases')({
  validateSearch: (raw: Record<string, unknown>): Search => ({
    show: raw.show === 'all' ? 'all' : 'open',
  }),
  component: CasesRoute,
})

/** "What am I working?" */
function CasesRoute() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()

  const findings = useQuery({
    queryKey: ['ir', 'cases'],
    queryFn: () => api.findingsPage({ limit: 500, offset: 0 }),
    refetchInterval: 60_000,
  })

  const cases = React.useMemo(
    () => deriveCases(findings.data?.findings ?? []),
    [findings.data],
  )
  const shown = search.show === 'all' ? cases : cases.filter((c) => c.reviewed < c.total)

  return (
    <Page>
      <PageHeader
        title="Cases"
        description={
          <>
            One scan, one case. Everything in a case arrived together — same document, same
            message — so investigating one finding almost always means investigating its
            siblings.
          </>
        }
        meta={
          <Select
            value={search.show}
            onChange={(e) => navigate({ search: { show: e.target.value as Search['show'] } })}
            className="w-40"
            aria-label="Which cases"
          >
            <option value="open">Open only</option>
            <option value="all">All cases</option>
          </Select>
        }
      />

      {/* Said once, plainly, at the top — not buried. A responder who assumes
          this page remembers an assignment will lose work. */}
      <div className="mb-4 rounded-2 border border-line bg-subtle px-3 py-2.5">
        <p className="text-t4 text-ink">
          These cases are <strong className="font-semibold">derived, not stored</strong>.
        </p>
        <p className="mt-1 text-t5 text-ink-muted">
          The engine has no investigations API — no assignee, no status, no notes, nothing that
          outlives the retention window. Grouping, severity rollup and review progress are
          computed here from the findings themselves. Anything that needs to persist between
          sessions needs a server-side case store first.
        </p>
      </div>

      {findings.isError ? (
        <AbsenceNote
          what="the findings database"
          why={findings.error instanceof Error ? findings.error.message : 'The query failed.'}
          consequence="No cases can be derived, which is not the same as having no open cases."
          remedy={
            <Button size="sm" onClick={() => findings.refetch()}>
              Retry
            </Button>
          }
        />
      ) : findings.isPending ? (
        <Card>
          <p className="text-t4 text-ink-muted">Deriving cases…</p>
        </Card>
      ) : shown.length === 0 ? (
        <Card>
          <EmptyState
            title={search.show === 'open' ? 'No open cases' : 'No cases'}
            detail={
              search.show === 'open'
                ? 'Every scan with findings has been fully triaged.'
                : 'No findings in the retained window, so nothing to group.'
            }
          />
        </Card>
      ) : (
        <Card bodyClassName="px-3 py-0">
          {shown.map((c) => (
            <CaseRow key={c.scanId} c={c} />
          ))}
        </Card>
      )}
    </Page>
  )
}

function CaseRow({ c }: { c: Case }) {
  const open = c.total - c.reviewed
  return (
    <Disclosure
      label={`Scan ${c.scanId.slice(0, 8)}`}
      summary={
        <>
          <Severity level={c.severity} variant="bare" />
          <span className="text-t5 text-ink-muted">
            {c.categories.slice(0, 2).join(', ')}
            {c.categories.length > 2 && ` +${c.categories.length - 2}`}
          </span>
          <Badge tone={open > 0 ? 'attn' : 'ok'}>
            {open > 0 ? `${open} open` : 'triaged'}
          </Badge>
          <Badge tone="muted">{ageLabel(c.firstSeen)}</Badge>
        </>
      }
    >
      <div className="flex flex-col gap-2">
        <dl className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-4 gap-y-1 text-t4">
          <dt className="text-ink-muted">Scan</dt>
          <dd>
            <MonoValue value={c.scanId} truncate="middle" copy />
          </dd>
          <dt className="text-ink-muted">Findings</dt>
          <dd>
            {c.total} · {c.reviewed} reviewed
          </dd>
          <dt className="text-ink-muted">Categories</dt>
          <dd>{c.categories.join(', ')}</dd>
          <dt className="text-ink-muted">First seen</dt>
          <dd>{new Date(c.firstSeen).toLocaleString()}</dd>
        </dl>
        <div>
          <Link
            to="/ir/alerts"
            search={{ limit: 100, offset: 0, show: 'all', selected: c.findings[0]?.id }}
            className="text-t4"
          >
            Triage this case →
          </Link>
        </div>
      </div>
    </Disclosure>
  )
}
