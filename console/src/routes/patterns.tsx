import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Page, PageHeader, Card } from '../ui/layout'
import { Input } from '../ui/field'
import { Badge } from '../ui/badge'
import { Disclosure } from '../ui/disclosure'
import { AbsenceNote, EmptyState } from '../ui/empty'

export const Route = createFileRoute('/patterns')({
  validateSearch: (raw: Record<string, unknown>) => ({
    q: typeof raw.q === 'string' && raw.q ? raw.q : undefined,
  }),
  component: PatternsRoute,
})

/** "What can it detect?" */
function PatternsRoute() {
  const search = Route.useSearch()
  const navigate = Route.useNavigate()

  const categories = useQuery({
    queryKey: ['categories'],
    queryFn: api.categories,
    staleTime: 5 * 60_000,
  })

  const filtered = React.useMemo(() => {
    const all = categories.data ?? []
    if (!search.q) return all
    const needle = search.q.toLowerCase()
    return all
      .map((c) => ({
        ...c,
        sub_categories: c.sub_categories.filter((s) => s.toLowerCase().includes(needle)),
      }))
      .filter((c) => c.category.toLowerCase().includes(needle) || c.sub_categories.length > 0)
  }, [categories.data, search.q])

  const totalPatterns = (categories.data ?? []).reduce((n, c) => n + c.pattern_count, 0)

  return (
    <Page>
      <PageHeader
        title="Patterns"
        description="Every category the engine has loaded, and the sub-categories inside it. This is what the scanner can see — a category absent here is a blind spot, not a quiet one."
        meta={
          categories.data && (
            <>
              <Badge tone="count">{totalPatterns.toLocaleString()} patterns</Badge>
              <Badge tone="count">{categories.data.length} categories</Badge>
            </>
          )
        }
        actions={
          <Input
            placeholder="Find a pattern…"
            value={search.q ?? ''}
            onChange={(e) =>
              navigate({ search: { q: e.target.value || undefined } })
            }
            className="w-64"
            aria-label="Find a pattern"
          />
        }
      />

      {categories.isError ? (
        <AbsenceNote
          what="the pattern catalog"
          why="siphon-api did not answer /v1/categories, so what the engine can detect is unknown."
        />
      ) : categories.isPending ? (
        <Card>
          <p className="text-t4 text-ink-muted">Loading catalog…</p>
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <EmptyState title="Nothing matches" detail={`No category or pattern matches “${search.q}”.`} />
        </Card>
      ) : (
        <Card bodyClassName="px-3 py-0">
          {filtered.map((c) => (
            <Disclosure
              key={c.category}
              label={c.category}
              summary={
                <span className="text-t5 text-ink-muted">
                  {c.pattern_count} {c.pattern_count === 1 ? 'pattern' : 'patterns'}
                </span>
              }
            >
              <ul className="flex flex-wrap gap-1">
                {c.sub_categories.map((s) => (
                  <li key={s}>
                    <span className="inline-flex rounded-1 border border-line-subtle px-1.5 py-px font-mono text-t5 text-ink-soft">
                      {s}
                    </span>
                  </li>
                ))}
              </ul>
            </Disclosure>
          ))}
        </Card>
      )}
    </Page>
  )
}
