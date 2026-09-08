import { createFileRoute, Outlet } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { AppShell, IR } from '../ui/app-shell'
import { useGlobalCommands } from '../features/global-commands'
import { api } from '../lib/api'

/**
 * The IR shell. A real path segment, unlike C2's pathless `_c2` layout, so
 * every responder surface lives under `/ir`.
 *
 * Same product, opposite verb — C2 operates the scanner, IR investigates what
 * it caught (docs/wireframes/IR-vs-C2.md). Everything below the nav is shared:
 * the token layer, every primitive, the API client, the palette.
 */
function IRLayout() {
  useGlobalCommands(IR)

  // Queue depth is the only number the nav carries, and for a responder it is
  // *the* number: how much is waiting. Polled rather than fetched once,
  // because a triage console that goes stale is one you stop believing.
  const queue = useQuery({
    queryKey: ['ir', 'queue-depth'],
    queryFn: () => api.findingsPage({ limit: 200, offset: 0 }),
    refetchInterval: 60_000,
  })
  const depth = (queue.data?.findings ?? []).filter((f) => !f.analyst_verdict).length

  return (
    <AppShell console={IR} queueDepth={depth}>
      <Outlet />
    </AppShell>
  )
}

export const Route = createFileRoute('/ir')({ component: IRLayout })
