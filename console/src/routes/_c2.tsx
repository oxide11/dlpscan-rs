import { createFileRoute, Outlet } from '@tanstack/react-router'
import { AppShell, C2 } from '../ui/app-shell'
import { useGlobalCommands } from '../features/global-commands'

/**
 * The C2 shell. Pathless layout route, so its children keep the bare paths
 * (`/findings`, not `/c2/findings`) while IR nests under `/ir`.
 */
function C2Layout() {
  useGlobalCommands(C2)
  return (
    <AppShell console={C2}>
      <Outlet />
    </AppShell>
  )
}

export const Route = createFileRoute('/_c2')({ component: C2Layout })
