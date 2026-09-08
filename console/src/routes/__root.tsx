import { createRootRoute, Outlet } from '@tanstack/react-router'
import { AppShell } from '../ui/app-shell'
import { CommandPaletteProvider } from '../ui/command-palette'
import { ToastProvider } from '../ui/toast'
import { TooltipProvider } from '../ui/overlays'
import { useGlobalCommands } from '../features/global-commands'

function Shell() {
  useGlobalCommands()
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}

export const Route = createRootRoute({
  component: () => (
    <TooltipProvider delayDuration={200}>
      <ToastProvider>
        <CommandPaletteProvider>
          <Shell />
        </CommandPaletteProvider>
      </ToastProvider>
    </TooltipProvider>
  ),
})
