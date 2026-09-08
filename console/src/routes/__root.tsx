import { createRootRoute, Outlet } from '@tanstack/react-router'
import { CommandPaletteProvider } from '../ui/command-palette'
import { ToastProvider } from '../ui/toast'
import { TooltipProvider } from '../ui/overlays'

/**
 * Providers only. The shell lives in each console's layout route (`_c2`, `ir`)
 * because C2 and IR carry different navigation — see `ui/app-shell.tsx`.
 */
export const Route = createRootRoute({
  component: () => (
    <TooltipProvider delayDuration={200}>
      <ToastProvider>
        <CommandPaletteProvider>
          <Outlet />
        </CommandPaletteProvider>
      </ToastProvider>
    </TooltipProvider>
  ),
})
