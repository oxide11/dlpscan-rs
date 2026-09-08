import { useNavigate } from '@tanstack/react-router'
import { useCommandSource } from '../ui/command-palette'
import { NAV } from '../ui/app-shell'

/**
 * The always-available palette entries: the eight routes.
 *
 * Route-specific sources (pods, pattern ids, saved views) register themselves
 * from their own screens — see `useCommandSource`.
 */
export function useGlobalCommands() {
  const navigate = useNavigate()

  useCommandSource(() =>
    NAV.map((n) => ({
      id: `nav:${n.to}`,
      group: 'Go to',
      label: n.label,
      keywords: [n.question, n.to],
      hint: n.to,
      run: () => navigate({ to: n.to }),
    })),
  )
}
