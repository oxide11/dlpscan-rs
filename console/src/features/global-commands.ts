import { useNavigate } from '@tanstack/react-router'
import { useCommandSource } from '../ui/command-palette'
import type { ConsoleId } from '../ui/app-shell'

/**
 * The always-available palette entries for whichever console is mounted: its
 * own routes, plus a single jump to the sibling console.
 *
 * Route-specific sources (cases, pattern ids, saved views) register themselves
 * from their own screens — see `useCommandSource`.
 */
export function useGlobalCommands(id: ConsoleId) {
  const navigate = useNavigate()

  useCommandSource(() => [
    ...id.nav.map((n) => ({
      id: `nav:${n.to}`,
      group: 'Go to',
      label: n.label,
      keywords: [n.question, n.to],
      hint: n.to,
      run: () => navigate({ to: n.to }),
    })),
    ...(id.sibling
      ? [
          {
            id: `nav:sibling:${id.sibling.to}`,
            group: 'Go to',
            label: `Switch to ${id.sibling.name}`,
            keywords: [id.sibling.why, id.sibling.to],
            hint: id.sibling.to,
            run: () => navigate({ to: id.sibling!.to }),
          },
        ]
      : []),
  ])
}
