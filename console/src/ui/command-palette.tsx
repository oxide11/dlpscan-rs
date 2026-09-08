import * as React from 'react'
import { Command } from 'cmdk'
import * as RDialog from '@radix-ui/react-dialog'
import { Kbd } from './mono'

/**
 * The real navigation.
 *
 * Sources are **registered per route, not hardcoded here**, so the palette
 * stays complete as screens are added rather than decaying into a stale list
 * that has to be remembered. A route calls `useCommandSource` and its entries
 * appear while it is mounted.
 */
export interface CommandItem {
  id: string
  label: string
  group: string
  /** Extra text matched against but not displayed — ids, aliases. */
  keywords?: string[]
  hint?: string
  run: () => void
}

export type CommandSource = () => CommandItem[]

const Ctx = React.createContext<{
  register: (s: CommandSource) => () => void
  open: () => void
} | null>(null)

/**
 * Register this route's palette entries for as long as it is mounted.
 *
 * The identity registered is stable, but it always calls through to the newest
 * `source` — so a route can close over its current filter state without
 * re-registering on every keystroke, and the palette can never run an action
 * against a stale snapshot.
 */
export function useCommandSource(source: CommandSource) {
  const ctx = React.useContext(Ctx)
  const latest = React.useRef(source)

  React.useEffect(() => {
    latest.current = source
  })

  const stable = React.useCallback<CommandSource>(() => latest.current(), [])

  React.useEffect(() => ctx?.register(stable), [ctx, stable])
}

export function useCommandPalette() {
  const ctx = React.useContext(Ctx)
  return { open: ctx?.open ?? (() => {}) }
}

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false)
  // State, not a ref: the registered set is read during render to build the
  // item list, so it has to participate in rendering rather than be smuggled
  // past it with a forced update.
  const [sources, setSources] = React.useState<readonly CommandSource[]>([])

  const register = React.useCallback((s: CommandSource) => {
    setSources((prev) => [...prev, s])
    return () => setSources((prev) => prev.filter((x) => x !== s))
  }, [])

  React.useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const value = React.useMemo(() => ({ register, open: () => setOpen(true) }), [register])

  const items = React.useMemo(() => {
    if (!open) return []
    // One route throwing while building its entries must not empty the palette.
    return sources.flatMap((s) => {
      try {
        return s()
      } catch {
        return []
      }
    })
  }, [open, sources])

  const groups = React.useMemo(() => {
    const m = new Map<string, CommandItem[]>()
    for (const it of items) {
      const arr = m.get(it.group) ?? []
      arr.push(it)
      m.set(it.group, arr)
    }
    return [...m.entries()]
  }, [items])

  return (
    <Ctx.Provider value={value}>
      {children}
      <RDialog.Root open={open} onOpenChange={setOpen}>
        <RDialog.Portal>
          <RDialog.Overlay className="fixed inset-0 z-50 bg-black/40" />
          <RDialog.Content
            aria-label="Command palette"
            className="fixed left-1/2 top-[15vh] z-50 w-[min(620px,92vw)] -translate-x-1/2 overflow-hidden rounded-3 border border-line bg-surface shadow-modal"
          >
            <RDialog.Title className="sr-only">Command palette</RDialog.Title>
            <Command loop>
              <div className="flex items-center gap-2 border-b border-line-subtle px-3">
                <Command.Input
                  autoFocus
                  placeholder="Search routes, pods, patterns, actions…"
                  className="h-11 w-full bg-transparent text-t3 text-ink outline-none placeholder:text-ink-faint"
                />
                <Kbd>esc</Kbd>
              </div>
              <Command.List className="max-h-[52vh] overflow-auto p-1.5">
                <Command.Empty className="px-2 py-6 text-center text-t4 text-ink-muted">
                  Nothing matches.
                </Command.Empty>
                {groups.map(([group, entries]) => (
                  <Command.Group
                    key={group}
                    heading={group}
                    className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-t5 [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-faint"
                  >
                    {entries.map((it) => (
                      <Command.Item
                        key={it.id}
                        value={`${it.label} ${it.keywords?.join(' ') ?? ''}`}
                        onSelect={() => {
                          setOpen(false)
                          it.run()
                        }}
                        className="flex cursor-pointer items-center justify-between gap-3 rounded-1 px-2 py-1.5 text-t4 text-ink data-[selected=true]:bg-hover"
                      >
                        <span className="truncate">{it.label}</span>
                        {it.hint && (
                          <span className="shrink-0 font-mono text-t5 text-ink-faint">{it.hint}</span>
                        )}
                      </Command.Item>
                    ))}
                  </Command.Group>
                ))}
              </Command.List>
            </Command>
          </RDialog.Content>
        </RDialog.Portal>
      </RDialog.Root>
    </Ctx.Provider>
  )
}
