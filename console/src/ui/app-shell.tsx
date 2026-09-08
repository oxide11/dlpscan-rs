import * as React from 'react'
import { Link } from '@tanstack/react-router'
import { cn } from '../lib/cn'
import { Badge } from './badge'
import { Kbd, MOD_KEY } from './mono'
import { BannerStack, type BannerSpec } from './banner'
import { useCommandPalette } from './command-palette'

/** Eight routes. Each is a question an operator asks. */
export const NAV = [
  { to: '/', label: 'Overview', question: 'Is it healthy, and what needs me?' },
  { to: '/findings', label: 'Findings', question: 'What did it catch?' },
  { to: '/scan', label: 'Scan', question: 'What would it do with this?' },
  { to: '/patterns', label: 'Patterns', question: 'What can it detect?' },
  { to: '/policies', label: 'Policies', question: 'What are we telling it to do?' },
  { to: '/running', label: 'Running', question: 'What is actually running right now?' },
  { to: '/assurance', label: 'Assurance', question: 'Can I prove any of this?' },
  { to: '/settings', label: 'Settings', question: 'How is it wired?' },
] as const

function useTheme() {
  const [theme, setTheme] = React.useState<'light' | 'dark'>(
    () => (document.documentElement.dataset.theme as 'light' | 'dark') ?? 'dark',
  )
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    // The only thing this console persists is per-operator display preference.
    try {
      localStorage.setItem('siphon.theme', next)
    } catch {
      /* private mode — the in-memory toggle still works for this tab */
    }
    setTheme(next)
  }
  return { theme, toggle }
}

/**
 * The mark is mid-tone teal on transparent, so it holds on both themes with no
 * second file and no inversion filter. 22px cap height, never smaller — the
 * hexagon lattice behind the octopus turns to mud below that.
 */
function Logo() {
  return (
    <img
      src="./assets/octopus-64.png"
      alt="Polygon Cyber"
      width={22}
      height={22}
      className="size-[22px] shrink-0 object-contain"
    />
  )
}

export function AppShell({
  banners = [],
  children,
}: {
  banners?: BannerSpec[]
  children: React.ReactNode
}) {
  const { theme, toggle } = useTheme()
  const { open } = useCommandPalette()
  const [navOpen, setNavOpen] = React.useState(false)

  // Queue depth is the only number in the nav.
  const queueDepth = 0

  return (
    <div className="flex min-h-dvh flex-col bg-page">
      <BannerStack banners={banners} />

      <header
        className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-surface px-4"
        style={{ height: 'var(--header-height)' }}
      >
        <button
          type="button"
          className="text-ink-soft lg:hidden"
          aria-label="Menu"
          aria-expanded={navOpen}
          onClick={() => setNavOpen((o) => !o)}
        >
          ☰
        </button>

        <Link to="/" className="flex items-center gap-2 no-underline">
          <Logo />
          <span className="text-t3 font-semibold text-ink">Siphon</span>
        </Link>

        <button
          type="button"
          onClick={open}
          className="ml-auto flex h-7 items-center gap-2 rounded-1 border border-line bg-page px-2 text-t5 text-ink-muted hover:border-line-strong"
        >
          Search
          <Kbd>{MOD_KEY} K</Kbd>
        </button>

        <button
          type="button"
          onClick={toggle}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          className="text-t4 text-ink-muted hover:text-ink"
        >
          {theme === 'dark' ? '☾' : '☀'}
        </button>
      </header>

      <div className="flex flex-1">
        <nav
          className={cn(
            'shrink-0 border-r border-line bg-surface',
            // Off-canvas drawer below 900px, per the contract.
            'fixed inset-y-0 left-0 z-40 w-[var(--nav-width)] pt-[var(--header-height)] transition-transform lg:static lg:translate-x-0 lg:pt-0',
            navOpen ? 'translate-x-0' : '-translate-x-full',
          )}
          style={{ width: 'var(--nav-width)' }}
        >
          <ul className="flex flex-col gap-px p-2">
            {NAV.map((n) => (
              <li key={n.to}>
                <Link
                  to={n.to}
                  title={n.question}
                  onClick={() => setNavOpen(false)}
                  className="flex items-center justify-between rounded-1 px-2 py-1.5 text-t4 text-ink-soft no-underline hover:bg-hover hover:text-ink [&.active]:bg-hover [&.active]:font-medium [&.active]:text-ink"
                  activeOptions={{ exact: n.to === '/' }}
                >
                  {n.label}
                  {n.to === '/' && queueDepth > 0 && <Badge tone="count">{queueDepth}</Badge>}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        {navOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/40 lg:hidden"
            onClick={() => setNavOpen(false)}
            aria-hidden="true"
          />
        )}

        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  )
}
