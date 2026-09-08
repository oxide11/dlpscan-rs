import * as React from 'react'
import { Link } from '@tanstack/react-router'
import { cn } from '../lib/cn'
import { Badge } from './badge'
import { Kbd, MOD_KEY } from './mono'
import { BannerStack, type BannerSpec } from './banner'
import { useCommandPalette } from './command-palette'

/**
 * One shell, two consoles.
 *
 * C2 and IR are the same product seen through opposite verbs — operate vs
 * investigate (docs/wireframes/IR-vs-C2.md). They share the token layer, every
 * primitive, the API client and the palette; what actually differs is the nav
 * and who is reading it. So the difference lives here, in a prop, rather than
 * in a second copy of the design system that would drift within weeks.
 */
export interface NavItem {
  to: string
  label: string
  /** Shown as the link's title, and matched by the command palette. */
  question: string
}

export interface ConsoleId {
  /** Shown beside the mark. */
  name: string
  /** Root path for this console — the logo links here. */
  home: string
  nav: readonly NavItem[]
  /**
   * The other console, for the header switcher.
   *
   * Optional, and omitted until the sibling's routes actually exist — a nav
   * entry that 404s teaches operators to distrust the nav, which is a worse
   * outcome than the switcher arriving one release later.
   */
  sibling?: { name: string; to: string; why: string }
}

/** C2 — operate. Eight routes, each a question an operator asks. */
export const C2: ConsoleId = {
  name: 'Siphon',
  home: '/',
  nav: [
    { to: '/', label: 'Overview', question: 'Is it healthy, and what needs me?' },
    { to: '/detections', label: 'Detections', question: 'What did it catch?' },
    { to: '/scan', label: 'Scan', question: 'What would it do with this?' },
    { to: '/patterns', label: 'Patterns', question: 'What can it detect?' },
    { to: '/policies', label: 'Policies', question: 'What are we telling it to do?' },
    { to: '/running', label: 'Running', question: 'What is actually running right now?' },
    { to: '/assurance', label: 'Assurance', question: 'Can I prove any of this?' },
    { to: '/settings', label: 'Settings', question: 'How is it wired?' },
  ],
  sibling: { name: 'IR', to: '/ir', why: 'Investigate findings — triage, cases, evidence' },
}

/** IR — investigate. The same eight-question discipline, a responder's day. */
export const IR: ConsoleId = {
  name: 'Siphon IR',
  home: '/ir',
  nav: [
    { to: '/ir', label: 'Respond', question: 'What needs me now?' },
    { to: '/ir/alerts', label: 'Alerts', question: 'What needs a decision?' },
    { to: '/ir/cases', label: 'Cases', question: 'What am I working?' },
    { to: '/ir/analyze', label: 'Analyze', question: 'What is this thing?' },
    { to: '/ir/correlate', label: 'Correlate', question: 'What else is connected?' },
    { to: '/ir/evidence', label: 'Evidence', question: 'Can I hand this over?' },
    { to: '/ir/handoffs', label: 'Handoffs', question: 'What did I escalate?' },
    { to: '/ir/account', label: 'Account', question: 'My profile and preferences' },
  ],
  sibling: { name: 'C2', to: '/', why: 'Operate Siphon — patterns, policies, pods' },
}

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
      src="/assets/octopus-64.png"
      alt="Polygon Cyber"
      width={22}
      height={22}
      className="size-[22px] shrink-0 object-contain"
    />
  )
}

export function AppShell({
  console: id,
  banners = [],
  /** Queue depth is the only number allowed in the nav. */
  queueDepth = 0,
  children,
}: {
  console: ConsoleId
  banners?: BannerSpec[]
  queueDepth?: number
  children: React.ReactNode
}) {
  const { theme, toggle } = useTheme()
  const { open } = useCommandPalette()
  const [navOpen, setNavOpen] = React.useState(false)

  // The nav entry the queue count belongs to: the one that answers "what is
  // waiting for me". Different route per console, same meaning.
  const countedRoute = id === IR ? '/ir/alerts' : '/'

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

        <Link to={id.home} className="flex items-center gap-2 no-underline">
          <Logo />
          <span className="text-t3 font-semibold text-ink">{id.name}</span>
        </Link>

        {/* The consoles are two lenses on one dataset, so crossing between
            them is navigation, not a context switch to be hidden in a menu. */}
        {id.sibling && (
          <Link
            to={id.sibling.to}
            title={id.sibling.why}
            className="ml-1 rounded-1 border border-line px-1.5 py-0.5 text-t5 text-ink-muted no-underline hover:border-line-strong hover:text-ink"
          >
            {id.sibling.name} ↗
          </Link>
        )}

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
            {id.nav.map((n) => (
              <li key={n.to}>
                <Link
                  to={n.to}
                  title={n.question}
                  onClick={() => setNavOpen(false)}
                  className="flex items-center justify-between rounded-1 px-2 py-1.5 text-t4 text-ink-soft no-underline hover:bg-hover hover:text-ink [&.active]:bg-hover [&.active]:font-medium [&.active]:text-ink"
                  activeOptions={{ exact: n.to === id.home }}
                >
                  {n.label}
                  {n.to === countedRoute && queueDepth > 0 && (
                    <Badge tone="count">{queueDepth}</Badge>
                  )}
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
