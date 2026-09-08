import * as React from 'react'
import { cn } from '../lib/cn'

/**
 * The load-bearing simplification: native `<details>`. No JS, no state, and
 * ⌘F finds text inside closed sections — which a JS accordion silently breaks.
 *
 * A shared `name` makes a group mutually exclusive (the browser does it).
 * Never nest.
 *
 * **A closed disclosure whose label is just a noun is a bug.** The summary
 * slot carries the count, the state, the reason to open it — that is what
 * makes hide-by-default safe rather than a way to lose information.
 */
export function Disclosure({
  label,
  summary,
  name,
  defaultOpen,
  children,
  className,
}: {
  label: string
  summary?: React.ReactNode
  /** Shared across siblings ⇒ native accordion behaviour. */
  name?: string
  defaultOpen?: boolean
  children: React.ReactNode
  className?: string
}) {
  return (
    <details
      name={name}
      open={defaultOpen}
      className={cn('group border-b border-line-subtle last:border-b-0', className)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 py-2 text-t4 hover:bg-hover [&::-webkit-details-marker]:hidden">
        <svg
          className="size-3 shrink-0 text-ink-faint transition-transform group-open:rotate-90"
          viewBox="0 0 12 12"
          aria-hidden="true"
        >
          <path d="M4 2.5L8 6l-4 3.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="font-medium text-ink">{label}</span>
        {summary && <span className="ml-auto flex items-center gap-2">{summary}</span>}
      </summary>
      <div className="pb-3 pl-5">{children}</div>
    </details>
  )
}
