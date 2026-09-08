import * as React from 'react'
import { cn } from '../lib/cn'

/**
 * One per route. The description is where a screen states its own limits —
 * the retention edge, cache lag, what it cannot show. That is not filler; a
 * screen that hides its own blind spot is how an operator draws a wrong
 * conclusion from a true number.
 */
export function PageHeader({
  title,
  description,
  actions,
  meta,
  className,
}: {
  title: string
  description?: React.ReactNode
  actions?: React.ReactNode
  meta?: React.ReactNode
  className?: string
}) {
  return (
    <header className={cn('flex flex-col gap-2 pb-4', className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h1 className="text-t1 font-semibold text-ink">{title}</h1>
          {description && <p className="max-w-prose text-t4 text-ink-muted">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {meta && <div className="flex flex-wrap items-center gap-2">{meta}</div>}
    </header>
  )
}

/** Bordered box, three optional slots, no shadow, **no nesting**. */
export function Card({
  title,
  actions,
  footer,
  children,
  className,
  bodyClassName,
}: {
  title?: React.ReactNode
  actions?: React.ReactNode
  footer?: React.ReactNode
  children: React.ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cn('rounded-2 border border-line bg-surface', className)}>
      {(title || actions) && (
        <div className="flex items-center justify-between gap-3 border-b border-line-subtle px-3 py-2">
          {typeof title === 'string' ? (
            <h2 className="text-t4 font-semibold text-ink">{title}</h2>
          ) : (
            title
          )}
          {actions && <div className="flex items-center gap-1.5">{actions}</div>}
        </div>
      )}
      <div className={cn('p-3', bodyClassName)}>{children}</div>
      {footer && (
        <div className="border-t border-line-subtle px-3 py-2 text-t5 text-ink-muted">{footer}</div>
      )}
    </section>
  )
}

export interface KeyValueRow {
  key: string
  value: React.ReactNode
  /** Where this fact came from, when that is not obvious or not trustworthy. */
  provenance?: string
}

/** A `<dl>` of facts about one thing. Replaces the paragraph. */
export function KeyValue({ rows, className }: { rows: KeyValueRow[]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1.5', className)}>
      {rows.map((r) => (
        <React.Fragment key={r.key}>
          <dt className="text-t4 text-ink-muted">{r.key}</dt>
          <dd className="min-w-0 text-t4 text-ink">
            {r.value}
            {r.provenance && (
              <span className="ml-1.5 text-t5 text-ink-faint">({r.provenance})</span>
            )}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

/** Page body wrapper — one column, consistent gutters. */
export function Page({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('mx-auto w-full max-w-[1400px] px-5 py-5', className)}>{children}</div>
}
