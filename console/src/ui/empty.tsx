import * as React from 'react'
import { cn } from '../lib/cn'

/**
 * Hard rule 3 — absence is a state.
 *
 * "Zero findings" and "the extractor that would have produced findings was not
 * in this build" are different facts and must never render the same. The first
 * is a result. The second is a blind spot wearing a result's clothes, and it is
 * how a scanner reports clean for content nobody read.
 *
 * Before rendering any zero, check capabilities.
 */

/** A true zero: we looked, and there was nothing. */
export function EmptyState({
  title,
  detail,
  action,
  className,
}: {
  title: string
  detail?: React.ReactNode
  action?: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center gap-2 px-4 py-10 text-center', className)}>
      <p className="text-t3 font-medium text-ink">{title}</p>
      {detail && <p className="max-w-md text-t4 text-ink-muted">{detail}</p>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

/**
 * Not a zero: a gap. The thing that would have produced a result was absent,
 * so this space is unmeasured rather than empty.
 *
 * Deliberately carries the attention color and a border — an operator must be
 * able to tell it from `EmptyState` at a glance, across the room.
 */
export function AbsenceNote({
  what,
  why,
  consequence = 'This is not a zero. The value is unknown, so nothing follows from its absence.',
  remedy,
  className,
}: {
  /** The capability that was missing, e.g. "PDF extraction". */
  what: string
  /** Why it was missing — feature not in build, pod down, retention edge. */
  why: string
  /**
   * What the reader must not conclude. Defaults to the general form; override
   * it where the specific wrong conclusion is worth naming — an unscanned
   * attachment and an unreachable health endpoint invite different mistakes.
   */
  consequence?: string
  remedy?: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col gap-1.5 rounded-2 border border-attn/30 bg-attn-soft px-3 py-2.5',
        className,
      )}
      role="note"
    >
      <div className="flex items-center gap-1.5">
        <svg className="size-3.5 shrink-0 text-attn" viewBox="0 0 16 16" aria-hidden="true">
          <path d="M8 1.8l6.2 11.4H1.8L8 1.8z" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
          <path d="M8 6.3v3.1" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          <circle cx="8" cy="11.3" r="0.7" fill="currentColor" />
        </svg>
        <p className="text-t4 font-medium text-attn">Not measured — {what}</p>
      </div>
      <p className="text-t4 text-ink-soft">{why}</p>
      <p className="text-t5 text-ink-muted">{consequence}</p>
      {remedy && <div className="pt-0.5">{remedy}</div>}
    </div>
  )
}
