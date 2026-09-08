import * as React from 'react'
import { cn } from '../lib/cn'

export type BadgeProps = React.HTMLAttributes<HTMLSpanElement> & {
  /** `ok` and `attn` are the only colored tones in the whole console. */
  tone?: 'neutral' | 'ok' | 'attn' | 'muted' | 'count'
  dot?: boolean
}

const TONES: Record<NonNullable<BadgeProps['tone']>, string> = {
  neutral: 'bg-subtle text-ink-soft border-line',
  ok: 'bg-brand-soft text-brand-strong border-brand/25',
  attn: 'bg-attn-soft text-attn border-attn/25',
  muted: 'bg-transparent text-ink-muted border-line-subtle',
  count: 'bg-sunk text-ink-soft border-transparent tabular-nums font-mono',
}

const DOTS: Record<NonNullable<BadgeProps['tone']>, string> = {
  neutral: 'bg-ink-faint',
  ok: 'bg-brand',
  attn: 'bg-attn',
  muted: 'bg-ink-faint',
  count: 'bg-ink-faint',
}

/** Badge text is a state, not a sentence — two words maximum. */
export function Badge({ tone = 'neutral', dot, className, children, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-1 border px-1.5 py-px text-t5 font-medium whitespace-nowrap',
        TONES[tone],
        className,
      )}
      {...rest}
    >
      {dot && <span className={cn('size-1.5 rounded-full', DOTS[tone])} aria-hidden="true" />}
      {children}
    </span>
  )
}
