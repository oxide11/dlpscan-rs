import * as React from 'react'
import { cn } from '../lib/cn'

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  size?: 'sm' | 'md'
  /** Comes from a TanStack mutation's `isPending`, never local useState. */
  loading?: boolean
  /** Leading icon. Omit children for an icon-only button (pass aria-label). */
  icon?: React.ReactNode
}

const VARIANTS: Record<NonNullable<ButtonProps['variant']>, string> = {
  default: 'bg-surface text-ink border-line hover:bg-hover',
  primary: 'bg-brand text-onbrand border-brand hover:bg-brand-strong',
  // Outline, never filled: a destructive action should read as deliberate,
  // not as the loudest thing on screen.
  danger: 'bg-transparent text-attn border-attn hover:bg-attn-soft',
  ghost: 'bg-transparent text-ink-soft border-transparent hover:bg-hover hover:text-ink',
}

const SIZES: Record<NonNullable<ButtonProps['size']>, string> = {
  sm: 'h-6 px-2 text-t5 gap-1',
  md: 'h-[30px] px-3 text-t4 gap-1.5',
}

function Spinner() {
  return (
    <svg className="size-3 animate-spin" viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2" />
      <path d="M8 1.5A6.5 6.5 0 0 1 14.5 8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'default', size = 'md', loading, icon, className, children, disabled, ...rest },
  ref,
) {
  const iconOnly = !children
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        'inline-flex items-center justify-center rounded-1 border font-medium whitespace-nowrap',
        'transition-colors disabled:opacity-50 disabled:pointer-events-none',
        VARIANTS[variant],
        SIZES[size],
        iconOnly && (size === 'sm' ? 'w-6 px-0' : 'w-[30px] px-0'),
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner /> : icon}
      {children}
    </button>
  )
})
