import * as React from 'react'
import { cn } from '../lib/cn'

/** Mono is for data only: ids, offsets, config keys, hashes, regexes, code. */
export function MonoValue({
  value,
  truncate,
  copy,
  className,
}: {
  value: string
  /** `middle` keeps both ends of an id legible, which is how people match them. */
  truncate?: 'middle' | 'end'
  copy?: boolean
  className?: string
}) {
  const [copied, setCopied] = React.useState(false)

  const shown =
    truncate === 'middle' && value.length > 18
      ? `${value.slice(0, 8)}…${value.slice(-6)}`
      : value

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard blocked — the full value is in the title attribute */
    }
  }

  return (
    <span className={cn('inline-flex items-center gap-1 font-mono text-t4', className)}>
      <span className={cn(truncate === 'end' && 'truncate')} title={value}>
        {shown}
      </span>
      {copy && (
        <button
          type="button"
          onClick={onCopy}
          aria-label={copied ? 'Copied' : `Copy ${value}`}
          className="text-ink-faint hover:text-ink transition-colors"
        >
          {copied ? (
            <svg className="size-3" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M3 8.5l3.5 3.5L13 5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          ) : (
            <svg className="size-3" viewBox="0 0 16 16" aria-hidden="true">
              <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path d="M10.5 3.5H3.5a1 1 0 0 0-1 1v7" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          )}
        </button>
      )}
    </span>
  )
}

export type MaskKind = 'pan' | 'ssn' | 'email' | 'secret' | 'generic'

function mask(value: string, kind: MaskKind): string {
  switch (kind) {
    case 'pan': {
      const d = value.replace(/\D/g, '')
      return d.length > 4 ? `•••• •••• •••• ${d.slice(-4)}` : '••••'
    }
    case 'ssn':
      return `•••-••-${value.replace(/\D/g, '').slice(-4)}`
    case 'email': {
      const [u, d] = value.split('@')
      return d ? `${u.slice(0, 1)}${'•'.repeat(Math.max(3, u.length - 1))}@${d}` : '•'.repeat(8)
    }
    case 'secret':
      return `${value.slice(0, 3)}${'•'.repeat(Math.min(24, Math.max(6, value.length - 3)))}`
    default:
      return value.length > 6 ? `${value.slice(0, 3)}${'•'.repeat(value.length - 6)}${value.slice(-3)}` : '••••••'
  }
}

/**
 * Renders masked by default. Reveal is component-local, dies with the unmount,
 * is never persisted and never enters the URL, and fires an audit event.
 */
export function MaskedValue({
  value,
  mask: kind = 'generic',
  onReveal,
  className,
}: {
  value: string
  mask?: MaskKind
  onReveal?: (value: string) => void
  className?: string
}) {
  const [revealed, setRevealed] = React.useState(false)

  function toggle() {
    if (!revealed) onReveal?.(value)
    setRevealed((r) => !r)
  }

  return (
    <span className={cn('inline-flex items-center gap-1.5 font-mono text-t4', className)}>
      <span className={cn(!revealed && 'text-ink-muted select-none')}>
        {revealed ? value : mask(value, kind)}
      </span>
      <button
        type="button"
        onClick={toggle}
        aria-pressed={revealed}
        aria-label={revealed ? 'Hide value' : 'Reveal value (audited)'}
        className="text-ink-faint hover:text-ink transition-colors"
      >
        {revealed ? (
          <svg className="size-3.5" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M2 2l12 12M6.5 6.6A2 2 0 0 0 8 10a2 2 0 0 0 1.4-.6M4.2 4.7C2.7 5.7 1.5 8 1.5 8s2.5 4 6.5 4c1.1 0 2-.3 2.9-.7M12.3 11A9.6 9.6 0 0 0 14.5 8S12 4 8 4c-.5 0-1 .06-1.4.17" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
        ) : (
          <svg className="size-3.5" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M1.5 8S4 4 8 4s6.5 4 6.5 4-2.5 4-6.5 4S1.5 8 1.5 8z" fill="none" stroke="currentColor" strokeWidth="1.4" />
            <circle cx="8" cy="8" r="1.8" fill="none" stroke="currentColor" strokeWidth="1.4" />
          </svg>
        )}
      </button>
    </span>
  )
}

/**
 * True on Apple platforms, where the modifier is ⌘ rather than Ctrl. Read once
 * — this cannot change within a session, and `navigator.platform` is
 * deprecated, so `userAgentData` is preferred where it exists.
 */
export const IS_APPLE = /Mac|iPhone|iPad/.test(
  (navigator as unknown as { userAgentData?: { platform?: string } }).userAgentData?.platform ??
    navigator.userAgent,
)

/** The primary chord modifier, spelled the way this operator's keyboard spells it. */
export const MOD_KEY = IS_APPLE ? '⌘' : 'Ctrl'

export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        'inline-flex h-4 min-w-4 items-center justify-center rounded-[3px] border border-line bg-subtle px-1 font-mono text-[10px] text-ink-muted',
        className,
      )}
    >
      {children}
    </kbd>
  )
}
