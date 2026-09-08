import { cn } from '../lib/cn'
import type { Severity as Level, SeverityDerivation } from '../lib/severity'

// The type and the component deliberately share a name — types and values are
// separate namespaces, so `<Severity level={s} />` and `s: Severity` both read
// the way the contract writes them.
export type Severity = Level
export { SEVERITY_ORDER, atLeast } from '../lib/severity'

const LABEL: Record<Level, string> = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

/** Ordinal ramp: grey → blue → yellow → orange → red. */
const PILL: Record<Level, string> = {
  info: 'bg-sev-info-bg text-sev-info-fg',
  low: 'bg-sev-low-bg text-sev-low-fg',
  medium: 'bg-sev-med-bg text-sev-med-fg',
  high: 'bg-sev-high-bg text-sev-high-fg',
  // The only solid fill in the console — it escalates by weight as well as hue.
  critical: 'bg-sev-crit-bg text-sev-crit-fg',
}

const RAIL: Record<Level, string> = {
  info: 'bg-sev-info-fg',
  low: 'bg-sev-low-fg',
  medium: 'bg-sev-med-fg',
  high: 'bg-sev-high-fg',
  critical: 'bg-sev-crit-bg',
}

const FILLED: Record<Level, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/**
 * The four-bar rail is not decoration. Blue-vs-grey and yellow-vs-orange are
 * exactly the pairs that collapse under deuteranopia, and hue disappears
 * entirely in a printed export — the bar count survives both.
 */
function Rail({ level }: { level: Level }) {
  const n = FILLED[level]
  return (
    <span className="inline-flex items-end gap-px" aria-hidden="true">
      {[0, 1, 2, 3].map((i) => (
        <span
          key={i}
          className={cn(
            'w-[3px] rounded-[1px]',
            i < n ? RAIL[level] : 'bg-line-strong',
            ['h-1.5', 'h-2', 'h-2.5', 'h-3'][i],
          )}
        />
      ))}
    </span>
  )
}

export type SeverityProps = {
  level: Level
  variant?: 'pill' | 'bare'
  /**
   * The derivation from `lib/severity`. Supplying it satisfies the contract's
   * requirement that "why is this critical?" has an answer — the inputs render
   * in the native title tooltip.
   */
  derivation?: SeverityDerivation
  className?: string
}

export function Severity({ level, variant = 'pill', derivation, className }: SeverityProps) {
  const why = derivation
    ? `Derived: ${derivation.reason.join(' · ')}`
    : undefined

  if (variant === 'bare') {
    return (
      <span className={cn('inline-flex items-center gap-1.5 text-t4', className)} title={why}>
        <Rail level={level} />
        <span className="text-ink-soft">{LABEL[level]}</span>
      </span>
    )
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-1 px-1.5 py-px text-t5 font-medium',
        PILL[level],
        className,
      )}
      title={why}
    >
      <Rail level={level} />
      {LABEL[level]}
    </span>
  )
}
