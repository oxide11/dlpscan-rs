import { cn } from '../lib/cn'

/**
 * A headline number with a **named denominator**, never a composite score.
 *
 * Three rules, each with a failure behind it:
 *
 *  - Always show numerator and denominator as real counts. 96.6% reads
 *    identically whether it is 28/29 or 12,516/12,956, and those warrant
 *    different responses. The fraction is what makes the percentage safe to
 *    act on.
 *  - Always show the change, with arrow and color decoupled. The arrow is what
 *    the number did; the color is whether that is good. A rising
 *    evidence-attrition metric arrows **up** and reads **red**.
 *  - `numerator === null` renders the word `unverified` — never 0, and with no
 *    trend, because there is nothing to compare.
 */
export type PillarProps = {
  label: string
  numerator: number | null
  denominator: number | null
  /** REQUIRED. A denominator with no name is a score. */
  unit: string
  format?: 'pct' | 'count' | 'ratio'
  delta?: { pct: number; period: string } | null
  /**
   * What the objective specified, as a fraction of the denominator. Read
   * against this rather than against a prior period: a figure can rise every
   * week and still be short of what the obligation requires. Rendered as the
   * target and the gap to it, in points, with the color following whether
   * the gap is met.
   */
  target?: number | null
  polarity?: 'higher-better' | 'lower-better' | 'neutral'
  note?: string
  className?: string
}

const n = (v: number) => v.toLocaleString('en-US')

/** Below this the indicator reads flat: one that twitches on noise gets ignored. */
const FLAT_EPSILON = 0.05

function Delta({
  delta,
  polarity,
}: {
  delta: { pct: number; period: string }
  polarity: NonNullable<PillarProps['polarity']>
}) {
  const { pct, period } = delta
  const flat = polarity === 'neutral' || Math.abs(pct) < FLAT_EPSILON
  const tone: 'flat' | 'better' | 'worse' = flat
    ? 'flat'
    : (pct > 0) === (polarity === 'higher-better')
      ? 'better'
      : 'worse'

  // Arrow follows the sign of the change. Color follows whether that change is
  // good. Conflating them is the bug this component exists to prevent.
  const arrow = flat ? '→' : pct > 0 ? '↑' : '↓'

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 text-t5 tabular-nums',
        tone === 'better' && 'text-brand',
        tone === 'worse' && 'text-attn',
        tone === 'flat' && 'text-ink-muted',
      )}
    >
      <span aria-hidden="true">{arrow}</span>
      {flat ? 'flat' : `${Math.abs(pct).toFixed(1)}%`}
      <span className="text-ink-faint">{period}</span>
    </span>
  )
}

function Target({
  target,
  numerator,
  denominator,
  polarity,
}: {
  target: number
  numerator: number
  denominator: number
  polarity: NonNullable<PillarProps['polarity']>
}) {
  const value = denominator === 0 ? null : numerator / denominator
  const gapPts = value === null ? null : (value - target) * 100
  const met =
    gapPts === null
      ? null
      : polarity === 'lower-better'
        ? gapPts <= 1e-9
        : gapPts >= -1e-9
  return (
    <p
      className={cn(
        'text-t5 tabular-nums',
        met === null ? 'text-ink-faint' : met ? 'text-brand' : 'text-attn',
      )}
    >
      target {polarity === 'lower-better' ? '≤' : '≥'} {(target * 100).toFixed(target * 100 % 1 === 0 ? 0 : 1)}%
      {gapPts !== null && (
        <>
          {' · '}
          {met
            ? 'met'
            : Math.abs(gapPts) < 0.05
              ? // A gap that rounds to nothing in points is still a gap; say it
                // in counts, which is what 1 failed canary in 2,100 actually is.
                `${Math.ceil(Math.abs(target * denominator - numerator))} short of target`
              : `${Math.abs(gapPts).toFixed(1)} pts short`}
        </>
      )}
    </p>
  )
}

/** 1 decimal, except that a fraction short of 1 must never print as 100.0%:
 * 2,099 / 2,100 is 99.95%, and rounding it up is the lie the fraction below
 * the headline exists to prevent. */
function pctOf(numerator: number, denominator: number) {
  const v = (numerator / denominator) * 100
  const one = v.toFixed(1)
  return one === '100.0' && numerator !== denominator ? `${v.toFixed(2)}%` : `${one}%`
}

export function Pillar({
  label,
  numerator,
  denominator,
  unit,
  format = 'pct',
  delta,
  target,
  polarity = 'higher-better',
  note,
  className,
}: PillarProps) {
  const unverified = numerator === null

  let headline: string
  if (unverified) {
    headline = 'unverified'
  } else if (format === 'count' || denominator === null) {
    headline = n(numerator)
  } else if (format === 'ratio') {
    headline = denominator === 0 ? '—' : (numerator / denominator).toFixed(2)
  } else {
    headline = denominator === 0 ? '—' : pctOf(numerator, denominator)
  }

  return (
    <div className={cn('flex flex-col gap-1', className)}>
      <div className="text-t5 font-medium uppercase tracking-wide text-ink-muted">{label}</div>

      <div className="flex items-baseline gap-2">
        <span
          className={cn(
            'text-t1 font-semibold tabular-nums',
            unverified ? 'text-ink-faint text-t2 font-normal italic' : 'text-ink',
          )}
        >
          {headline}
        </span>
        {/* No trend at all when there is no verified numerator. */}
        {!unverified && delta && <Delta delta={delta} polarity={polarity} />}
      </div>

      {/* The fraction is not supplementary detail — it is what makes the
          headline safe to act on. A genuine count has no denominator, so it
          names its unit alone rather than inventing one; `numerator ===
          denominator` would be a fraction that says nothing. */}
      <div className="font-mono text-t5 text-ink-muted tabular-nums">
        {unverified
          ? `— ${unit}`
          : denominator === null
            ? unit
            : `${n(numerator)} / ${n(denominator)} ${unit}`}
      </div>

      {note && <p className="text-t5 text-ink-muted">{note}</p>}
      {/* A target is the reference; a prior period is only a reference when
          there is no target. Unverified has neither: nothing to compare. */}
      {!unverified && typeof target === 'number' && denominator !== null ? (
        <Target target={target} numerator={numerator} denominator={denominator} polarity={polarity} />
      ) : (
        !unverified &&
        delta === null && <p className="text-t5 text-ink-faint">no comparable prior period</p>
      )}
    </div>
  )
}
