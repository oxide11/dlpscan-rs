import { cn } from '../lib/cn'

/**
 * Classification answers *how sensitive is this data*. Severity answers *how
 * urgently does this need a human*. They are independent — Restricted data
 * handled correctly is not an incident — so they must not share a visual
 * language.
 *
 * Classification is a different **shape**: square-cornered, uppercase mono,
 * left edge bar, in a slate-to-violet ramp deliberately clear of severity's
 * blue. A Restricted label can never read as an alert.
 */
export type Classification = 'public' | 'internal' | 'confidential' | 'restricted'
export type Regime = 'pci' | 'phi' | 'pii' | 'sox' | 'gdpr'

export interface LabelSource {
  kind: 'asserted' | 'inferred'
  /** MIP, Purview, a filesystem tag — or the engine, when inferred. */
  authority: string
  verified: boolean
}

const TIER: Record<Classification, string> = {
  public: 'text-cls-public-fg bg-cls-public-bg border-l-ink-faint',
  internal: 'text-cls-int-fg bg-cls-int-bg border-l-cls-int-fg',
  confidential: 'text-cls-conf-fg bg-cls-conf-bg border-l-cls-conf-fg',
  restricted: 'text-cls-restr-fg bg-cls-restr-bg border-l-cls-restr-fg',
}

export function Classification({
  tier,
  source,
  className,
}: {
  tier: Classification
  /** Required in detail views: asserted and inferred are different trust levels. */
  source?: LabelSource
  className?: string
}) {
  const note = source
    ? source.kind === 'asserted'
      ? `Asserted by ${source.authority}${source.verified ? ', verified' : ', unverified by this engine'}`
      : `Inferred by ${source.authority} from what it matched`
    : undefined

  return (
    <span className={cn('inline-flex items-center gap-1', className)}>
      <span
        className={cn(
          'inline-flex items-center border-l-2 px-1.5 py-px font-mono text-t5 font-medium uppercase tracking-wide',
          TIER[tier],
        )}
        title={note}
      >
        {tier}
      </span>
      {source?.kind === 'asserted' && !source.verified && (
        <span className="text-t5 text-ink-muted" title={note}>
          unverified
        </span>
      )}
    </span>
  )
}

/**
 * Regulatory regimes are **categorical, not ordinal**, so they stay
 * monochrome. PCI is not "worse than" PHI, and coloring both is how a
 * two-color system becomes a twelve-color one.
 */
export function RegimeList({ regimes, className }: { regimes: Regime[]; className?: string }) {
  if (regimes.length === 0) return null
  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1', className)}>
      {regimes.map((r) => (
        <span
          key={r}
          className="inline-flex items-center border border-line px-1 py-px font-mono text-t5 uppercase text-ink-soft"
        >
          {r}
        </span>
      ))}
    </span>
  )
}

export function ClassificationStrip({
  tier,
  source,
  regimes,
  className,
}: {
  tier: Classification
  source?: LabelSource
  regimes?: Regime[]
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)}>
      <Classification tier={tier} source={source} />
      {regimes && regimes.length > 0 && <RegimeList regimes={regimes} />}
    </div>
  )
}
