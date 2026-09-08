/**
 * Severity derivation — the single place it happens.
 *
 * The engine does not emit a severity. It emits a confidence score, a
 * category, and whether a checksum validator passed and a context keyword was
 * found. Severity is this console's interpretation of those, which means two
 * obligations follow from the contract:
 *
 *   1. It is derived in exactly one place, so two screens cannot disagree.
 *   2. "Why is this critical?" always has an answer — `derive()` returns the
 *      inputs and a plain-language reason alongside the level, and the UI is
 *      required to surface them on hover.
 *
 * Deliberately not a score. Bands are explicit, the adjustments are named, and
 * each step is one level so a finding can never leap from low to critical on a
 * rounding change.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

export const atLeast = (a: Severity, b: Severity) =>
  SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b)

/**
 * Categories whose exposure is materially worse than the confidence alone
 * suggests: a live credential is actionable by an attacker immediately, and
 * card and health data carry direct regulatory consequence.
 */
const HIGH_STAKES = [
  'Generic Secrets',
  'Cloud Provider Secrets',
  'Code Platform Secrets',
  'Payment Service Secrets',
  'Messaging Service Secrets',
  'Credit Card Numbers',
  'Primary Account Numbers',
  'Protected Health Information',
]

/**
 * Categories that are sensitive but rarely an incident on their own. A work
 * email address in an outbound message is usually the job, not a leak.
 */
const LOW_STAKES = ['Contact Information', 'Network Identifiers', 'Dates']

function band(confidence: number): Severity {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.75) return 'high'
  if (confidence >= 0.6) return 'medium'
  if (confidence >= 0.4) return 'low'
  return 'info'
}

const step = (s: Severity, by: number): Severity =>
  SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, Math.max(0, SEVERITY_ORDER.indexOf(s) + by))]

export interface SeverityInputs {
  confidence: number
  category: string
  /** null when the pattern has no validator — not the same as failing one. */
  validated?: boolean | null
  hasContext?: boolean | null
}

export interface SeverityDerivation {
  level: Severity
  inputs: SeverityInputs
  /** Ordered, human-readable steps. Rendered verbatim in the hover. */
  reason: string[]
}

export function derive(inputs: SeverityInputs): SeverityDerivation {
  const { confidence, category, validated, hasContext } = inputs
  const reason: string[] = []

  let level = band(confidence)
  reason.push(`confidence ${confidence.toFixed(2)} → ${level}`)

  if (HIGH_STAKES.includes(category)) {
    const next = step(level, 1)
    if (next !== level) reason.push(`${category} is high-stakes → ${next}`)
    level = next
  } else if (LOW_STAKES.includes(category)) {
    const next = step(level, -1)
    if (next !== level) reason.push(`${category} is rarely an incident alone → ${next}`)
    level = next
  }

  // A validator that ran and failed is strong evidence against the match. A
  // pattern with no validator reports null, which is not the same fact and
  // must not be treated as a failure.
  if (validated === false) {
    const next = step(level, -1)
    if (next !== level) reason.push(`checksum failed → ${next}`)
    level = next
  } else if (validated === true) {
    reason.push('checksum passed')
  }

  if (hasContext === true) reason.push('supporting keyword nearby')

  return { level, inputs, reason }
}

/** Convenience for rows: derive straight from an API finding. */
export function deriveFinding(f: {
  confidence: number
  category: string
  validated?: boolean | null
  has_context?: boolean | null
}): SeverityDerivation {
  return derive({
    confidence: f.confidence,
    category: f.category,
    validated: f.validated,
    hasContext: f.has_context,
  })
}
