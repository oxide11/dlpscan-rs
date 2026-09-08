/**
 * Cases, derived from findings.
 *
 * # There is no case store
 *
 * The engine has no investigations API — no `/v1/cases`, no assignee, no
 * status, no notes. The IR prototype kept all of that in `localStorage`, which
 * means it existed on one analyst's laptop and nowhere else.
 *
 * Rather than invent persistence the server cannot back, a case here is
 * **derived**: one scan is one candidate case. That is not arbitrary — a scan
 * is the unit of ingest, so every finding in it arrived together, from the
 * same document or message, and investigating one almost always means
 * investigating its siblings.
 *
 * What this gives you honestly: grouping, severity rollup, review progress,
 * age. What it cannot give you: assignment, state transitions, narrative,
 * anything that outlives the retention window. Those need an API, and the UI
 * says so rather than faking them.
 */

import type { Finding } from './api'
import { deriveFinding, SEVERITY_ORDER, type Severity } from './severity'

export interface Case {
  /** The scan this case is derived from. */
  scanId: string
  findings: Finding[]
  /** Highest severity across the findings — what the case is worth. */
  severity: Severity
  /** Distinct categories, most frequent first. */
  categories: string[]
  reviewed: number
  total: number
  /** Earliest finding timestamp; a case is as old as its first sighting. */
  firstSeen: string
  lastSeen: string
}

const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s)

export function deriveCases(findings: Finding[]): Case[] {
  const byScan = new Map<string, Finding[]>()
  for (const f of findings) {
    const arr = byScan.get(f.scan_id)
    if (arr) arr.push(f)
    else byScan.set(f.scan_id, [f])
  }

  const cases: Case[] = []
  for (const [scanId, group] of byScan) {
    let severity: Severity = 'info'
    const counts = new Map<string, number>()
    let firstSeen = group[0].created_at
    let lastSeen = group[0].created_at
    let reviewed = 0

    for (const f of group) {
      const lvl = deriveFinding(f).level
      if (rank(lvl) > rank(severity)) severity = lvl
      counts.set(f.category, (counts.get(f.category) ?? 0) + 1)
      if (f.created_at < firstSeen) firstSeen = f.created_at
      if (f.created_at > lastSeen) lastSeen = f.created_at
      if (f.analyst_verdict) reviewed += 1
    }

    cases.push({
      scanId,
      findings: group,
      severity,
      categories: [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c),
      reviewed,
      total: group.length,
      firstSeen,
      lastSeen,
    })
  }

  // Worst first, then oldest — the two questions a responder asks in order.
  return cases.sort(
    (a, b) => rank(b.severity) - rank(a.severity) || a.firstSeen.localeCompare(b.firstSeen),
  )
}

/**
 * Median time from a finding being recorded to a human ruling on it.
 *
 * Median, not mean: one finding left unreviewed over a weekend would drag a
 * mean into uselessness, and the number is meant to describe the typical case.
 * Returns `null` when nothing has been reviewed — there is no MTTR yet, and a
 * zero would read as "instant" rather than "unknown".
 */
export function medianReviewMinutes(findings: Finding[]): number | null {
  const deltas = findings
    .filter((f) => f.analyst_verdict && f.reviewed_at)
    .map((f) => (Date.parse(f.reviewed_at!) - Date.parse(f.created_at)) / 60_000)
    .filter((d) => Number.isFinite(d) && d >= 0)
    .sort((a, b) => a - b)

  if (deltas.length === 0) return null
  const mid = Math.floor(deltas.length / 2)
  return deltas.length % 2 ? deltas[mid] : (deltas[mid - 1] + deltas[mid]) / 2
}

/** Whole-unit age, for a column that has to stay narrow. */
export function ageLabel(iso: string, now = Date.now()): string {
  const mins = Math.max(0, (now - Date.parse(iso)) / 60_000)
  if (mins < 60) return `${Math.round(mins)}m`
  if (mins < 60 * 24) return `${Math.round(mins / 60)}h`
  return `${Math.round(mins / (60 * 24))}d`
}
