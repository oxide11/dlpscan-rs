import { createFileRoute } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  api,
  type AxisState,
  type HopReport,
  type HopState,
  type OperationalReport,
  type Ratio,
  type Reading,
  type SensorReport,
  type SensorsReport,
} from '../../lib/api'
import { Page, PageHeader, Card, KeyValue } from '../../ui/layout'
import { Pillar } from '../../ui/pillar'
import { Badge } from '../../ui/badge'
import { Button } from '../../ui/button'
import { Disclosure } from '../../ui/disclosure'
import { MonoValue } from '../../ui/mono'
import { AbsenceNote, EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/_c2/running')({ component: RunningRoute })

/**
 * ACEE per sensor: Availability, Coverage, Efficacy, Efficiency — the
 * performance lens from *Inside the Adversary's Loop* — each axis judged on
 * the server against a stated target and rendered here with its working.
 *
 * Three rules this page keeps. A figure that was not measured reads
 * `unverified`, never 0. The four axes are four tiles, never one number.
 * Every tile shows numerator, denominator and target, because a percentage
 * without those is a score. And a sensor the deployment expects but has never
 * heard from is rendered as loudly as one that is gone.
 */
function RunningRoute() {
  const q = useQuery({
    queryKey: ['sensors'],
    queryFn: api.sensors,
    refetchInterval: 30_000,
  })
  const r = q.data

  return (
    <Page>
      <PageHeader
        title="Running"
        description="Every detector as four axes — available, covering, working, affordable — each read against its target, not against last week."
        meta={
          r ? (
            <span className="text-t5 text-ink-muted">
              measured {new Date(r.generated_at).toLocaleTimeString()} · refreshes every 30 s ·
              schema v{r.schema_version} · targets: {r.objectives.source}
            </span>
          ) : null
        }
        actions={
          <Button onClick={() => q.refetch()} loading={q.isFetching}>
            Refresh
          </Button>
        }
      />

      {q.isError ? (
        <AbsenceNote
          what="sensor telemetry"
          why={
            q.error instanceof Error && /503/.test(q.error.message)
              ? 'siphon-api has no database, so heartbeats are not stored.'
              : 'siphon-api did not answer /v1/sensors.'
          }
          consequence="Nothing below was measured. An unmeasured sensor is not a healthy one."
          remedy={
            <Button size="sm" onClick={() => q.refetch()}>
              Retry
            </Button>
          }
        />
      ) : q.isPending ? (
        <Card>
          <p className="text-t4 text-ink-muted">Reading heartbeats…</p>
        </Card>
      ) : (
        <>
          <ProgramStrip r={r!} />

          {r!.never_seen.length > 0 && (
            <AbsenceNote
              className="mb-4"
              what={`${r!.never_seen.join(', ')} — never heard from`}
              why="No heartbeat has ever arrived from these sensors. Either they are not running, or SIPHON_TELEMETRY_URL and a Sensor key are not configured on them."
              consequence="Not a sensor that is quiet. A sensor nobody can see. Traffic it should be inspecting may be passing uninspected, and coverage against the matrix counts it as absent."
            />
          )}

          {r!.sensors.length === 0 && r!.never_seen.length === 0 ? (
            <Card>
              <EmptyState title="No sensors" detail="Nothing has reported in the last seven days." />
            </Card>
          ) : (
            <div className="flex flex-col gap-4">
              {r!.sensors.map((s) => (
                <SensorCard key={s.sensor} s={s} />
              ))}
            </div>
          )}

          <Notes r={r!} />
        </>
      )}
    </Page>
  )
}

/* ── vocabulary ─────────────────────────────────────────────────────────── */

const LIVENESS_TONE = { healthy: 'ok', stale: 'attn', gone: 'attn' } as const
const HOP_TONE: Record<HopState, 'ok' | 'attn' | 'muted' | 'neutral'> = {
  ok: 'ok',
  warn: 'attn',
  off: 'attn',
  not_applicable: 'muted',
}
const HOP_LABEL: Record<HopState, string> = {
  ok: 'mutual',
  warn: 'weak',
  off: 'off',
  not_applicable: 'n/a',
}
const AXIS_TONE: Record<AxisState, 'ok' | 'attn' | 'muted' | 'neutral'> = {
  met: 'ok',
  gap: 'attn',
  unmeasured: 'muted',
  no_target: 'neutral',
}
const AXIS_LABEL: Record<AxisState, string> = {
  met: 'met',
  gap: 'gap',
  unmeasured: 'unmeasured',
  no_target: 'no target',
}

function pct(r: Ratio) {
  return r.ratio === null ? null : Math.round(r.ratio * 1000) / 10
}

function ago(iso: string) {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 90) return `${s}s ago`
  if (s < 5400) return `${Math.round(s / 60)}m ago`
  if (s < 172800) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

function dur(secs: number) {
  if (secs < 3600) return `${Math.round(secs / 60)}m`
  if (secs < 172800) return `${(secs / 3600).toFixed(1)}h`
  return `${(secs / 86400).toFixed(1)}d`
}

function AxisBadge({ state }: { state: AxisState }) {
  return (
    <Badge tone={AXIS_TONE[state]} dot={state !== 'unmeasured'}>
      {AXIS_LABEL[state]}
    </Badge>
  )
}

/** The badge word for a sensor's posture: what it does on a finding, or why
 * it is doing less than its whole job. */
function operationalWord(o: OperationalReport): { word: string; tone: 'ok' | 'attn' | 'muted' } {
  if (o.state === 'not_reported') return { word: 'posture n/r', tone: 'muted' }
  const mode =
    o.posture?.on_finding === 'block'
      ? 'blocks'
      : o.posture?.on_finding === 'annotate'
        ? 'annotates'
        : 'advisory'
  if (o.state === 'ok') return { word: mode, tone: 'ok' }
  if (o.posture?.degraded) return { word: `${mode} · degraded`, tone: 'attn' }
  if (o.posture?.on_indeterminate === 'open') return { word: `${mode} · fails open`, tone: 'attn' }
  return { word: `${mode} · delegated`, tone: 'attn' }
}

function Hop({ label, h }: { label: string; h: HopReport }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-t5 text-ink-muted">{label}</span>
      <Badge tone={HOP_TONE[h.state]} dot={h.state !== 'not_applicable'} title={h.detail}>
        {HOP_LABEL[h.state]}
        {h.cert_days_left !== undefined && h.state !== 'off' ? ` · ${h.cert_days_left}d` : ''}
      </Badge>
    </span>
  )
}

/** A Reading as a Pillar: numerator, denominator, target — all from the server. */
function ReadingPillar({
  label,
  r,
  unit,
  note,
}: {
  label: string
  r: Reading
  unit: string
  note?: string
}) {
  return (
    <Pillar
      label={label}
      numerator={r.value === null ? null : r.numerator}
      denominator={r.value === null ? null : r.denominator}
      unit={unit}
      format="pct"
      polarity="higher-better"
      delta={null}
      target={r.target}
      note={note}
    />
  )
}

/* ── program header ─────────────────────────────────────────────────────── */

function ProgramStrip({ r }: { r: SensorsReport }) {
  const p = r.program
  const a = p.adversarial
  return (
    <Card title="Program" bodyClassName="p-0" className="mb-4">
      <div className="grid gap-px bg-line-subtle md:grid-cols-2">
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <AxisBadge state={p.matrix_coverage.state} />
            <span className="text-t5 text-ink-muted">coverage against the matrix</span>
          </div>
          <ReadingPillar
            label="Expected sensors up and operational"
            r={p.matrix_coverage}
            unit="expected sensors"
            note={`Expected: ${r.objectives.expected.join(', ')}. A sensor that annotates only, fails open, is degraded, stale, or never seen does not count.`}
          />
        </div>
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <AxisBadge state={a ? a.recall.state : 'unmeasured'} />
            <span className="text-t5 text-ink-muted">adversarial recall, evadex</span>
          </div>
          {a ? (
            <ReadingPillar
              label="Variants detected, latest run"
              r={a.recall}
              unit="evasion variants"
              note={`${a.runs} run${a.runs === 1 ? '' : 's'} ingested · latest ${ago(a.last_run_at)}${a.scanner_label ? ` · ${a.scanner_label}` : ''}. Program-wide: evadex drives the scanner, not a sensor.`}
            />
          ) : (
            <Pillar
              label="Variants detected, latest run"
              numerator={null}
              denominator={null}
              unit="evasion variants"
              delta={null}
              note="No evadex run has been ingested. Recall against an adversarial corpus is unmeasured — the canaries below prove each path works, not that it resists evasion."
            />
          )}
        </div>
      </div>
    </Card>
  )
}

/* ── one sensor ─────────────────────────────────────────────────────────── */

function SensorCard({ s }: { s: SensorReport }) {
  const { availability, coverage, efficacy, efficiency } = s.acee
  const a = s.activity.h24
  const op = operationalWord(availability.operational)
  return (
    <Card
      title={
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="font-mono text-t4 font-semibold text-ink">{s.sensor}</h2>
          <Badge tone={LIVENESS_TONE[s.liveness]} dot>
            {s.liveness}
          </Badge>
          <Badge tone={op.tone} dot={op.tone !== 'muted'} title={availability.operational.detail}>
            {op.word}
          </Badge>
          <Badge tone={HOP_TONE[s.transport_overall]}>mTLS {HOP_LABEL[s.transport_overall]}</Badge>
          <span className="text-t5 text-ink-muted">
            {s.instances.length} instance{s.instances.length === 1 ? '' : 's'}
            {s.last_scan_at ? ` · last scan ${ago(s.last_scan_at)}` : ' · never scanned'}
          </span>
        </div>
      }
      bodyClassName="p-0"
    >
      <div className="grid gap-px bg-line-subtle md:grid-cols-4">
        {/* Availability = deployed ∧ running ∧ operational. The ratio is the
            running term; the note is the operational one, which is where a
            control that "is up" stops protecting anything. */}
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <AxisBadge state={availability.state} />
            <span className="text-t5 font-medium uppercase tracking-wide text-ink-muted">
              Availability
            </span>
          </div>
          <ReadingPillar
            label="Heartbeat slots, 24 h"
            r={availability.beats.h24}
            unit="heartbeat slots"
            note={`${availability.beats.d7.value === null ? 'No 7-day figure yet' : `${(availability.beats.d7.value * 100).toFixed(1)}% over 7 days`}. ${availability.operational.detail}.`}
          />
        </div>

        {/* Coverage at depth: of what reached the sensor, what it read. */}
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <AxisBadge state={coverage.state} />
            <span className="text-t5 font-medium uppercase tracking-wide text-ink-muted">
              Coverage
            </span>
          </div>
          <ReadingPillar
            label="Items read, 24 h"
            r={coverage.at_depth.h24}
            unit="items seen"
            note={
              coverage.at_depth.h24.value === null
                ? a.scans === undefined
                  ? 'Nothing counted in 24 h.'
                  : 'This sensor predates the unscanned count, so its reach is unmeasured.'
                : `${(a.unscanned ?? 0).toLocaleString()} passed unscanned — over a size cap, binary, or beyond the scanner limit.`
            }
          />
        </div>

        {/* Efficacy: recall and precision, separately. Never F1. */}
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <AxisBadge state={efficacy.state} />
            <span className="text-t5 font-medium uppercase tracking-wide text-ink-muted">
              Efficacy
            </span>
          </div>
          <div className="flex flex-col gap-3">
            <ReadingPillar
              label="Canary recall, 24 h"
              r={efficacy.canary.h24}
              unit="heartbeats with a canary"
              note={
                efficacy.last_canary
                  ? `Last: ${efficacy.last_canary.passed ? 'passed' : 'FAILED'}, ${efficacy.last_canary.detail}.`
                  : 'No canary has run — this sensor predates it.'
              }
            />
            <ReadingPillar
              label="Precision, 7 d"
              r={efficacy.precision}
              unit="findings ruled by an analyst"
              note={
                efficacy.verdicts
                  ? `${efficacy.verdicts.reviewed} reviewed.`
                  : 'No verdicts on this sensor’s findings yet.'
              }
            />
          </div>
        </div>

        {/* Efficiency: three of six cost dimensions; the other three named. */}
        <div className="bg-surface p-3">
          <div className="mb-1 flex items-center gap-2">
            <Badge tone={efficiency.measured.length === 0 ? 'muted' : 'neutral'}>
              {efficiency.measured.length} of 6 dimensions
            </Badge>
            <span className="text-t5 font-medium uppercase tracking-wide text-ink-muted">
              Efficiency
            </span>
          </div>
          <Pillar
            label="Compute, 24 h"
            numerator={
              efficiency.ms_per_scan_24h === undefined
                ? null
                : Math.round(efficiency.ms_per_scan_24h * 10) / 10
            }
            denominator={null}
            unit="ms per scan"
            format="count"
            polarity="lower-better"
            delta={null}
            note={[
              efficiency.ms_per_mb_24h !== undefined
                ? `${Math.round(efficiency.ms_per_mb_24h).toLocaleString()} ms/MB`
                : null,
              efficiency.errors_per_scan_24h !== undefined
                ? `${(efficiency.errors_per_scan_24h * 100).toFixed(2)}% errors`
                : null,
              efficiency.reviewed_7d !== undefined
                ? `${efficiency.reviewed_7d} reviewed, ${efficiency.false_positives_7d ?? 0} false, 7 d`
                : null,
              `Unmeasured: ${efficiency.unmeasured.join(', ')}.`,
            ]
              .filter(Boolean)
              .join(' · ')}
          />
        </div>
      </div>

      <div className="border-t border-line-subtle px-3 py-0">
        {s.instances.map((i) => (
          <Disclosure
            key={i.instance}
            label={i.instance}
            summary={
              <>
                <Badge tone={LIVENESS_TONE[i.liveness]} dot>
                  {i.liveness}
                  {i.liveness !== 'healthy' ? ` ${dur(i.stale_for_secs)}` : ''}
                </Badge>
                {i.last_canary && (
                  <Badge tone={i.last_canary.passed ? 'ok' : 'attn'} dot title={i.last_canary.detail}>
                    canary {i.last_canary.passed ? 'ok' : 'failed'}
                  </Badge>
                )}
                <Hop label="listener" h={i.transport.listener} />
                <Hop label="database" h={i.transport.database} />
                <span className="text-t5 text-ink-muted">
                  v{i.version} · up {dur(i.uptime_secs)}
                  {i.restarts_7d > 0 ? ` · ${i.restarts_7d} restart${i.restarts_7d === 1 ? '' : 's'} in 7 d` : ''}
                </span>
              </>
            }
          >
            <KeyValue
              rows={[
                { key: 'Last heartbeat', value: `${ago(i.last_seen)} (every ${i.interval_secs}s)` },
                { key: 'Started', value: new Date(i.started_at).toLocaleString() },
                {
                  key: 'Reported as',
                  value: i.api_key_id ? (
                    <MonoValue value={i.api_key_id} copy />
                  ) : (
                    <span className="text-ink-muted">in-process (siphon-api’s own row)</span>
                  ),
                },
                { key: 'Posture', value: i.operational.detail },
                {
                  key: 'Canary',
                  value: i.last_canary
                    ? `${i.last_canary.passed ? 'passed' : 'failed'} — ${i.last_canary.detail} (${ago(i.last_canary.at)})`
                    : 'not run — this sensor predates it',
                },
                { key: 'Listener', value: i.transport.listener.detail },
                { key: 'Database', value: i.transport.database.detail },
                {
                  key: 'Availability',
                  value: `${pct(i.availability.h24) ?? '—'}% / 24 h · ${pct(i.availability.d7) ?? '—'}% / 7 d`,
                  provenance: `${i.availability.h24.received}/${i.availability.h24.expected} slots`,
                },
                {
                  key: 'Activity, 7 d',
                  value:
                    i.activity.d7.scans !== undefined
                      ? `${i.activity.d7.scans.toLocaleString()} scans · ${
                          i.activity.d7.findings?.toLocaleString() ?? '—'
                        } findings${
                          i.activity.d7.unscanned !== undefined
                            ? ` · ${i.activity.d7.unscanned.toLocaleString()} unscanned`
                            : ''
                        }${
                          i.activity.d7.avg_duration_ms !== undefined
                            ? ` · ${i.activity.d7.avg_duration_ms.toFixed(1)} ms avg`
                            : ''
                        }`
                      : 'not counted',
                },
                {
                  key: 'Last scan',
                  value: i.last_scan_at ? ago(i.last_scan_at) : 'never',
                },
              ]}
            />
          </Disclosure>
        ))}
      </div>
    </Card>
  )
}

/* ── what the page cannot read ──────────────────────────────────────────── */

function Notes({ r }: { r: SensorsReport }) {
  const first = r.sensors[0]
  return (
    <div className="mt-4 flex flex-col gap-1 text-t5 text-ink-muted">
      <p>
        <span className="font-medium text-ink">Coverage.</span>{' '}
        {first?.acee.coverage.note ??
          'Coverage against the environment — flows with no sensor at all — cannot be measured from inside a sensor.'}
      </p>
      <p>
        <span className="font-medium text-ink">Efficacy.</span>{' '}
        {first?.acee.efficacy.note ??
          'Canary recall is one fixture through the deployed path: it proves the path, not the recall.'}
      </p>
      <p>
        <span className="font-medium text-ink">Targets.</span> Availability ≥{' '}
        {(r.objectives.availability * 100).toFixed(0)}%, coverage ≥ {(r.objectives.coverage * 100).toFixed(0)}%,
        precision ≥ {(r.objectives.precision * 100).toFixed(0)}%, canary ≥{' '}
        {(r.objectives.canary * 100).toFixed(0)}% — from {r.objectives.source}. These should come from an
        objectives layer; until one exists they are declared, and this line says so.
      </p>
    </div>
  )
}
