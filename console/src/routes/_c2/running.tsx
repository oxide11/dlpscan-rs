import { createFileRoute } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { api, type HopReport, type HopState, type SensorReport, type Ratio } from '../../lib/api'
import { Page, PageHeader, Card, KeyValue } from '../../ui/layout'
import { Pillar } from '../../ui/pillar'
import { Badge } from '../../ui/badge'
import { Button } from '../../ui/button'
import { Disclosure } from '../../ui/disclosure'
import { MonoValue } from '../../ui/mono'
import { AbsenceNote, EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/_c2/running')({ component: RunningRoute })

/**
 * "Is each sensor up, is it talking securely, is it catching things?"
 *
 * Three questions per detector, answered from heartbeat rows the server
 * aggregates — the console renders judgements, it does not make them. The one
 * thing this page adds is refusing to let a missing sensor look like a quiet
 * one: `never_seen` is rendered as loudly as `gone`.
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
        description="Every detector, by heartbeat: availability from the beats it sent, transport from what it reported, efficacy from what it counted."
        meta={
          r ? (
            <span className="text-t5 text-ink-muted">
              measured {new Date(r.generated_at).toLocaleTimeString()} · refreshes every 30 s
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
          {r!.never_seen.length > 0 && (
            <AbsenceNote
              className="mb-4"
              what={`${r!.never_seen.join(', ')} — never heard from`}
              why="No heartbeat has ever arrived from these sensors. Either they are not running, or SIPHON_TELEMETRY_URL and a Sensor key are not configured on them."
              consequence="Not a sensor that is quiet. A sensor nobody can see. Traffic it should be inspecting may be passing uninspected."
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
        </>
      )}
    </Page>
  )
}

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

function SensorCard({ s }: { s: SensorReport }) {
  const a = s.activity.h24
  const v = s.verdicts
  return (
    <Card
      title={
        <div className="flex items-center gap-2">
          <h2 className="font-mono text-t4 font-semibold text-ink">{s.sensor}</h2>
          <Badge tone={LIVENESS_TONE[s.liveness]} dot>
            {s.liveness}
          </Badge>
          <Badge tone={HOP_TONE[s.transport_overall]}>
            mTLS {HOP_LABEL[s.transport_overall]}
          </Badge>
          <span className="text-t5 text-ink-muted">
            {s.instances.length} instance{s.instances.length === 1 ? '' : 's'}
            {s.last_scan_at ? ` · last scan ${ago(s.last_scan_at)}` : ' · never scanned'}
          </span>
        </div>
      }
      bodyClassName="p-0"
    >
      <div className="grid gap-px bg-line-subtle md:grid-cols-4">
        <div className="bg-surface p-3">
          <Pillar
            label="Availability, 24 h"
            numerator={s.availability.h24.ratio === null ? null : s.availability.h24.received}
            denominator={s.availability.h24.ratio === null ? null : s.availability.h24.expected}
            unit="heartbeat slots"
            format="pct"
            polarity="higher-better"
            delta={null}
            note={
              s.availability.d7.ratio === null
                ? 'No 7-day figure yet.'
                : `${pct(s.availability.d7)}% over 7 days.`
            }
          />
        </div>
        <div className="bg-surface p-3">
          {/* Absent counters render as unverified, never 0 — a sensor that
              does not count scans is not a sensor that scanned nothing. */}
          <Pillar
            label="Detection rate, 24 h"
            numerator={a.scans_with_findings ?? null}
            denominator={a.scans ?? null}
            unit="scans with findings"
            format="pct"
            polarity="neutral"
            delta={null}
            note={
              a.findings !== undefined
                ? `${a.findings.toLocaleString()} findings${a.errors ? ` · ${a.errors} errors` : ''}`
                : undefined
            }
          />
        </div>
        <div className="bg-surface p-3">
          <Pillar
            label="Precision, 7 d"
            numerator={v && v.precision !== null ? v.true_positives : null}
            denominator={v && v.precision !== null ? v.true_positives + v.false_positives : null}
            unit="reviewed as true"
            format="pct"
            polarity="higher-better"
            delta={null}
            note={
              v
                ? `${v.reviewed} reviewed by an analyst.`
                : 'No verdicts on this sensor’s findings yet.'
            }
          />
        </div>
        <div className="bg-surface p-3">
          <Pillar
            label="Throughput, 24 h"
            numerator={a.scans ?? null}
            denominator={null}
            unit="scans"
            format="count"
            polarity="neutral"
            delta={null}
            note={
              a.bytes !== undefined
                ? `${(a.bytes / 1_048_576).toFixed(1)} MB read`
                : 'Bytes not counted by this sensor.'
            }
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
