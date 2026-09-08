/**
 * siphon-api client.
 *
 * Auth is deliberately **not** handled here. Per the component contract, the
 * bearer token never touches `localStorage` — an XSS in this console would
 * otherwise be credential theft against the API. Two supported deployments:
 *
 *   1. The reverse proxy terminates auth and sets an httpOnly, SameSite=Strict
 *      cookie. `credentials: 'same-origin'` below is what carries it.
 *   2. A short-lived token held in memory only, installed via `setToken()`
 *      after an interactive login. It dies with the tab.
 *
 * There is no third option, and nothing here writes to storage.
 *
 * Matched values arrive **redacted by default**. Masking is a server-side
 * control keyed on the caller's role, not a UI courtesy — see
 * `crates/siphon-api/src/masking.rs`. Passing `unmask` asks for values in the
 * clear; the server grants it only if the role holds the permission, and
 * records the disclosure either way.
 */

let memoryToken: string | null = null

/** Install a short-lived bearer token for this tab only. Never persisted. */
export function setToken(token: string | null) {
  memoryToken = token
}

export class ApiError extends Error {
  readonly status: number
  readonly body: string
  readonly url: string

  constructor(status: number, body: string, url: string) {
    super(`${status} from ${url}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
    this.url = url
  }
}

/**
 * Everything is reached under `/api`, never the origin root — siphon-api's
 * `POST /scan` would otherwise collide with this console's `/scan` route once
 * the bundle is embedded in the same binary, separated only by HTTP method.
 */
const BASE = import.meta.env.VITE_SIPHON_API_BASE ?? '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${BASE}${path}`
  const headers = new Headers(init?.headers)
  headers.set('Accept', 'application/json')
  if (init?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (memoryToken) headers.set('Authorization', `Bearer ${memoryToken}`)

  const res = await fetch(url, { ...init, headers, credentials: 'same-origin' })
  if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => ''), url)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

const qs = (params: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

/* -------------------------------------------------------------------------
 * Response shapes.
 *
 * Hand-written today. These are the shapes most likely to drift against the
 * Rust structs — the durable fix is generating them (ts-rs or schemars →
 * OpenAPI) rather than maintaining this by hand. Tracked in docs/README.md.
 * ---------------------------------------------------------------------- */

export interface Finding {
  id: string
  scan_id: string
  category: string
  sub_category: string | null
  matched_text: string | null
  confidence: number
  span_start: number | null
  span_end: number | null
  has_context: boolean | null
  /** Always NULL from the engine today — see ENGINE-NOTES.md. */
  context_required: boolean | null
  validated: boolean | null
  created_at: string
  tenant_id: string | null
  analyst_verdict: 'tp' | 'fp' | 'unsure' | null
  reviewed_at: string | null
  review_note: string | null
  metadata?: Record<string, unknown> | null
}

export interface FindingsPage {
  findings: Finding[]
  total?: number
  limit: number
  offset: number
}

/** Who the caller is, per `GET /v1/me`. */
export interface Me {
  actor: string
  role:
    | 'admin'
    | 'analyst'
    | 'responder'
    | 'responder-readonly'
    | 'auditor'
    | 'operator'
    | 'sensor'
    | 'viewer'
  auth_source: 'proxy' | 'api_key' | 'open_mode'
  permissions: string[]
  /** Present only for an issued key. */
  key_id?: string
  tenant?: string
}

/* Sensors — `GET /v1/sensors`. Every figure here is derived server-side from
 * heartbeat rows; the console renders, it does not judge. */

export type Liveness = 'healthy' | 'stale' | 'gone'
export type HopState = 'not_applicable' | 'ok' | 'warn' | 'off'

export interface HopReport {
  state: HopState
  detail: string
  cert_days_left?: number
}

export interface Ratio {
  received: number
  expected: number
  /** Absent when nothing was expected yet — not 0. */
  ratio: number | null
}

export interface Activity {
  scans?: number
  scans_with_findings?: number
  findings?: number
  errors?: number
  bytes?: number
  avg_duration_ms?: number
  detection_rate?: number
}

export interface Windowed<T> {
  h24: T
  d7: T
}

export interface SensorInstance {
  instance: string
  api_key_id: string | null
  version: string
  started_at: string
  uptime_secs: number
  restarts_7d: number
  last_seen: string
  interval_secs: number
  liveness: Liveness
  stale_for_secs: number
  availability: Windowed<Ratio>
  transport: { listener: HopReport; database: HopReport; overall: HopState }
  activity: Windowed<Activity>
  last_scan_at: string | null
}

export interface SensorReport {
  sensor: string
  liveness: Liveness
  instances: SensorInstance[]
  availability: Windowed<Ratio>
  transport_overall: HopState
  activity: Windowed<Activity>
  verdicts: {
    reviewed: number
    true_positives: number
    false_positives: number
    precision: number | null
  } | null
  last_scan_at: string | null
}

export interface SensorsReport {
  generated_at: string
  sensors: SensorReport[]
  /** Expected by every deployment, never heard from. */
  never_seen: string[]
}

export interface CategoryInfo {
  category: string
  pattern_count: number
  sub_categories: string[]
}

export interface DetailedHealth {
  status: string
  version: string
  uptime_seconds: number
  patterns_loaded: number
  categories_loaded: number
  database?: {
    connected: boolean
    latency_ms: number | null
    findings_count: number | null
  } | null
  scans?: { total: number; errors: number } | null
}

export interface ScanMatch {
  text: string
  category: string
  sub_category: string
  confidence: number
  span: [number, number]
  has_context: boolean
  context_required: boolean
  metadata?: Record<string, string>
}

export interface ThroughputPoint {
  hour: string
  scans: number
  bytes: number
  findings: number
}

export interface OverridesSnapshot {
  disabled_patterns?: string[]
  regex_overrides?: Record<string, string>
  min_confidence?: Record<string, number>
  [k: string]: unknown
}

export interface AuditEvent {
  id?: string
  timestamp: string
  event_type: string
  actor?: string | null
  detail?: string | null
  hash?: string | null
}

/* ---------------------------------------------------------------------- */

export const api = {
  health: () => request<{ status: string; pod?: string }>('/health'),
  detailedHealth: () => request<DetailedHealth>('/v1/health/detailed'),
  dbHealth: () => request<Record<string, unknown>>('/v1/db/health'),
  metrics: () => request<Record<string, number>>('/v1/metrics'),

  categories: () => request<CategoryInfo[]>('/v1/categories'),
  policies: () => request<unknown[]>('/v1/policies'),
  allowlist: () => request<unknown>('/v1/allowlist'),
  audit: () => request<AuditEvent[]>('/v1/audit'),

  scan: (text: string, options?: Record<string, unknown>) =>
    request<ScanMatch[]>('/scan', {
      method: 'POST',
      body: JSON.stringify({ text, options }),
    }),

  explain: (text: string) =>
    request<unknown>('/v1/scan/explain', {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),

  findingsRing: () => request<Finding[]>('/v1/findings'),

  me: () => request<Me>('/v1/me'),

  sensors: () => request<SensorsReport>('/v1/sensors'),

  /**
   * `unmask` is `pii`, `pci` or `pii,pci`. Omitting it returns redacted
   * values, which is the default for every caller whatever their role — the
   * server decides, and an unmasked request is audited there.
   */
  findingsPage: (p: {
    category?: string
    limit?: number
    offset?: number
    unmask?: string
  }) => request<FindingsPage>(`/v1/findings/pg${qs(p)}`),

  findingsStats: () => request<Record<string, unknown>>('/v1/findings/stats'),

  throughput: (p: { hours?: number; tenant?: string; channel?: string }) =>
    request<ThroughputPoint[]>(`/v1/stats/throughput${qs(p)}`),

  /** Returns the export URL rather than fetching — the browser downloads it. */
  exportUrl: (p: {
    format: 'csv' | 'json'
    category?: string
    from?: string
    to?: string
    limit?: number
    unmask?: string
  }) => `${BASE}/v1/findings/export${qs(p)}`,

  feedback: (id: string, verdict: 'tp' | 'fp' | 'unsure', note?: string) =>
    request<void>(`/v1/findings/${encodeURIComponent(id)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ verdict, note }),
    }),

  overridesCurrent: () => request<OverridesSnapshot>('/v1/overrides/current'),

  overridesApply: (body: OverridesSnapshot) =>
    request<unknown>('/v1/overrides/apply', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  evadexRuns: (p: { limit?: number; offset?: number }) =>
    request<unknown>(`/v1/evadex/runs${qs(p)}`),
  evadexStats: () => request<unknown>('/v1/evadex/runs/stats'),

  baselinesCurrent: () => request<unknown>('/v1/baselines/current'),
  baselinesDelta: () => request<unknown>('/v1/baselines/delta'),
}
