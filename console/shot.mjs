/**
 * Render check: screenshots every route in both themes, with the API either
 * mocked (`--mock`) or absent, and fails on any console error.
 *
 * Absent-API is not a degraded run — it is the case the contract cares most
 * about, because that is when a screen has to say "not measured" instead of
 * showing a zero.
 */
import { chromium } from 'playwright'

const MOCK = process.argv.includes('--mock')
const OUT = process.env.SHOT_DIR ?? '/tmp'
const BASE = 'http://127.0.0.1:4173'

const CATEGORIES = [
  { category: 'Credit Card Numbers', pattern_count: 9, sub_categories: ['Visa', 'MasterCard', 'Amex', 'Discover'] },
  { category: 'Contact Information', pattern_count: 14, sub_categories: ['Email Address', 'US Phone Number'] },
  { category: 'Generic Secrets', pattern_count: 31, sub_categories: ['AWS Access Key', 'Slack Token'] },
  { category: 'Government Identifiers', pattern_count: 62, sub_categories: ['USA SSN', 'Canada SIN', 'South Africa ID'] },
]

const SEED = [
  ['Credit Card Numbers', 'Visa', '4111111111111111', 0.96, true, 'tp'],
  ['Government Identifiers', 'USA SSN', '219-09-9999', 0.91, true, null],
  ['Generic Secrets', 'AWS Access Key', 'AKIAIOSFODNN7EXAMPLE', 0.88, null, null],
  ['Government Identifiers', 'Canada SIN', '046-454-286', 0.72, true, 'fp'],
  ['Contact Information', 'Email Address', 'aaron.dahl@statcan.gc.ca', 0.64, null, null],
  ['Credit Card Numbers', 'MasterCard', '5500005555555559', 0.55, false, null],
  ['Contact Information', 'US Phone Number', '613-859-6932', 0.42, null, null],
  ['Government Identifiers', 'South Africa ID', '8001015009087', 0.35, true, null],
]

const findings = Array.from({ length: 40 }, (_, i) => {
  const [category, sub, text, conf, validated, verdict] = SEED[i % SEED.length]
  return {
    id: `f_${String(i).padStart(4, '0')}a91c3de8b7`,
    scan_id: `s_${String(i).padStart(4, '0')}77bc21ef90`,
    category,
    sub_category: sub,
    matched_text: text,
    confidence: conf,
    span_start: 42,
    span_end: 42 + String(text).length,
    has_context: i % 3 !== 0,
    context_required: null,
    validated,
    created_at: new Date(Date.now() - i * 3_600_000).toISOString(),
    tenant_id: null,
    analyst_verdict: verdict,
    reviewed_at: verdict ? new Date().toISOString() : null,
    review_note: null,
  }
})

const hop = (state, detail, extra = {}) => ({ state, detail, ...extra })
const instance = (over) => ({
  instance: 'siphon-fs-7d9c4b-x2k9p',
  api_key_id: 'sk_abcdefghjkmn',
  version: '1.4.0',
  started_at: new Date(Date.now() - 3 * 86_400_000).toISOString(),
  uptime_secs: 3 * 86_400,
  restarts_7d: 1,
  last_seen: new Date(Date.now() - 12_000).toISOString(),
  interval_secs: 30,
  liveness: 'healthy',
  stale_for_secs: 0,
  availability: {
    h24: { received: 2871, expected: 2880, ratio: 0.9969 },
    d7: { received: 19_902, expected: 20_160, ratio: 0.9872 },
  },
  transport: {
    listener: hop('ok', 'mutual TLS', { cert_days_left: 71 }),
    database: hop('ok', 'mtls: client certificate presented'),
    overall: 'ok',
  },
  activity: {
    h24: { scans: 1_204, scans_with_findings: 86, findings: 141, errors: 2, bytes: 812_000_000, avg_duration_ms: 41.2, detection_rate: 0.0714 },
    d7: { scans: 8_911, scans_with_findings: 602, findings: 1_003, errors: 9, bytes: 6_100_000_000, avg_duration_ms: 39.8, detection_rate: 0.0676 },
  },
  last_scan_at: new Date(Date.now() - 95_000).toISOString(),
  ...over,
})

const SENSORS = {
  generated_at: new Date().toISOString(),
  sensors: [
    {
      sensor: 'siphon-api',
      liveness: 'healthy',
      instances: [
        instance({ instance: 'siphon-api-5f6b7c-a1b2c', api_key_id: null, version: '2.12.0', restarts_7d: 0 }),
        instance({ instance: 'siphon-api-5f6b7c-d3e4f', api_key_id: null, version: '2.12.0', restarts_7d: 0 }),
      ],
      availability: { h24: { received: 2880, expected: 2880, ratio: 1 }, d7: { received: 20_160, expected: 20_160, ratio: 1 } },
      transport_overall: 'ok',
      activity: { h24: { scans: 42_110, scans_with_findings: 1_902, findings: 2_640, errors: 3, detection_rate: 0.0452 }, d7: { scans: 301_400, scans_with_findings: 13_010, findings: 18_902, errors: 21, detection_rate: 0.0432 } },
      verdicts: { reviewed: 412, true_positives: 371, false_positives: 41, precision: 0.9005 },
      last_scan_at: new Date(Date.now() - 4_000).toISOString(),
    },
    {
      sensor: 'siphon-fs',
      liveness: 'healthy',
      instances: [instance({})],
      availability: { h24: { received: 2871, expected: 2880, ratio: 0.9969 }, d7: { received: 19_902, expected: 20_160, ratio: 0.9872 } },
      transport_overall: 'ok',
      activity: { h24: { scans: 1_204, scans_with_findings: 86, findings: 141, errors: 2, bytes: 812_000_000, detection_rate: 0.0714 }, d7: { scans: 8_911, scans_with_findings: 602, findings: 1_003, errors: 9, bytes: 6_100_000_000, detection_rate: 0.0676 } },
      verdicts: { reviewed: 38, true_positives: 30, false_positives: 8, precision: 0.789 },
      last_scan_at: new Date(Date.now() - 95_000).toISOString(),
    },
    {
      sensor: 'siphon-smtp',
      liveness: 'stale',
      instances: [
        instance({
          instance: 'siphon-smtp-9a8b7c-q1w2e',
          version: '0.2.0',
          liveness: 'stale',
          stale_for_secs: 1_140,
          last_seen: new Date(Date.now() - 1_140_000).toISOString(),
          transport: { listener: hop('not_applicable', 'no listener'), database: hop('warn', 'require: encrypted, service anonymous to the database'), overall: 'warn' },
          availability: { h24: { received: 2_100, expected: 2880, ratio: 0.729 }, d7: { received: 19_000, expected: 20_160, ratio: 0.942 } },
          activity: { h24: { scans: 3_301, scans_with_findings: 12, findings: 19, errors: 40, detection_rate: 0.0036 }, d7: { scans: 22_000, scans_with_findings: 90, findings: 140, errors: 210, detection_rate: 0.0041 } },
        }),
      ],
      availability: { h24: { received: 2_100, expected: 2880, ratio: 0.729 }, d7: { received: 19_000, expected: 20_160, ratio: 0.942 } },
      transport_overall: 'warn',
      activity: { h24: { scans: 3_301, scans_with_findings: 12, findings: 19, errors: 40, detection_rate: 0.0036 }, d7: { scans: 22_000, scans_with_findings: 90, findings: 140, errors: 210, detection_rate: 0.0041 } },
      verdicts: null,
      last_scan_at: new Date(Date.now() - 1_200_000).toISOString(),
    },
  ],
  never_seen: ['siphon-icap'],
}

const ROUTES = {
  '/api/v1/sensors': SENSORS,
  '/api/v1/health/detailed': {
    status: 'ok',
    version: '2.4.0',
    uptime_seconds: 61_200,
    patterns_loaded: 583,
    categories_loaded: 41,
    database: { connected: true, latency_ms: 3, findings_count: 128_412 },
    scans: { total: 91_204, errors: 12 },
  },
  '/api/v1/categories': CATEGORIES,
  '/api/v1/findings/pg': { findings, limit: 100, offset: 0 },
}

const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' })
const errs = []
const shots = []

for (const theme of ['dark', 'light']) {
  for (const r of ['/', '/detections', '/scan', '/patterns', '/running', '/ir', '/ir/alerts', '/ir/cases']) {
    const p = await b.newPage({ viewport: { width: 1440, height: 900 } })
    p.on('console', (m) => m.type() === 'error' && errs.push(`${theme}${r}: ${m.text()}`))
    p.on('pageerror', (e) => errs.push(`${theme}${r}: PAGEERROR ${e.message}`))

    if (MOCK) {
      await p.route('**/api/**', async (route) => {
        const path = new URL(route.request().url()).pathname
        const body = ROUTES[path]
        if (body === undefined) return route.fulfill({ status: 404, body: '{}' })
        return route.fulfill({ json: body })
      })
    }

    await p.goto(BASE + r, { waitUntil: 'networkidle' })
    await p.evaluate((t) => (document.documentElement.dataset.theme = t), theme)
    await p.waitForTimeout(500)
    const name = `${OUT}/c2${MOCK ? '' : '-noapi'}-${theme}${r.replace(/\//g, '-') || '-home'}.png`
    await p.screenshot({ path: name, fullPage: ['/detections', '/ir/alerts', '/running'].includes(r) })
    shots.push(name)
    await p.close()
  }
}

await b.close()
console.log(shots.join('\n'))
// A 502 with no API running is the point of that pass, not a failure.
const real = errs.filter((e) => !/502|Failed to load resource/.test(e))
if (real.length) {
  console.error('\nCONSOLE ERRORS:\n' + real.join('\n'))
  process.exit(1)
}
console.log('\nno unexpected console errors')
