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
// Mirrors sensors_api::reading — value, working, target, gap, state.
const reading = (n, d, target, basis) => {
  const value = n === null || d === null || d === 0 ? null : Math.min(1, n / d)
  const gap = value === null || target === null ? null : value - target
  const state =
    value === null ? 'unmeasured' : target === null ? 'no_target' : value + 1e-9 >= target ? 'met' : 'gap'
  return { value, numerator: n, denominator: d, target, gap, state, basis }
}
const T = { availability: 0.99, coverage: 0.95, precision: 0.8, canary: 1 }
const windowed = (h24, d7) => ({ h24, d7 })
const posture = (on_finding, on_indeterminate, degraded) => ({ on_finding, on_indeterminate, ...(degraded ? { degraded } : {}) })
const canaryLast = (passed, agoMs) => ({
  passed,
  detail: passed ? 'found North America - United States and Credit Card Numbers' : 'missing Credit Card Numbers',
  at: new Date(Date.now() - agoMs).toISOString(),
})
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
  operational: { state: 'ok', detail: 'advisory by design: the caller acts on the findings', posture: posture('advisory', 'not_applicable') },
  transport: {
    listener: hop('ok', 'mutual TLS', { cert_days_left: 71 }),
    database: hop('ok', 'mtls: client certificate presented'),
    overall: 'ok',
  },
  activity: {
    h24: { scans: 1_204, scans_with_findings: 86, findings: 141, errors: 2, unscanned: 91, bytes: 812_000_000, avg_duration_ms: 41.2 },
    d7: { scans: 8_911, scans_with_findings: 602, findings: 1_003, errors: 9, unscanned: 640, bytes: 6_100_000_000, avg_duration_ms: 39.8 },
  },
  last_canary: canaryLast(true, 12_000),
  last_scan_at: new Date(Date.now() - 95_000).toISOString(),
  ...over,
})
const acee = ({ liveness = 'healthy', beats = [2871, 2880], beats7 = [19_902, 20_160], operational, scans = 1204, unscanned = 91, canary = [2871, 2871], canary7 = [19_902, 19_902], verdicts = null, lastCanary = canaryLast(true, 12_000), ms = 41.2, msMb = 61, errRate = 0.0017 }) => {
  const opState = operational.state === 'ok' ? 'met' : operational.state === 'warn' ? 'gap' : 'unmeasured'
  const beat = reading(beats[0], beats[1], T.availability, 'heartbeat slots received ÷ slots expected')
  const availState = liveness !== 'healthy' ? 'gap' : [beat.state, opState].includes('gap') ? 'gap' : [beat.state, opState].includes('unmeasured') ? 'unmeasured' : 'met'
  const cov = reading(scans, unscanned === null ? null : scans + unscanned, T.coverage, 'items scanned ÷ items seen (scanned + passed unscanned)')
  const can = reading(canary[1] > 0 ? canary[0] : null, canary[1] > 0 ? canary[1] : null, T.canary, 'heartbeats whose canary found every planted category ÷ heartbeats that ran one')
  const prec = reading(verdicts ? verdicts.true_positives : null, verdicts ? verdicts.true_positives + verdicts.false_positives : null, T.precision, 'findings an analyst ruled true ÷ findings an analyst ruled, 7 d')
  const worst = (a, b) => (a === 'gap' || b === 'gap' ? 'gap' : a === 'unmeasured' || b === 'unmeasured' ? 'unmeasured' : 'met')
  return {
    availability: { running: liveness, beats: windowed(beat, reading(beats7[0], beats7[1], T.availability, 'heartbeat slots received ÷ slots expected')), operational, state: availState },
    coverage: { at_depth: windowed(cov, cov), state: cov.state, note: 'Coverage against the environment — mail flows, proxies and file paths that have no sensor at all — cannot be measured from inside a sensor. This is coverage at depth: of what reached the sensor, how much it read.' },
    efficacy: { canary: windowed(can, reading(canary7[0], canary7[1], T.canary, 'x')), ...(lastCanary ? { last_canary: lastCanary } : {}), precision: prec, verdicts, state: worst(can.state, prec.state), note: 'Canary recall is one fixture with two planted values, scanned through the deployed path each heartbeat. It proves the path finds what it is for; it does not prove recall is high. Adversarial recall is in the program header.' },
    efficiency: {
      ...(ms !== null ? { ms_per_scan_24h: ms, ms_per_mb_24h: msMb, errors_per_scan_24h: errRate } : {}),
      ...(verdicts ? { reviewed_7d: verdicts.reviewed, false_positives_7d: verdicts.false_positives } : {}),
      measured: [...(ms !== null ? ['compute'] : []), ...(verdicts ? ['operator attention', 'false positives (count, not blast radius)'] : [])],
      unmeasured: [...(ms === null ? ['compute'] : []), ...(verdicts ? [] : ['operator attention', 'false-positive blast radius']), 'license cost', 'maintenance cost', 'opportunity cost'],
    },
  }
}

const apiOp = { state: 'ok', detail: 'advisory by design: the caller acts on the findings', posture: posture('advisory', 'not_applicable') }
const smtpOp = { state: 'warn', detail: 'annotates; fails closed; annotates only: enforcement is delegated downstream and not verified here', posture: posture('annotate', 'closed') }
const apiVerdicts = { reviewed: 412, true_positives: 371, false_positives: 41, precision: 0.9005 }
const fsVerdicts = { reviewed: 38, true_positives: 30, false_positives: 8, precision: 0.789 }

const SENSORS = {
  schema_version: 2,
  generated_at: new Date().toISOString(),
  objectives: { expected: ['siphon-api', 'siphon-fs', 'siphon-icap', 'siphon-smtp'], ...T, source: 'defaults' },
  program: {
    matrix_coverage: reading(2, 4, T.coverage, 'expected sensors that are healthy and operational ÷ expected sensors'),
    adversarial: { recall: reading(1_840, 2_000, null, 'variants detected ÷ variants, latest evadex run'), runs: 14, last_run_at: new Date(Date.now() - 5 * 3_600_000).toISOString(), scanner_label: 'siphon-core 3.1.0' },
  },
  sensors: [
    {
      sensor: 'siphon-api',
      liveness: 'healthy',
      acee: acee({ beats: [2880, 2880], beats7: [20_160, 20_160], operational: apiOp, scans: 42_110, unscanned: 12, canary: [2880, 2880], canary7: [20_160, 20_160], verdicts: apiVerdicts, ms: 3.4, msMb: 210, errRate: 0.00007 }),
      instances: [
        instance({ instance: 'siphon-api-5f6b7c-a1b2c', api_key_id: null, version: '2.12.0', restarts_7d: 0, operational: apiOp }),
        instance({ instance: 'siphon-api-5f6b7c-d3e4f', api_key_id: null, version: '2.12.0', restarts_7d: 0, operational: apiOp }),
      ],
      availability: { h24: { received: 2880, expected: 2880, ratio: 1 }, d7: { received: 20_160, expected: 20_160, ratio: 1 } },
      transport_overall: 'ok',
      activity: { h24: { scans: 42_110, scans_with_findings: 1_902, findings: 2_640, errors: 3, unscanned: 12 }, d7: { scans: 301_400, scans_with_findings: 13_010, findings: 18_902, errors: 21, unscanned: 80 } },
      last_scan_at: new Date(Date.now() - 4_000).toISOString(),
    },
    {
      sensor: 'siphon-fs',
      liveness: 'healthy',
      acee: acee({ operational: instance({}).operational, verdicts: fsVerdicts }),
      instances: [instance({})],
      availability: { h24: { received: 2871, expected: 2880, ratio: 0.9969 }, d7: { received: 19_902, expected: 20_160, ratio: 0.9872 } },
      transport_overall: 'ok',
      activity: { h24: { scans: 1_204, scans_with_findings: 86, findings: 141, errors: 2, unscanned: 91, bytes: 812_000_000 }, d7: { scans: 8_911, scans_with_findings: 602, findings: 1_003, errors: 9, unscanned: 640, bytes: 6_100_000_000 } },
      last_scan_at: new Date(Date.now() - 95_000).toISOString(),
    },
    {
      sensor: 'siphon-smtp',
      liveness: 'stale',
      acee: acee({ liveness: 'stale', beats: [2100, 2880], beats7: [19_000, 20_160], operational: smtpOp, scans: 3_301, unscanned: 14, canary: [2099, 2100], canary7: [18_999, 19_000], verdicts: null, lastCanary: canaryLast(false, 1_140_000), ms: 118, msMb: 44, errRate: 0.012 }),
      instances: [
        instance({
          instance: 'siphon-smtp-9a8b7c-q1w2e',
          version: '0.2.0',
          liveness: 'stale',
          stale_for_secs: 1_140,
          last_seen: new Date(Date.now() - 1_140_000).toISOString(),
          operational: smtpOp,
          last_canary: canaryLast(false, 1_140_000),
          transport: { listener: hop('not_applicable', 'no listener'), database: hop('warn', 'require: encrypted, service anonymous to the database'), overall: 'warn' },
          availability: { h24: { received: 2_100, expected: 2880, ratio: 0.729 }, d7: { received: 19_000, expected: 20_160, ratio: 0.942 } },
          activity: { h24: { scans: 3_301, scans_with_findings: 12, findings: 19, errors: 40, unscanned: 14 }, d7: { scans: 22_000, scans_with_findings: 90, findings: 140, errors: 210, unscanned: 95 } },
        }),
      ],
      availability: { h24: { received: 2_100, expected: 2880, ratio: 0.729 }, d7: { received: 19_000, expected: 20_160, ratio: 0.942 } },
      transport_overall: 'warn',
      activity: { h24: { scans: 3_301, scans_with_findings: 12, findings: 19, errors: 40, unscanned: 14 }, d7: { scans: 22_000, scans_with_findings: 90, findings: 140, errors: 210, unscanned: 95 } },
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
