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

const ROUTES = {
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
  for (const r of ['/', '/findings', '/scan', '/patterns']) {
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
    await p.screenshot({ path: name, fullPage: r === '/findings' })
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
