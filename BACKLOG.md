# Siphon Backlog

Last updated: 2026-06-14

## Ready to build

### High priority
- [x] siphon-api serve subcommand — persistent HTTP API without k8s (PR #318; siphon serve delegates to siphon-api binary)
- [ ] Findings deduplication — don't store duplicate findings for identical input

### Medium priority
- [ ] LSH persistence — store document similarity results in postgres
- [ ] evadex results → postgres — store evadex scan results in findings table for C2 trending
- [ ] POST /v1/findings/prune ?days=N — already done, document in API reference

### Detection improvements (from evadex data)
- [ ] Morse code remaining bypass — currently ~50%, target <30%
- [ ] Regional digits — Thai, Extended Arabic-Indic still high bypass

### Infrastructure
- [ ] Helm chart: postgres subchart or external postgres configuration
- [ ] siphon-fs postgres pool — already wired, needs end-to-end test
- [ ] lab-up.sh — add postgres to local kind setup

## In progress (open PRs)
- [ ] #311 — fix(core): trim trailing whitespace in morse no-sep decoder
- [ ] #297 — deps: bump calamine 0.34→0.35 (dependabot)

## Recently completed
- [x] Delimiter normalization (stage 6b) — PR #300
- [x] Encoding decode passes — PR #301/#302
- [x] Dot-stripping regression fix — PR #303
- [x] Morse code decode — PR #304/#308/#309/#310
- [x] Swiss VALOR detection — PR #289
- [x] SEDOL detection, Malta TIN FP fix, regional digits — PR #274
- [x] Findings persistence schema — PR #312
- [x] C2 Findings History tab — PR #313
- [x] Batch + file scan persistence — PR #314
- [x] Retention policy — PR #315
- [x] evadex v3.28.2 published to PyPI
- [x] Findings export endpoint — GET /v1/findings/export (CSV + JSON, 100k row limit, date range filter)
- [x] Rate limiting on findings query endpoints — /v1/findings/export 5/min, /v1/findings/pg 30/min, /v1/findings/stats 60/min per IP
- [x] Stats caching — /v1/findings/stats response cached 60s to avoid repeated full-table COUNT scans
- [x] EDM persistence — migration 0005_edm.sql + persist_edm_query/persist_edm_registration in db.rs + wired into scan handler
- [x] CUSIP context keywords expanded — added instrument, ticker, position, identifier, portfolio, holding, asset, issuance, prospectus, indenture, maturity, coupon, face value, par value; distance 50→75
- [x] Encoding chain alternatives — base64→ROT13, ROT13→base64, hex→base64 two-stage chains in generate_alternative_decodings
- [x] Postgres end-to-end in kind cluster — siphon-lab cluster verified, postgres deployed, findings persistence tested
