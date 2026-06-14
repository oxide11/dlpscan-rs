# Siphon Backlog

Last updated: 2026-06-13

## Ready to build

### High priority
- [ ] Test postgres findings end to end in kind cluster — spin up postgres, verify persist_scan(), query endpoints, retention pruning
- [ ] Findings export endpoint — GET /v1/findings/export returns CSV for compliance teams
- [ ] Rate limiting on /v1/findings/pg — prevent expensive queries impacting scan performance
- [ ] siphon-api serve subcommand — persistent HTTP API without k8s (needed for evadex bridge integration)

### Medium priority
- [ ] EDM persistence — store exact match registration + query results in postgres
- [ ] LSH persistence — store document similarity results in postgres
- [ ] evadex results → postgres — store evadex scan results in findings table for C2 trending
- [ ] Findings deduplication — don't store duplicate findings for identical input
- [ ] POST /v1/findings/prune ?days=N — already done, document in API reference

### Detection improvements (from evadex data)
- [ ] Morse code remaining bypass — currently ~50%, target <30%
- [ ] Encoding chains — base64→ROT13 chains still high bypass
- [ ] CUSIP context — only detected in settlement format
- [ ] Regional digits — Thai, Extended Arabic-Indic still high bypass

### Infrastructure
- [ ] Helm chart: postgres subchart or external postgres configuration
- [ ] siphon-fs postgres pool — already wired, needs end-to-end test
- [ ] lab-up.sh — add postgres to local kind setup

## In progress (open PRs)
- [ ] #311 — fix(core): trim trailing whitespace in morse no-sep decoder
- [ ] #312 — findings schema + persist_scan + query endpoints
- [ ] #313 — C2 Findings History tab
- [ ] #314 — batch + file scan persistence
- [ ] #315 — retention policy
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
