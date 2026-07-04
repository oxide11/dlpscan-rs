# Siphon Backlog

Last updated: 2026-07-04

## Ready to build

### UI/UX improvements
- [ ] Scan results — show confidence scores, span highlighting, BIN enrichment for credit cards
- [x] Findings history table — sortable (click headers) and CSV export button (feat/backlog-sprint-2)
- [ ] Loading states — smoother transitions, skeleton screens
- [ ] File upload scan — drag and drop interface in Scan tab
- [ ] Scan results — highlight matched text in original input

### Stability
- [x] nginx configmap persists across pod restarts — mounted from siphon-nginx-config ConfigMap (Authorization + API key survive restart), verified (fix/stability)
- [x] SIPHON_API_KEY set in lab — injected from siphon-api-auth secret into siphon-api + siphon-fs; verified live (fix/stability)
- [x] lab-up.sh idempotent — declarative apply for namespace/secret/configmap + SIGPIPE fix in key generation; runs cleanly twice with a stable API key (fix/stability)

### Adversarial Testing tab
- [ ] evadex bridge metrics fully wired — show real detection rate, FP rate, coverage
- [ ] File generator working end to end — generate and download test files from UI
- [ ] Run Now fully working — trigger scan from C2 and see results

### Findings tab
- [x] Postgres history showing correctly — /v1/findings/pg populates from siphon-fs file scans; verified end-to-end (fix/stability)
- [x] Export button — CSV export via /v1/findings/export (feat/backlog-sprint-2)
- [ ] Date range filter working

### High priority
- [x] siphon-api serve subcommand — persistent HTTP API without k8s (PR #318; siphon serve delegates to siphon-api binary)
- [x] Streaming scan SSE — POST /scan/stream returns findings as Server-Sent Events as discovered; done+duration final frame
- [x] Pattern hot-reload — notify v6 file watcher on SIPHON_OVERRIDES_PATH; debounced auto-reload + POST /v1/admin/reload (RequireAdminAction)
- [ ] Findings deduplication — don't store duplicate findings for identical input

### Medium priority
- [x] LSH persistence — store document similarity results in postgres (PR #320)
- [x] evadex results → postgres — store evadex scan results in findings table for C2 trending (PR #321)
- [x] POST /v1/findings/prune ?days=N — done; documented in docs/enterprise/api.md

### Detection improvements (from evadex data)
- [x] Morse code file-scan bypass — fixed: embedded morse segments now found in filename-prefixed text (PR #336)
- [x] JCB detection — fixed: hex-decoder no longer corrupts all-digit JCB numbers (PR #336)
- [x] Morse code em-dash/en-dash variants — fixed: U+2013/2014/2212/2015 mapped to '-' in HOMOGLYPH_MAP (PR #349)
- [x] Morse code IBAN bypass — fixed: all 4 evadex variants (space/nosep/newline/slash sep) now detected; slash decoder extended to accept multi-char alpha tokens merged by stage 6b (PR #349)
- [ ] Morse code remaining bypass — ~40% remaining (evadex measures ~29%); target <30%. Remaining failures are context-required IDs (SSN/SIN/AU_TFN/DE_TAX_ID/FR_INSEE) skipped by the morse alt-decode path by design. PR #349 chips at this.
- [x] Regional digits — Thai (U+0E50), Extended Arabic-Indic (U+06F0), Arabic-Indic (U+0660) now detected via HOMOGLYPH_MAP; Thai-digit card regression locked in (PR #359); verified PASS in the evadex suite

### Infrastructure
- [ ] Helm chart: postgres subchart or external postgres configuration
- [x] siphon-fs postgres pool — fixed missing SIPHON_DATABASE_URL in 30-siphon-fs.yaml; file-scan findings now reach postgres; verified end-to-end (fix/stability)
- [x] lab-up.sh — add postgres to local kind setup

## In progress (open PRs)
- [ ] #349 — fix(core): em-dash/en-dash homoglyphs + IBAN mixed-nosep morse decoder
- [ ] #350 — deps: bump kube 3.1→4.0 and k8s-openapi 0.27→0.28

## Resumption notes (for when you come back)

Start here:
1. Check open PRs — several may be ready to merge (#360 final-sprint docs;
   #350 kube 4.0 bump; #349 morse/regional homoglyph fix).
2. Run evadex against the latest Siphon for a fresh detection baseline
   (`cd ../evadex && python -m evadex scan --transport http --url http://localhost:8080/api --tier northam --fast`).
3. Tackle the morse bypass — biggest remaining detection gap (~40% internal /
   ~29% evadex). See PR #349 and the morse alt-decode path.
4. Wire real auth (`SIPHON_API_KEY`) + TLS before any non-lab deployment; run a
   load test to establish a throughput/latency baseline.

See `HANDOFF.md` for full state, versions, and commands.

## Recently completed
- [x] C2 command palette (Ctrl+K) — full surface search + quick actions, keyboard-navigable (feat/backlog-sprint-2)
- [x] LiveScan Ctrl+Enter shortcut — trigger scan from textarea keyboard shortcut (feat/backlog-sprint-2)
- [x] LiveScan session history — last 5 scans with snippet / finding count / duration (feat/backlog-sprint-2)
- [x] LiveScan green no-findings banner — distinct ✓ banner when scan returns 0 findings (feat/backlog-sprint-2)
- [x] FindingsHistory sortable columns — click column header to sort ascending/descending (feat/backlog-sprint-2)
- [x] FindingsHistory CSV export — ↓ CSV button calls /v1/findings/export (feat/backlog-sprint-2)
- [x] Makefile — build/test/lint/scan/fmt/pr-check targets (feat/backlog-sprint-2)
- [x] docker-compose.dev.yml — local dev without kind, postgres healthcheck wired (feat/backlog-sprint-2)
- [x] lab-up.sh service health checks — check_service() waits for HTTP 200 on each svc (feat/backlog-sprint-2)
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
- [x] LSH persistence — migration 0006_lsh.sql + persist_lsh_query/persist_lsh_registration in db.rs + wired into scan handler; GET /v1/lsh/history; GET /v1/findings/stats extended with lsh section
- [x] evadex → postgres — migration 0007_evadex.sql; POST/GET /v1/evadex/runs + GET /v1/evadex/runs/stats in siphon-api; bridge push-to-siphon via SIPHON_API_URL; C2 Stored Runs panel
- [x] CUSIP context keywords expanded — added instrument, ticker, position, identifier, portfolio, holding, asset, issuance, prospectus, indenture, maturity, coupon, face value, par value; distance 50→75
- [x] Encoding chain alternatives — base64→ROT13, ROT13→base64, hex→base64 two-stage chains in generate_alternative_decodings
- [x] Morse em-dash/en-dash + IBAN mixed-nosep decoder — siphon-core 2.1.4; see fix/morse-regional-context PR
- [x] Postgres end-to-end in kind cluster — siphon-lab cluster verified, postgres deployed, findings persistence tested
- [x] Streaming scan SSE + pattern hot-reload — feat/streaming-hotreload branch; see PR for full details
- [x] Admin-console read-only endpoints — GET /v1/categories, POST /v1/scan/explain, GET /v1/health/detailed (PR #345); recorded in CHANGELOG siphon-api 2.4.0
- [x] Pipe-morse + Thai-digit card detection regression tests — tests/integration_test.rs (PR #359)
