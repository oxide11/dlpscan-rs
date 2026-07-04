# Siphon — Handoff Notes

Last updated: 2026-07-04

Companion doc to `CLAUDE.md` (architecture/conventions) and `BACKLOG.md`
(work queue). This file is the "resume here after a break" quick-start.

## Current state

- **Versions** (per-crate SemVer — see `CLAUDE.md` "Versioning"):
  - `siphon` (root CLI) — **2.2.0**
  - `siphon-core` — **2.1.3**
  - `siphon-api` — **2.4.0**
  - `siphon-fs` — **1.0.0**
  - `siphon-launcher` — **2.1.0**
- **Tests — all passing** (verified 2026-07-04):
  - `cargo test --lib` → **154 passed**
  - `cargo test --test integration_test` → **69 passed**
  - `cargo test --test evasion_test` → **12 passed**
  - Total: **235 passing, 0 failing**
- **Detection spot check: 10/10 passing** — visa (plain / base64 / morse /
  zero-width / dotted), SIN, IBAN, CUSIP, ISIN, LEI all detected. Reproduce with
  the "Scan test" command below.
- **Branch:** `refine/final-sprint` (4 commits ahead of `main`, open as PR #360).
- **Working tree:** `Cargo.lock` touched by dependabot merges; a few untracked
  `morse_*.py` / `pr349_body.md` scratch files at repo root — **not** part of the
  codebase, safe to ignore or delete.

## Open PRs

| PR | Branch | Summary | Notes |
|---|---|---|---|
| #360 | `refine/final-sprint` | chore(api): record admin-console endpoints as siphon-api 2.4.0 + these handoff docs | current branch; ready to merge |
| #350 | `claude/branch-merge-review-goyt39` | deps: bump kube 3.1→4.0 and k8s-openapi 0.27→0.28 | dependency bump; needs CI green + review of `k8s-roll` feature usage |
| #349 | `fix/morse-regional-context` | fix(core): em-dash/en-dash homoglyphs + IBAN mixed-nosep morse decoder | detection fix; verify against evadex morse suite before merge |

## To resume work

```bash
git checkout main && git pull
cargo build --release                          # default features
# OR: cargo build --release --features full     # everything (siem, webhooks, tls, k8s-roll, …)

# Local lab (kind cluster + postgres):
./scripts/lab-up.sh --no-build                 # cluster already exists
./scripts/lab-up.sh                            # fresh build
# then browse to the C2 UI:
#   http://127.0.0.1:8080/ui/     (siphon-api)
```

> Lab auth is `devBypass=true` — **no real auth in the lab**, do not expose it.

## Key commands

- **Build:** `cargo build --release` (add `--features full` for everything)
- **Lint (CI parity):** `cargo fmt --check` &&
  `cargo clippy --lib -- -D warnings -A dead-code -A unused-imports`
- **Test:** `cargo test --lib` / `--test integration_test` / `--test evasion_test`
- **Lab up:** `./scripts/lab-up.sh` (`--no-build` to reuse a running cluster)
- **Scan test:**
  `echo "4532015112830366" | ./target/release/siphon.exe scan-text --format json`
  (JSON output is a **top-level array** of matches, not `{"matches": [...]}`)
- **evadex against Siphon** (fresh baseline):
  ```bash
  cd ../evadex
  python -m evadex scan --transport http --url http://localhost:8080/api --tier northam --fast
  ```

## Architecture summary

- `crates/siphon-core` — pattern-matching engine, 10-stage normalization
  pipeline (`scanner/mod.rs`, `normalize/mod.rs`), 72 checksum validators.
- `crates/siphon-api` — HTTP scan API, Postgres persistence (migrations
  `0001`–`0007`), findings/EDM/LSH/evadex endpoints, audit chain.
- `crates/siphon-fs` — multipart file-scan service (PDF/Office/archives/…).
- `crates/siphon-launcher` — loopback-only local-dev process manager.
- `docs/wireframes/siphon-c2.html` — single-file React C2 UI.
- `deploy/k8s/lab/` — kind cluster manifests; `deploy/helm/siphon/` — prod chart.

Full detail lives in `CLAUDE.md`.

## What was built (this sprint)

- **Findings persistence wave** (siphon-api 2.3.0, PRs #312–#321): Postgres
  scans+findings schema, `persist_scan()` background writes, retention policy
  (`SIPHON_FINDINGS_RETENTION_DAYS`), `GET /v1/findings/pg|stats|export`,
  rate-limiting + 60 s stats caching, batch/file-scan persistence.
- **EDM + LSH persistence**: migrations `0005_edm.sql` / `0006_lsh.sql`;
  `GET /v1/lsh/history`; stats endpoint extended with an LSH section.
- **evadex → Postgres** (migration `0007_evadex.sql`): `POST/GET /v1/evadex/runs`
  + `/v1/evadex/runs/stats`; bridge push-to-siphon; C2 "Stored Runs" panel.
- **Streaming scan + hot-reload**: `POST /scan/stream` (SSE), notify-v6 file
  watcher on `SIPHON_OVERRIDES_PATH` + `POST /v1/admin/reload`.
- **Admin-console read-only endpoints** (siphon-api 2.4.0, PR #345):
  `GET /v1/categories`, `POST /v1/scan/explain`, `GET /v1/health/detailed`.
- **Detection (siphon-core 2.1.3)**: CUSIP context keywords expanded (14 new,
  distance 50→75); encoding-chain alternatives (base64→ROT13, ROT13→base64,
  hex→base64); morse file-scan + JCB fixes (PR #336); pipe-morse & Thai-digit
  card regression tests locked in (PR #359).
- **Lab/DX**: postgres in the kind lab, `lab-up.sh` health checks + idempotency
  work, Makefile targets, `docker-compose.dev.yml`, C2 command palette (Ctrl+K),
  LiveScan history/shortcuts, sortable findings history + CSV export.

## Biggest remaining gaps

1. **Morse-code bypass** — Siphon still misses ~40% of morse variants on its
   internal measure (evadex measures ~29% residual). The remaining failures are
   context-required patterns (SSN/SIN/AU_TFN/DE_TAX_ID/FR_INSEE) that the morse
   alt-decode path skips **by design** (no nearby keyword survives the morse
   transform). Target <30%. PR #349 chips at this — start there.
2. **Regional digits** — Thai (U+0E50), Extended Arabic-Indic (U+06F0),
   Arabic-Indic (U+0660) are covered by `HOMOGLYPH_MAP` and now PASS in evadex's
   suite; a Thai-digit card regression test is locked in (PR #359). Re-verify
   with a fresh evadex run and close out the stale BACKLOG line if clean.
3. **Real auth** — lab runs `devBypass=true`. `SIPHON_API_KEY` (SHA-256 hashed)
   exists but is not wired into the lab. Not production-ready without it.
4. **TLS** — lab is HTTP only. `tls` (rustls) feature exists; not enabled in lab.
5. **Load testing** — not done. No throughput/latency baseline under concurrency.

## Resumption checklist

1. `git checkout main && git pull`; review the three open PRs (#349/#350/#360) —
   several are ready to merge.
2. Run evadex against the latest Siphon for a fresh detection baseline.
3. Tackle the morse bypass (biggest remaining detection gap) — see PR #349.
4. Wire real auth + TLS before any non-lab deployment.
