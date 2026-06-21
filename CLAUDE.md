# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Siphon is a high-performance DLP scanner built as a Rust Cargo workspace. The
top-level crate (`siphon`) is the CLI; the workspace members in `crates/` are
long-running services:

- `siphon-core` — scanner engine (patterns, validators, detection pipeline)
- `siphon-api` — sync HTTP scan service with RBAC, API-key auth, audit chain
- `siphon-fs` — multipart file-scan service (PDF, Office, archives, etc.)
- `siphon-launcher` — local-dev process manager (loopback-only, no auth)

Deployment assets live under `deploy/` (Dockerfiles, docker-compose, Helm
chart, k8s manifests). Rulesets live in `rulesets/` as **YAML** files.

## Toolchain

- **Rust: 1.95** (pinned in `rust-toolchain.toml`, mirrored in every
  `Cargo.toml` `rust-version`, CI workflows, and Dockerfile base images). Bump
  all five in lockstep when upgrading.
- **Edition: 2021**
- `Cargo.lock` is committed. Dockerfiles build with `--locked`; do not
  regenerate the lockfile without intent.

## Common commands

```bash
# Lint / format check
cargo fmt --check
cargo clippy --lib -- -D warnings -A dead-code -A unused-imports

# Run all tests
cargo test --lib
cargo test --test integration_test
cargo test --test evasion_test

# Run a single test by name (use -- --exact for exact match)
cargo test --lib test_luhn_validation
cargo test --test integration_test test_detects_ssn -- --exact

# Build
cargo build --release                                     # default features
cargo build --release --features "siem,webhooks"          # add SIEM/webhooks
cargo build --release --features full                     # everything
cargo build --release --no-default-features --features metrics  # minimal

# Benchmark
cargo run --release --bin benchmark
```

Other test harnesses (not run by default CI):
```bash
cargo test --test detection_quality   # labeled-corpus regression suite
cargo test --test fp_probe            # false-positive investigation
cargo test --test evadex_regressions  # regressions from evadex adversarial harness
cargo test --test forensics_test      # Office/PDF metadata tests
cargo test --test audit_spec          # audit chain HMAC integrity
```

## Architecture

### Detection pipeline (siphon-core)

The scan path in `crates/siphon-core/src/scanner/mod.rs` is a 10-stage pipeline:

1. **Input validation** — reject > 10 MB or empty inputs
2. **Normalization** (`normalize/mod.rs`) — 10 evasion-defeat stages:
   zero-width stripping → HTML entity decode → percent-decode → homoglyph
   substitution (Cyrillic/Greek/mathematical → ASCII) → leet-speak → NFKC →
   nested base64/base64url/base32/hex decode (up to 3 layers) → whitespace normalize
3. **RegexSet phase-1** — single O(n) pass identifies which patterns fire
4. **Per-pattern regex phase-2** — extracts spans only for matched patterns
5. **Checksum validation** (`validation.rs`) — 72 validators (Luhn, mod-97
   IBAN, Verhoeff, Base58Check, Bech32, ISO 3779, …)
6. **Context checking** (`context/`) — Aho-Corasick prefilter on 5,000+
   keywords across 6 languages; context-gated patterns are skipped entirely
   if no nearby keyword is found
7. **Confidence scoring** (`scoring.rs`) — base specificity per pattern ±
   adjustments for context presence / validation pass/fail
8. **Deduplication** — overlapping match removal
9. **Override application** (`overrides.rs`) — disabled patterns, regex
   overrides, match-list bindings (allow/block/mask/tag), unique-count
   thresholds; applied from a `LiveOverrides` snapshot (hot-reloadable)
10. **Emission** — sorted by confidence

Key types in `crates/siphon-core/src/models.rs`:
- `Match` — text, category, sub_category, confidence (0.0–1.0), span offsets,
  metadata (BIN issuer/country enrichment). `redacted_text()` shows first 3 +
  last 3 chars; `masked_text()` fully masks.
- `PatternDef` — category, sub_category, regex, case_insensitive, specificity,
  context_required
- `ScanConfig` — categories filter, min_confidence, require_context,
  deduplicate, entropy modes, EDM/LSH integration, optional trace sink

Other notable modules in siphon-core:
- `edm.rs` — Exact Data Match (SHA-256 hash vault, HMAC-SHA256 lookup)
- `lsh.rs` — Locality-Sensitive Hashing for document-similarity labeling
- `audit.rs` — tamper-evident HMAC-SHA256 audit chain + ring-buffer cache
- `findings_ring.rs` — in-memory VecDeque of recent findings per pod
- `forensics/` — Office/PDF metadata extraction (feature-gated)

### siphon-api routes

Auth: every request requires `Authorization: Bearer <key>` header (SHA-256 hashed
at rest from `SIPHON_API_KEY` env var; stateless per-request check). `/health`
and `/ready` are unauthenticated (kubelet probes).

```
GET  /health                    pod identity + liveness
GET  /ready                     readiness probe
POST /scan                      text → findings (JSON body: {text, options?})
POST /scan/batch                [{text, id}] → [{id, findings}]
GET  /v1/policies               loaded *.yaml rulesets (read-only)
GET  /v1/allowlist              current allowlist
GET  /v1/audit                  recent events from audit ring buffer
GET  /v1/findings               recent findings from this pod's FindingsRing (in-memory)
GET  /v1/findings/pg            Postgres-backed paginated findings (?category=&limit=&offset=)
GET  /v1/findings/stats         category breakdown + daily counts (cached 60s) + LSH section
GET  /v1/findings/export        bulk CSV/JSON export (?format=csv|json&category=&from=&to=&limit=, max 100k rows; 5/min rate limit)
POST /v1/findings/prune         manual retention trigger — admin only
POST /v1/overrides/apply        hot-reload PatternOverrides (no restart)
GET  /v1/overrides/current      current PatternOverrides snapshot
GET  /v1/metrics                scans_total, findings_total, scan_errors_total
GET  /v1/db/health              Postgres pool state
GET  /v1/lsh/history            paginated LSH query history from Postgres (?limit=&offset=&matched_only=)
POST /v1/evadex/runs            ingest completed evadex scan from bridge (idempotent on run_id)
GET  /v1/evadex/runs            paginated evadex run history (?limit=&offset=, max 500)
GET  /v1/evadex/runs/stats      aggregated detection rate + top-10 bypassed techniques
POST /v1/overrides/roll         annotate k8s Deployment for auto-rollout (feature: k8s-roll)
```

Key env vars for siphon-api:

| Variable | Default | Notes |
|---|---|---|
| `SIPHON_PORT` | 8080 | |
| `SIPHON_BIND` | 127.0.0.1 | |
| `SIPHON_API_KEY` | — | required in production |
| `SIPHON_TLS_CERT` / `SIPHON_TLS_KEY` | — | PEM paths |
| `SIPHON_CORS_ORIGINS` | none | comma-separated |
| `SIPHON_RATE_LIMIT` | 120 | req/min per IP |
| `SIPHON_REQUEST_TIMEOUT_SECS` | 30 | |
| `SIPHON_AUDIT_LOG_PATH` | — | JSONL audit file |
| `SIPHON_AUDIT_SIGNING_KEY_HEX` | — | enables HMAC-SHA256 chain |
| `SIPHON_AUDIT_TAIL_PATH` | — | chain tail state file |
| `SIPHON_AUDIT_RING_CAP` | 500 | in-memory event buffer |
| `SIPHON_FINDINGS_RING_CAP` | 1000 | recent findings buffer |
| `SIPHON_POLICIES_DIR` | — | directory of *.yaml rulesets |
| `SIPHON_ALLOWLIST_PATH` | — | JSON allowlist |
| `SIPHON_DATABASE_URL` | — | Postgres (optional) |
| `SIPHON_FINDINGS_RETENTION_DAYS` | 90 | Days to retain findings (0 = keep forever) |
| `SIPHON_OVERRIDES_PATH` | — | PatternOverrides YAML (hot-reloadable) |

The `LiveOverrides` state is an `Arc<RwLock<…>>` snapshot cloned per request —
operators can call `POST /v1/overrides/apply` to swap overrides without restart.
Findings rings are per-pod; each replica maintains its own ring.

## Findings persistence layer (postgres)

Migration files in `crates/siphon-api/src/migrations/`:
- `0001_init.sql` — pgcrypto, pg_trgm, db_health table
- `0002_findings.sql` — scans + findings tables, 6 indexes including GIN trigram
- `0003_file_scans.sql` — adds file_name, file_hash, mime_type to scans
- `0004_retention.sql` — prune_findings() PL/pgSQL function + retention index

Key functions in `crates/siphon-api/src/db.rs`:
- `init_optional()` → `(PoolState, Option<Pool>)` — three states: Unconfigured/Connected/StartupFailed
- `persist_scan(pool, scan_id, api_key, input, response, duration_ms, action)` — called after every scan
- `prune_old_findings(pool, retention_days)` — called by background task + `POST /v1/findings/prune`

Scan endpoints with persistence:
- `POST /scan` → `persist_scan()` via `tokio::spawn` (non-blocking)
- `POST /scan/batch` → one `persist_scan()` per item via `tokio::spawn`
- siphon-fs file scans → persist via `crates/siphon-fs/src/db.rs` (schema owned by siphon-api)

Findings query endpoints:
- `GET /v1/findings` — in-memory ring (existing, unchanged)
- `GET /v1/findings/pg?category=&limit=&offset=` — postgres query
- `GET /v1/findings/stats` — category breakdown + daily counts
- `POST /v1/findings/prune` — manual retention trigger (admin only)

Env vars for postgres:

| Variable | Default | Notes |
|---|---|---|
| `SIPHON_DATABASE_URL` | — | Postgres connection string (optional) |
| `SIPHON_FINDINGS_RETENTION_DAYS` | 90 | Days to retain findings (0 = keep forever) |

C2 wireframe:
- `docs/wireframes/siphon-c2.html` — current full-stack C2 dashboard
- Command palette `Ctrl+K` — full surface search + quick actions, keyboard-navigable
- LiveScan — `Ctrl+Enter` shortcut, last-5-scan session history, green no-findings banner
- FindingsHistory tab — sortable columns, CSV export button (`↓ CSV` → `/v1/findings/export`), postgres-backed pagination
- History tab polls `/v1/findings/stats` every 60s, `/v1/findings/pg` on filter change
- Live tab fans out to `/v1/findings` ring per pod; Adversarial Testing tab shows evadex bridge metrics

## Open PRs

| PR | Branch | Summary |
|---|---|---|
| #297 | dependabot/cargo/calamine-0.35.0 | deps: bump calamine 0.34→0.35 |
| #311 | fix/morse-trim-trailing-whitespace | fix(core): trim trailing whitespace in morse no-sep decoder (in progress) |

### Recently merged (2026-06-21)

| PR | Branch | Summary |
|---|---|---|
| #312 | feat/findings-persistence | feat(api): findings persistence to postgres |
| #313 | feat/findings-history-tab | feat(wireframes): Findings History tab — postgres-backed |
| #314 | feat/batch-file-scan-persistence | feat(api,fs): findings persistence for batch and file scans |
| #315 | feat/findings-retention | feat(api): findings retention policy |
| #318 | feat/siphon-serve | feat(cli): siphon serve subcommand |
| #320 | feat/lsh-persistence | feat(api): LSH document similarity persistence to postgres |
| #321 | feat/evadex-persistence | feat(api): evadex adversarial-run persistence to postgres |

### siphon-fs routes

Same auth and health/ready as siphon-api. One additional endpoint:

```
POST /scan    multipart/form-data file upload → extraction → findings
GET  /v1/findings
```

Max body: `SIPHON_FS_BODY_LIMIT_MB` (default 100 MB). File formats supported
(parenthetical = feature gate controlling the dep):

- Plain text, RTF, EML — always available
- PDF (`pdf`) — pdf-extract
- DOCX/XLSX/PPTX/ODS/ODT (`office`) — calamine + quick-xml
- ZIP/RAR/7Z (`archives`) — 10k file limit, 500 MB total, 100:1 compression
  ratio bomb detection, path traversal sanitized
- Parquet/SQLite (`data-formats`) — arrow + rusqlite
- PNG/JPG/GIF/BMP/TIFF/WebP barcode & QR (`barcode`) — rxing + image
- Outlook MSG (`msg`) — cfb OLE2
- VCF, LDIF, ICS, MHTML, WARC, CAB, MBOX — no extra feature gate

### CLI subcommands (root `siphon` crate)

```
scan <file>             single file
scan-dir <dir>          recursive directory scan
scan-text [text]        inline or stdin
guard <text>            InputGuard API (--action flag/reject/redact/tokenize/obfuscate)
serve                   start the siphon-api HTTP server (delegates to siphon-api binary)
categories              list all pattern categories
presets                 list available presets (PciDss, Pii, Credentials, Healthcare, ContactInfo)
init                    interactive setup wizard (.siphonrc)
config show|set|reset…  configuration management
test-pattern <regex>    test a regex against stdin text
info                    version, pattern count, features
edm register|scan|…     Exact Data Match vault operations
lsh register|query|…    Document Similarity vault
tui                     interactive TUI (feature: tui)
top                     live statistics dashboard (feature: tui)
forensics <files…>      metadata extraction + author attribution (feature: forensics)
```

Global flags: `--format {text,json,csv,sarif}`, `--min-confidence`,
`--require-context`, `--categories`.

### Feature flags

| Feature | Default | What it adds |
|---|---|---|
| `metrics` | ✓ | Prometheus metrics |
| `barcode` | ✓ | QR/barcode decoding |
| `pdf` | ✓ | PDF extraction |
| `office` | ✓ | DOCX/XLSX/ODS/ODT/PPTX |
| `archives` | ✓ | ZIP/RAR/7Z |
| `msg` | ✓ | Outlook MSG |
| `bin-data` | ✓ | 374k BIN prefix lookup |
| `data-formats` | ✓ | Parquet/SQLite |
| `forensics` | ✓ | Office/PDF metadata extraction |
| `siem` | — | Splunk HEC, Elasticsearch, Syslog, Datadog forwarders |
| `webhooks` | — | Findings webhook notifier |
| `tui` | — | ratatui interactive TUI |
| `async-support` | — | tokio + reqwest runtime |
| `tls` | — | rustls HTTPS (implies async-support) |
| `yaml-config` | — | YAML config loading |
| `python` | — | pyo3 Python bindings |
| `redis-rate-limit` | — | Redis distributed rate limiting |
| `k8s-roll` | — | kube-rs Deployment auto-rollout |
| `full` | — | All optional features |

**Per-crate feature isolation (workspace resolver = 2):** The workspace uses
resolver v2 so features don't leak between members. Specifically, `siphon-api`
depends on siphon with `default-features = false, features = ["metrics"]` to
drop all file-extraction deps (PDF, Office, archives, rusqlite) — those live in
`siphon-fs`. Without resolver v2, rusqlite's libsqlite3-sys would conflict with
sqlx's copy. Don't change this dep declaration without understanding the linkage.

### Ruleset YAML format

Rulesets in `rulesets/` are YAML files loaded by `siphon-api` from
`SIPHON_POLICIES_DIR`:

```yaml
name: PCI Production
version: "1"
baselines:           # pattern subsets: pii, pci, phi, internal_financial,
  - pci              #   source_code_secrets, confidential_documents
action: reject       # reject | flag | redact
mode: denylist       # denylist | allowlist
min_confidence: 0.6
require_context: false
redaction_char: "X"
overrides:
  - category: Card Expiration Dates
    min_confidence: 0.8
    require_context: true
allowlist:           # exact values to always allow through
  - "4111-1111-1111-1111"
```

## Versioning

**Per-crate SemVer `MAJOR.MINOR.PATCH`.** Each crate carries its own version
and revs independently. A bug fixed only in `siphon-fs` produces a new
`siphon-fs` patch release without touching `siphon-api`.

### What versions exist

| Component | Version source | Used by |
|---|---|---|
| `siphon` (root CLI) | `Cargo.toml` `[package].version` | end users running the CLI |
| `siphon-core` | `crates/siphon-core/Cargo.toml` | every other crate (path dep) |
| `siphon-api` | `crates/siphon-api/Cargo.toml` | `deploy/Dockerfile.api`, `siphon-api` Docker tag |
| `siphon-fs` | `crates/siphon-fs/Cargo.toml` | `deploy/Dockerfile.fs`, `siphon-fs` Docker tag |
| `siphon-launcher` | `crates/siphon-launcher/Cargo.toml` | local-dev tool only |
| Helm chart structure | `deploy/helm/siphon/Chart.yaml` `version:` | upgrade-path semantics for the chart itself (PVC migrations, RBAC reshuffles) |
| Stack release label | `deploy/helm/siphon/Chart.yaml` `appVersion:` | a meta-label for the bundled release; equals the highest component version moved in this wave |

### What bumps when

A change's Conventional Commit **scope** drives which crate(s) bump:

- `feat(api): ...`     → `siphon-api` MINOR
- `fix(fs): ...`       → `siphon-fs` PATCH
- `feat(core)!: ...`   → `siphon-core` MAJOR (and see "core MAJOR cascades" below)
- `chore(deps): ...`   → no bump unless the dep change is user-visible
- `docs: ...`          → no bump

Scopes (use one per commit; pick the most specific):

| Scope | Bumps |
|---|---|
| `core` | `siphon-core` |
| `api` | `siphon-api` |
| `fs` | `siphon-fs` |
| `launcher` | `siphon-launcher` |
| `cli` | `siphon` (root) |
| `chart` / `helm` | Helm chart `version:` |
| `deploy` | nothing on its own — pair with the affected crate scope |
| `docs` / `chore` / `ci` / `test` | nothing |

### Lockstep updates within one crate

When you bump `crates/<name>/Cargo.toml` `[package].version = "X.Y.Z"`, in the
**same commit** also update:

1. `deploy/Dockerfile.<name>` — add or update `LABEL version="X.Y.Z"`.
2. `deploy/helm/siphon/values.yaml` — the matching `<name>.image.tag: "X.Y.Z"`.
   Never leave a service tag empty in production values; never use `latest`.
3. `deploy/docker-compose.yml` — the matching `image: <name>:X.Y.Z` line.
4. `CHANGELOG.md` — add a `## <name> X.Y.Z — YYYY-MM-DD` heading.

When you bump the Helm chart's own `version:`, also update its `appVersion:`
to match the highest crate version moved in this release wave.

### Core MAJOR cascades

`siphon-core` is a `path =` dep of every other crate. A `siphon-core` MAJOR
bump means downstream crates had to be edited to keep compiling — each gets at
least a MINOR bump in the same wave. A PATCH or MINOR doesn't force a
downstream bump unless the downstream actually changed.

### Inter-crate dep pinning

Today the workspace uses `path =` only (no `version =`) for inter-crate deps.
Add a `version =` constraint alongside the `path =` **only** when publishing a
crate to a registry.

### Image-tag policy

| File | Rule |
|---|---|
| `deploy/helm/siphon/values.yaml` | every `*.image.tag:` is a fully pinned `X.Y.Z` string. Never empty, never `latest`, never floating `X.Y`. |
| `deploy/Dockerfile.*` | base images pinned by major+minor |
| `deploy/docker-compose.yml` | `:latest` acceptable for local dev profiles; release-shipped compose pins to `X.Y.Z` |

## Releases

### Git tags

One tag per crate per release, namespaced:

- `siphon-core-vX.Y.Z`
- `siphon-api-vX.Y.Z`
- `siphon-fs-vX.Y.Z`
- `siphon-launcher-vX.Y.Z`
- `siphon-cli-vX.Y.Z`
- `siphon-chart-vX.Y.Z`

A "release wave" is a single commit on `main` that bumps one or more crates
and gets one tag per bumped crate (annotated, signed where possible). Tags
are immutable — never re-point.

### Pre-release flow

1. Branch off `main` (`feat/<scope>-<short-summary>`).
2. Make changes; commits use Conventional Commits with scope.
3. In a final commit, bump the crate version per "Lockstep updates" above and
   add a CHANGELOG entry.
4. Open PR; CI runs.
5. After merge to `main`, push the per-crate tag(s) on the merge commit.

### Tooling

- `scripts/bump-version.sh <target> <bump>` — touches every file the lockstep
  table lists; `--dry-run` and `--no-changelog` available.
- `scripts/changelog.sh <target>` — generates per-crate release notes from
  `git log`; `--write` replaces the TODO stub in CHANGELOG.md.
- `scripts/check-semver.sh` — runs `cargo-semver-checks` on modified library
  crates; wired as a pre-commit hook by `scripts/install-hooks.sh`.

## Commits

Use Conventional Commits with a scope:

    <type>(<scope>): <short summary>

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `breaking`
(or `feat!`/`fix!`). One scope per commit; subject under ~70 characters.

## Branches

Feature work goes on a branch; main is protected. Never force-push to `main`.

## CI expectations

Before pushing, your change should pass locally:

```
cargo fmt --check
cargo clippy --lib -- -D warnings -A dead-code -A unused-imports
cargo test --lib
cargo test --test integration_test
cargo test --test evasion_test
```

CI mirrors these in `.github/workflows/ci.yml`.

## Security

- Dependabot watches `cargo`, `github-actions`, and `docker` ecosystems weekly.
- DevSkim SAST runs on push/PR (`.github/workflows/devskim.yml`).
- `deny.toml` gates advisories; add exceptions sparingly with a rationale.
- API-key auth is SHA-256 hashed at rest. TLS (rustls) optional.
- Audit chain uses HMAC-SHA256 when `SIPHON_AUDIT_SIGNING_KEY_HEX` is set.
- `siphon-launcher` hard-exits if `SIPHON_LAUNCHER_BIND` is set to a
  non-loopback address — it has no authentication and is local-only by design.

## Where things live

- Scanner patterns: `crates/siphon-core/src/` + `rulesets/*.yaml`
- HTTP handlers: `src/api.rs` (CLI-embedded server) and `crates/siphon-api/src/`
- File extractors: `src/extractors.rs` and `crates/siphon-fs/src/`
- RBAC: `src/rbac.rs`
- Policy engine: `src/policy.rs`
- SIEM / webhooks: gated by the `siem` / `webhooks` features in the root crate
- Integration tests: `tests/`
- Architecture / patterns docs: `docs/`
- Per-crate version source of truth: `Cargo.toml` (root) and `crates/*/Cargo.toml`
