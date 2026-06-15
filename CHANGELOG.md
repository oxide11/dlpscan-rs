# Changelog

All notable, user-visible changes to the Siphon stack are recorded here. Each
release block is dated and contains per-crate sub-sections — bumps are
independent, so a release block typically moves only the crates that actually
changed in a given wave.

Format follows [Keep a Changelog](https://keepachangelog.com/), adapted for
the per-crate SemVer model documented in `CLAUDE.md`. Older
workspace-single-version history (every crate moving in lockstep) lives in
`docs/CHANGELOG.md` and ends at the workspace `2.1.0` release on
2026-04-07. After that point, each crate publishes its own version stream,
starting from this file.

---

## 2026-06-14

### siphon-core 2.1.3

- feat(core): CUSIP context keywords expanded — 14 additional keywords added
  (`instrument`, `ticker`, `position`, `identifier`, `portfolio`, `holding`,
  `asset`, `issuance`, `prospectus`, `indenture`, `maturity`, `coupon`,
  `face value`, `par value`); context distance widened from 50 to 75 chars,
  improving detection of CUSIP numbers in financial documents where the
  instrument label appears further from the identifier than the previous window
  allowed.
- feat(core): encoding chain alternatives added — `generate_alternative_decodings()`
  now produces `base64→ROT13`, `ROT13→base64`, and `hex→base64` two-stage
  chains alongside the existing single-pass decoders, catching doubly-encoded
  values that evadex encodes across two distinct transforms.

### siphon-api 2.3.0

- feat(api): findings persistence to Postgres — scans + findings tables via
  migrations `0001_init.sql`–`0004_retention.sql`; `persist_scan()` called
  after every text scan in a background `tokio::spawn` (never blocks the HTTP
  response). New query endpoints: `GET /v1/findings/pg` (paginated DB query,
  filterable by category), `GET /v1/findings/stats` (category breakdown + daily
  counts, cached 60 s), `POST /v1/findings/prune` (manual retention trigger,
  admin-only).
- feat(api): batch and file scan persistence — `POST /scan/batch` and
  `siphon-fs POST /scan` now persist via the same `persist_scan()` path; one
  row per item for batch, one row per file for file scans.
- feat(api): findings retention policy — `SIPHON_FINDINGS_RETENTION_DAYS` env
  var (default 90, 0 = keep forever); `prune_old_findings()` runs at startup
  and in a nightly background task.
- feat(api): findings export — `GET /v1/findings/export` returns CSV or JSON,
  up to 100 k rows, filterable by category and ISO8601 date range; rate-limited
  at 5 req/min per IP (prevents accidental full-table dumps from C2 polling).
- feat(api): per-endpoint rate limits — `/v1/findings/export` 5/min,
  `/v1/findings/pg` 30/min, `/v1/findings/stats` 60/min per IP, tighter than
  the global `SIPHON_RATE_LIMIT`.
- feat(api): EDM persistence — migration `0005_edm.sql`; every Exact Data Match
  finding triggers a `persist_edm_query()` call; EDM registration events
  persisted on vault write.
- feat(api): LSH document similarity persistence — migration `0006_lsh.sql`;
  `persist_lsh_query()` called after every scan that runs an LSH check; new
  `GET /v1/lsh/history` endpoint (paginated, filterable by `matched_only`);
  `GET /v1/findings/stats` extended with an `lsh` section (total
  registrations, total queries, match rate, last registration timestamp).
- feat(api): evadex adversarial-run ingest — migration `0007_evadex.sql`;
  `POST /v1/evadex/runs` accepts completed evadex scan payloads from the
  bridge, storing per-run stats and up to 2 000 individual findings; idempotent
  on `run_id` (`ON CONFLICT DO NOTHING`). `GET /v1/evadex/runs` returns
  paginated run history (limit ≤ 500). `GET /v1/evadex/runs/stats` returns
  aggregated detection-rate summary and top-10 bypassed techniques from
  `evadex_findings`.

### siphon-cli 2.2.0

- feat(cli): `siphon serve` subcommand — delegates to the `siphon-api` binary
  found on `PATH` (or via `--exe`), enabling a persistent HTTP API without
  needing the full k8s stack. Exits 1 with a clear error when `siphon-api` is
  not installed. Forwards all remaining flags (`--port`, `--bind`, env-var
  pass-through) to the child process.

---

## 2026-05-26

### siphon-core 2.1.2

- fix(core): delimiter-injection evasion bypass reduced — new normalization
  stage 6b (`strip_alnum_adjacent_delimiters`) strips `-`, `.`, `/`, `\`, and
  `_` between alphanumeric characters when at least one neighbour is a digit or
  uppercase letter, defeating evadex `hyphen_delimiter`, `dot_delimiter`,
  `slash_delimiter`, `mixed_delimiter`, and `excessive_delimiter` techniques.
  Natural-language compound words (`test-case`) are preserved because both
  neighbours are lowercase letters.
- fix(core): USA SSN pattern makes separator optional (`?`) — after stage 6b
  strips hyphens from `078-05-1120`, the SSN regex needs optional separators to
  still match. `context_required: true` and `is_valid_ssn` keep false-positive
  risk low.
- fix(core): `has_evasion_markers()` extended — detects single-char delimiter
  between alphanumeric neighbours (at least one digit or uppercase) so the
  normalizer fast path is bypassed for identifier-delimiter evasion inputs.

---

## 2026-05-13

### siphon-core 2.1.1

- fix(core): SEDOL detection restored from 0% to ~80% — pattern was listed in
  both `PatternDef.context_required` and `models::is_context_required()`;
  removed the dual block so SEDOL runs without mandatory context keywords.
- fix(core): Malta TIN false-positive rate reduced — tightened regex from
  `\d{3,9}[A-Z]?` to the exact 8-char format `\d{7}[A-Z]` and moved behind
  context requirement.
- fix(core): Tanzania NIDA false-positive rate reduced — 20-digit sequences now
  require a nearby NIDA context keyword instead of firing unconditionally.
- fix(core): leet-moderate evasion detection improved — added `normalize_leet_to_digits()`
  (inverse of existing `normalize_leet()`) so letter-substituted digits
  (`l`→`1`, `o`→`0`, `s`→`5`, etc.) are recovered as an alternative decoding
  pass.
- fix(core): morse-in-mixed-text evasion improved — new `decode_morse_in_text()`
  extracts the longest contiguous morse run from surrounding prose; `morse_slash_sep`
  technique detection improved from ~5% to ~50%.
- fix(core): ROT13+base64 encoding-chain evasion improved — `generate_alternative_decodings()`
  now chains ROT13 followed by the full normalization pipeline as an extra
  alternative, catching nested ROT13(base64(data)) payloads.
- fix(core): CUSIP context detection strengthened — added 8 additional keywords
  (`settlement`, `clearinghouse`, `dtcc`, `depository trust`, `fixed income`,
  `bond`, `equity`, `securities`).
- fix(core): regional digit normalization added — Arabic-Indic, Extended
  Arabic-Indic, Devanagari, Bengali, and Thai digit codepoints now map to ASCII
  equivalents via `HOMOGLYPH_MAP`, enabling detection of numeric PII encoded in
  non-Latin digit scripts.

---

## 2026-04-26

### ui (siphon-ui)

- refactor(ui): extract two duplicated patterns into shared modules.
  Three pages (`app/page.tsx`, `app/pods/page.tsx`,
  `app/findings/page.tsx`) carried near-identical inline copies of
  the destructive-tinted error card and the date / age formatters.
  New `components/ui/error-alert.tsx` (with a `<ErrorAlert title
  message hint? />` shape) and `lib/formatters.ts` (with
  `formatTimestampUtc` + `formatRelativeAge`) replace those copies.
  No version bump — `ui/package.json` follows the root Cargo.toml
  per the version-sync gate.

### chart 2.1.0

- feat(chart): Authelia password-reset flow is now production-shaped. The
  chart already had `password_reset.disable: false` set, but only rendered
  the filesystem notifier — Authelia would write reset "emails" to
  `/config/notification.txt` regardless of environment. New
  `authelia.notifier.smtp.{enabled,host,port,username,sender,identifier,subject,startupCheckAddress,disableHtmlEmails,tls.{skipVerify,serverName,minimumVersion}}`
  values keys flip the rendered notifier between filesystem (default,
  for dev) and SMTP (for prod). When `smtp.enabled=true`, the
  Authelia Deployment auto-mounts `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE`
  from the existing `authelia.secretName` Secret under the key
  `smtp_password` — same model as the other AUTHELIA_*_FILE secrets.
- chore(scripts): new `scripts/reset-authelia-password.sh` break-glass
  helper. Re-hashes a user's password via the official Authelia
  container (parameter-identical to a self-service reset hash) and
  patches `users_database.yml` in place, with a timestamped backup
  alongside. For when SMTP is broken and you can't wait.
- docs(authentication): self-service and break-glass reset flows
  documented in `docs/AUTHENTICATION.md`; production checklist now
  references the new `authelia.notifier.smtp.*` keys instead of a
  generic "switch notifier to SMTP" line item.

### siphon-api 2.2.0

- feat(api): RBAC enforcement is now wired end-to-end — `auth_middleware`
  resolves the bearer key into an `AuthContext { role }` stamped onto each
  request; per-route extractors (today: `RequireAdminAction`) gate handlers
  on `siphon::rbac::role_has_permission`, returning 403 with an audit-log
  `REJECT` row before any handler logic runs. The `POST /v1/overrides/roll`
  and `POST /v1/k8s/deployments/{name}/rollout` endpoints — which mutate
  cluster state via `kube` — are gated on `Permission::AdminAction`. Open
  dev mode (no `SIPHON_API_KEY` configured) maps to `Role::Operator`, so
  AdminAction-gated routes refuse to fire without explicit auth even when
  bearer auth is off. Multi-key role-mapping (a `HashMap<key, Role>`)
  remains as follow-up plumbing — the schema's already in
  `rbac::resolve_role`.

---

## 2026-04-25

### siphon-fs 1.0.0

First independent release of `siphon-fs` on its own version line. Prior to
this, the crate moved in lockstep with the rest of the workspace (last shared
release: `2.1.0`, 2026-04-07). Going forward, `siphon-fs` revs independently
under its own SemVer contract — bug fixes that only touch the file scanner
ship as `siphon-fs` patch releases without dragging `siphon-api` or
`siphon-core` along.

The `1.0.0` discontinuity is deliberate: it marks the first release where
the surface below is contractual and SemVer-stable, not the natural
continuation of the workspace's `2.1.x` line. Subsequent `siphon-fs` releases
will only break the listed contract on a `2.0.0` MAJOR bump.

#### Stable contract

**HTTP routes.** Backwards-compatible additions are MINOR bumps; removing or
changing the request/response shape of any of these is a MAJOR bump:

- `GET  /health` — liveness probe; unauthenticated; returns `200 ok` plus
  pod-id / version metadata.
- `GET  /ready` — readiness probe; unauthenticated; returns `200 ok` once
  the overrides ConfigMap has parsed cleanly.
- `POST /scan` — multipart file upload; one `file` part; response is the
  same `findings[]` shape `siphon-api`'s `/scan` returns. `Content-Type`
  is `multipart/form-data` (and only `multipart/form-data` — JSON is not
  accepted on this endpoint).
- `GET  /v1/findings` — in-memory ring buffer of recent findings, sorted
  newest-first, capacity bounded by `SIPHON_FINDINGS_RING_CAP`.
- `GET  /v1/capabilities` — service self-description (supported file
  formats, max body limit, feature flags).
- `POST /v1/overrides/reload` — re-reads pattern overrides from
  `SIPHON_OVERRIDES_PATH` without restarting the pod.

**Environment variables.** Renaming or removing any of these is a MAJOR bump;
adding new ones is MINOR:

- `SIPHON_FS_BIND` — listen address. Defaults to `0.0.0.0:8081`.
- `SIPHON_FS_BODY_LIMIT_MB` — maximum multipart body size in MB. Default 100.
- `SIPHON_OVERRIDES_PATH` — path to the pattern-overrides JSON. Defaults to
  `/etc/siphon/overrides.json`.
- `SIPHON_FINDINGS_RING_CAP` — in-memory ring buffer capacity. Default 1000.
- `RUST_LOG` — standard `tracing-subscriber` filter expression.

**File-format support.** PDFs, Office (`.docx` / `.xlsx` / `.pptx`),
archives (`zip`, `7z`, `rar`), spreadsheets (`csv`, `parquet`, `arrow`), and
images (with the optional `ocr` feature). Adding a new format is a MINOR
bump; removing one is MAJOR.

**Container image.** `oxide11/siphon-fs:1.0.0` is the pinned tag in the
chart's `values.yaml` and the dev `docker-compose.yml`. The `LABEL
org.opencontainers.image.version` matches the crate version. Image base
(`debian:bookworm-slim`) is treated as a transient build detail — base swaps
that don't break the binary contract are PATCH bumps.

#### Known experimental (NOT covered by SemVer)

- The `ocr` feature flag — Tesseract-backed OCR over scanned-document
  attachments. Behavior, dependency footprint, and binary output may change
  between MINOR releases until the feature stabilises.
- The OCI base image's tag pinning. We pin by major+minor today
  (`debian:bookworm-slim` resolves to whatever the upstream tag points at);
  digest pinning is on the roadmap but not part of the `1.0.0` contract.

#### Migration from workspace `2.1.0`

There is no API change between workspace `2.1.0` and `siphon-fs 1.0.0`. The
running binary, env vars, and HTTP routes are byte-for-byte the same. The
only operator-visible change is the image tag — pull `siphon-fs:1.0.0`
instead of `siphon-fs:2.1.0`. Helm-chart users pick this up automatically
when they upgrade to the chart release that pins
`fs.image.tag: "1.0.0"` in `values.yaml`.

The crate's SemVer line will continue from here as `1.0.x`, `1.1.x`, etc.,
independent of `siphon-api` (still on the `2.1.x` line) and `siphon-core`
(also `2.1.x`).

---

For workspace-single-version history before this point (releases
`0.1.0` through `2.1.0`, all crates moving together), see
[`docs/CHANGELOG.md`](docs/CHANGELOG.md).
