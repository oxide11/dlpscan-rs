# Siphon Backlog

Last updated: 2026-09-30

## Security audit log

### 2026-09-30 — archive extraction, and who gets told what went unread

Round 9. Audited the file-extraction surface (`src/extractors.rs`, 4.1k lines,
reachable from the `siphon-fs` upload edge) plus a sweep over auth, SQL,
outbound HTTP and the audit record. Four findings, all in extraction, all
fixed in siphon 2.5.1 — see the CHANGELOG entry.

The shape of all four is the recurring one in this codebase: **content that was
seen and not read must never be reported as clean.** Three of them were the
size/ratio guards trusting `file.size()`, a number the archive asserts about
itself, and then reading without a bound; the fourth was `PipelineResult`
having no field for the warnings `extract_text` was already producing, so the
CLI path discarded them.

Worth recording that the project already had the right fix written down twice:
`extract_7z` carries the comment *"`entry.size()` is attacker-supplied header
metadata, so a lying header must not become an unbounded read"*, and the
generic-ZIP pass reads through `take` for the same stated reason. The
Office-XML and OpenDocument passes were simply never brought in line. Checking
whether a known fix has been applied **everywhere** it applies turned out to be
worth more than looking for novel bug classes.

Checked and clean, recorded so the next round starts from here:

- **SQL.** Every statement in `crates/siphon-api/src/db.rs` is a static string
  with `$1`-style bound parameters. No interpolated identifiers, no
  interpolated `ORDER BY`.
- **Key comparison.** No constant-time compare anywhere, and none needed:
  `siphon_auth::keys::resolve` hashes the presented token and looks the hash up
  in a map, so no secret is ever compared byte by byte. The comment claiming
  "constant work regardless of outcome: one hash, one lookup" is accurate.
- **Redaction.** The webhook payload carries `redacted_match: m.redacted_text()`,
  not the matched value, and `crates/siphon-core/src/audit.rs` stores no raw
  matched text at all. Nothing in the finding path writes a sensitive value to
  disk or to an outbound request.
- **Outbound HTTP.** `webhooks.rs` and `siem.rs` both go through
  `http_util::safe_http_post`, which owns DNS resolution, SSRF validation and
  CRLF sanitisation. Not re-audited here beyond confirming there is no second
  path around it.
- **Panics on the request path.** The only `unwrap`/`expect` in
  `crates/siphon-api/src/main.rs` outside tests are lock-poison expects (which
  require an earlier panic) and two signal-handler installs at startup. No
  input-driven unwrap, slice index or integer cast in a handler.
- **Archive path traversal.** `sanitize_archive_path` keeps only
  `Component::Normal`, which drops `..`, roots and Windows prefixes, and then
  re-checks `starts_with(base)`. Correct, and already covered by tests.

Still not reviewed, carried forward from round 8 and still open: **the ICAP
`Encapsulated` offset handling.** It was audited this round and does have a
finding, but the fix belongs on top of PR #480 rather than on `main` — the
round-8 parser work in `crates/siphon-icap/src/main.rs` is still unmerged, so
`main`'s copy of that file is 164 lines behind the code the finding was found
in. Tracked separately; `src/extractors.rs` is byte-identical on both branches,
which is why this round's fixes could go to `main` on their own.


### 2026-09-30 — rustls advisory + first pass over the four new crates

`rustls` 0.23.44 → 0.23.45 for **RUSTSEC-2026-0285** (TLS 1.3 handshake
messages accepted across an encryption-level boundary, RFC 8446 §5.1).
Patched rather than accepted, so it needs no `deny.toml` entry.

`siphon-icap`, `siphon-smtp`, `siphon-mail` and `siphon-auth` had not been
reviewed since they were split out. First dedicated pass — **no findings**.
Recorded so the next audit starts from what was already checked rather than
re-deriving it:

- **Secrets.** No hardcoded keys, PEM material or credential-bearing
  connection strings in any of the four. The only secret reads are
  `SIPHON_DATABASE_URL` / `SIPHON_DATABASE_PASSWORD` from the environment in
  `siphon-smtp`.
- **Answering "clean" for unread content** — the 2026-09-09 class. Covered in
  all three mail/proxy surfaces. `siphon-icap` routes oversize and binary
  bodies through `unscannable_verdict` under `SIPHON_ICAP_ON_UNSCANNABLE`,
  checking truncation *before* binary-sniffing (a sniff on a truncated prefix
  answers a question about the prefix, not the transfer), and a scan error
  returns 500 rather than a clean 204. `siphon-smtp` has the equivalent
  control in `SIPHON_SMTP_ON_INDETERMINATE`, and `policy::action_for` applies
  it to any `Accept` verdict whose inspection was incomplete — so one
  detectable value in one part cannot deliver a message whose other part
  nobody could open. The linchpin is `siphon_mail::inspection()`:
  `PartStatus::is_inspected` is a strict allowlist of `Scanned`, and no parts
  at all is `Incomplete`, not a clean bill of health. `siphon-smtp` only ever
  moves that value toward `Incomplete` (on a structural parse warning), never
  back.
- **Tenant scope from the key, not the header.** `siphon-auth` reads no
  headers at all; `tenant_id` comes from the `api_keys` row matched on the
  presented secret's hash. Centralising auth did not reintroduce the
  header-trust bug fixed in siphon-api and siphon-fs on 2026-09-09 — both
  `tenant_scope()` resolvers still confine a bound key and let a header only
  agree, never contradict.

Three things this pass turned up that are not security findings but are worth
keeping, none of them caused by the rustls bump — all three reproduce on an
unmodified `main`:

- **`siphon-auth` had no CI at all.** No workflow named the crate, so
  `tests/mtls.rs` — the only suite anywhere that drives a real rustls
  handshake — had never run in CI. Added as a step in this PR. Note that its
  first CI run is also its first-ever run.
- **`siphon-fs` `size_limit_tests` race (flaky).** `with_env` in
  `crates/siphon-fs/src/main.rs` saves, sets and restores process-global env
  vars with no lock, and the test harness runs tests in parallel threads in
  one process. Several tests in that module drive the same two variables
  (`SIPHON_FS_BODY_LIMIT_MB`, `SIPHON_FS_MAX_FILE_SIZE_MB`), so they clobber
  each other: `per_file_default_follows_a_raised_body_limit` reads 100 MB —
  exactly the neighbouring test's value — where it set 250 MB. A `static
  Mutex` around `with_env` fixes it. Not currently visible because CI runs
  `-p siphon-fs --test auth_test` and never the bin's unit tests.
- **Two suites are sensitive to a CRLF checkout.** On Windows,
  `scripts/dev/mkcerts.sh` fails (`set -Eeuo pipefail\r`, and openssl's
  `-subj /O=Siphon/...` is mangled by MSYS path conversion), taking all six
  mtls tests with it; and `guard::obfuscate`'s source-scanning test
  (`every_dispatch_arm_names_something_the_scanner_emits`) mis-parses
  `obfuscate.rs` because it splits on `"\n}\n"`. Both files are `i/lf` in the
  index, so Linux CI is unaffected — this only bites contributors on a
  `core.autocrlf=true` checkout.

Not re-reviewed here: siphon-icap's ICAP framing and siphon-smtp's milter
protocol parsing, which deserve their own pass.

## Security debt — unmaintained dependencies

Five transitive dependencies are flagged unmaintained by RustSec. None has a
known exploit as of this writing; they are tracked here so they are not
silently forgotten between dependency audits. Replace opportunistically when a
maintained alternative exists and the migration risk is low.

| Crate | RustSec ID | Notes |
|---|---|---|
| `ring` | RUSTSEC-2026-0243 | Cryptography primitive used by rustls. The maintainership situation is well-known in the ecosystem; `aws-lc-rs` is the leading maintained alternative but requires a C toolchain. Revisit when rustls makes the switch by default. |
| `rustls-pemfile` | RUSTSEC-2026-0244 | PEM parsing used by the TLS feature. Consider migrating to `rustls-pki-types` (the newer rustls-endorsed crate) when the TLS plumbing is next touched. |
| `ttf-parser` | RUSTSEC-2026-0249 | Font parsing pulled in by the PDF extraction chain. No maintained drop-in; revisit when the PDF dep tree updates. |
| `paste` | RUSTSEC-2026-0251 | Proc-macro helper; used only at compile time, no runtime attack surface. Prefer inlining or switching to std `concat_idents!` / `format_ident!` (from `syn`) when the using code is next touched. |
| `proc-macro-error2` | RUSTSEC-2026-0252 | Build-time only (proc-macro support). No exploitable runtime surface; track the originating crate's migration to `proc-macro-error` v2 or `syn` diagnostics. |

## Security debt — operational correctness

### EDM salt stability (`SIPHON_EDM_SALT_HEX`)

`ExactDataMatcher` generates a fresh 32-byte CSPRNG salt per process start when no
salt is configured. This means EDM vault hashes are invalidated on every restart —
registered values will never match until the vault is re-registered. The CLI `save`/
`load` path already serializes the salt correctly; the API path does not.

**Fix:** Add `SIPHON_EDM_SALT_HEX` env var; load it in `siphon-api/src/main.rs` and
pass it to `ExactDataMatcher::new(Some(salt), ...)`. Warn at startup if EDM vaults
are registered without a stable salt. Align with the CLI's existing
`--edm-salt-path` mechanism.

**Files:** `crates/siphon-api/src/main.rs` (AppState init), `crates/siphon-core/src/edm.rs`

### JSON deserialization depth limit

`serde_json` uses recursive descent with no configurable stack-depth cap. A
request body with deeply nested JSON (e.g. `{"a":{"a":{"a":...}}}` 15k+ levels)
can overflow the thread stack before the body-size limit rejects it, since nesting
depth is not proportional to byte count.

**Affected endpoints:** all `Json<T>` extractor sites in siphon-api (POST /scan,
POST /scan/batch, POST /v1/overrides/apply, POST /v1/evadex/runs, …).

**Fix options (prefer either):**
1. Add a Tower middleware layer that reads the raw body, checks nesting depth
   (character-count heuristic on `{`/`[` depth), and returns 400 before handing
   to serde_json.
2. Switch the affected handlers to `Bytes` extraction, pre-scan depth with a
   fast counter loop, then deserialize — avoids any additional dep.

**Severity:** DoS-only (no data exposure); the body-size limit provides partial
mitigation by capping bytes, but a ~1 MB body can hold ~100k depth levels.

**Files:** `crates/siphon-api/src/main.rs` (all JSON handler sites)

---

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
- [x] Findings deduplication — skip duplicate persist_scan() for same input_hash within 60s (siphon-api 2.4.0)

### Medium priority
- [x] LSH persistence — store document similarity results in postgres (PR #320)
- [x] evadex results → postgres — store evadex scan results in findings table for C2 trending (PR #321)
- [x] POST /v1/findings/prune ?days=N — done; documented in docs/enterprise/api.md

### Detection improvements (from evadex data)
- [x] Morse code file-scan bypass — fixed: embedded morse segments now found in filename-prefixed text (PR #336)
- [x] JCB detection — fixed: hex-decoder no longer corrupts all-digit JCB numbers (PR #336)
- [x] Morse code em-dash/en-dash variants — fixed: U+2013/2014/2212/2015 mapped to '-' in HOMOGLYPH_MAP (PR #349)
- [x] Morse code IBAN bypass — fixed: all 4 evadex variants (space/nosep/newline/slash sep) now detected; slash decoder extended to accept multi-char alpha tokens merged by stage 6b (PR #349)
- [x] Morse delimited-preamble bypass — fixed: comma/slash/pipe digit-morse embedded in surrounding text (filename preamble on the file-scan path, or a prose prefix like `card `) now decoded via `find_embedded_digit_morse_delimited`, the delimited analogue of the nosep embedded scan (PR #336). Preamble/prefix spot checks 0/6 → 6/6; bare-separator variants stay 5/5 (PR #367; siphon-core 2.1.7)
- [ ] Morse code remaining bypass — remaining failures are context-required IDs (SSN/SIN/AU_TFN/DE_TAX_ID/FR_INSEE) skipped by the morse alt-decode path *by design*: the alt-decoding emits bare digits without the surrounding context keyword, so context-gated patterns don't fire. Luhn/checksum-gated values (cards, IBAN, routing) are now covered across all separators incl. embedded-in-text. Closing the context-required class needs the alt-decoder to carry surrounding context — a larger change weighed against FP risk. Target <30%; re-baseline with evadex before deciding.
- [ ] Remaining credit_card gaps (evadex replay 2026-07-04, post #365-#367; 63/100 previously-bypassing variants now detected) — still bypassing: zero-padding (`right_pad_zeros`/`left_pad_zeros`, ~10), nested/partial base64 chains (`base64_partial`/`base64_no_padding`/`base64_double`/`url_of_base64`/`hex_of_base64`, ~11), `noise_embedded` (4), residual `homoglyph_substitution` (4), `barcode_split` (2), and a couple of `morse_slash_sep`/`morse_no_sep` stragglers. Zero-padding and deep-nested base64 are the highest-value next targets.
- [x] Unicode digit-script + confusable-digit folding — fixed: Stage 10 gained a Unicode `Nd` fallback (`fold_unicode_digit`) folding all decimal-digit scripts (Devanagari/Bengali/Gujarati/Tamil/math-bold/… ~60 scripts) to ASCII; new Stage 11 (`fold_confusable_digit_runs`) folds letter-shaped digit confusables (O→0, l/I→1, Greek/Cyrillic O→0) inside long digit-dense runs. Closes leet_aggressive / greek_omicron / Devanagari-digit gaps; run-gated + Luhn-gated so prose is untouched (PR #366; siphon-core 2.1.6)
- [x] Regional digits — Thai (U+0E50), Extended Arabic-Indic (U+06F0), Arabic-Indic (U+0660) now detected via HOMOGLYPH_MAP; Thai-digit card regression locked in (PR #359); verified PASS in the evadex suite

### Infrastructure
- [ ] Helm chart: postgres subchart or external postgres configuration
- [x] siphon-fs postgres pool — fixed missing SIPHON_DATABASE_URL in 30-siphon-fs.yaml; file-scan findings now reach postgres; verified end-to-end (fix/stability)
- [x] lab-up.sh — add postgres to local kind setup

## In progress (open PRs)
- [x] #365 — fix(core): evadex-mutate gaps — base64 mixed-case + delimiter/noise uniformity; siphon-core 2.1.5 — **merged to main** (squash 0778cd4, 2026-07-04)
- [x] #366 — fix(core): unicode digit-script folding + confusable-digit normalization; siphon-core 2.1.6 — **merged to main** (squash 362f792, 2026-07-04)
- [x] #367 — fix(core): preamble-tolerant delimited digit-morse decoding; siphon-core 2.1.7 — **merged to main** (squash a8ff937, 2026-07-04). Stack merged in order #365 → #366 → #367; each child was rebased onto main after its parent squash-merged (squash collapses history, so a non-force merge-commit resolved the conflict).
- [x] #349 — fix(core): em-dash/en-dash homoglyphs + IBAN mixed-nosep morse decoder — merged; siphon-core 2.1.4
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
- [x] Merged PR stack #365 → #366 → #367 to main (siphon-core 2.1.5 → 2.1.6 → 2.1.7, 2026-07-04). Clean main verified: 394 siphon-core lib tests + 154 root lib + 69 integration + 12 evasion all pass; `cargo deny` clean; release binary builds. Spot check 27/29 (the 2 "fails" are malformed test vectors that don't fold to a Luhn-valid PAN — correctly-built Greek/Cyrillic-O payloads *are* detected, confirming Stage 11 confusable folding). evadex mutate credit_card bypass 84.4% → **74.2%** (159 bred, seed 42, same breeding scan); evadex replay `--failed-only` credit_card: **63/100** previously-bypassing variants now detected (regional-digit + morse-separator + nested-base64 techniques flipped to detected).
- [x] Stage-6b dot-stripping + base64 alt-decode test failures — `should_strip_dot` now leaves letter-bounded dots intact (`D123.4567` stays an identifier) while still stripping pure numeric groupings; base64→ROT13 alt-decode chain only emits when ROT13 actually transforms the bytes, so pure-digit payloads no longer re-introduce plain base64 output stage 4c already covers (main 0cb99c9)
- [x] #349 — em-dash/en-dash homoglyphs + IBAN mixed-nosep/slash morse decoder — merged; siphon-core 2.1.4 (all 4 evadex IBAN morse variants now detected)
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
