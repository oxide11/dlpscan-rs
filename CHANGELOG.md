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

## 2026-09-02

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
  archive is on disk. Regression tests added in `tests/archive_security_test.rs`.
- chore(deps): bump `anyhow` 1.0.102 → 1.0.104 (RUSTSEC-2026-0190,
  memory-corruption in `Error::downcast_mut`).
- chore(deps): bump `h2` 0.4.15 → 0.4.19 (RUSTSEC-2026-0258, DoS via
  unbounded empty DATA frames).
- chore(deps): bump `lru` 0.18.0 → 0.18.3 (RUSTSEC-2026-0253, potential
  use-after-free in `LruCache::pop`).
- chore(deps): bump `chacha20` 0.10.0 → 0.10.2 (yanked version).

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
