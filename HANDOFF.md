# Siphon — Handoff Notes

Last updated: 2026-10-15

Companion doc to `CLAUDE.md` (architecture/conventions), `BACKLOG.md`
(work queue) and `FUTURE.md` (roadmap). This file is the "resume here after
a break" quick-start. The previous version of it was dated 2026-07-04 and
named versions, PRs and a crate list that were three months stale; treat
anything here older than the date above with the same suspicion.

## Current state

- **Versions** (per-crate SemVer — see `CLAUDE.md` "Versioning"), read from
  each `Cargo.toml` on the date above:
  - `siphon` (root CLI, package `siphon-cli`) — **2.5.0**
  - `siphon-core` — **2.10.0**
  - `siphon-api` — **2.12.1**
  - `siphon-fs` — **1.5.0**
  - `siphon-launcher` — **2.1.2**
  - `siphon-icap` — **0.3.0** · `siphon-smtp` — **0.2.1** · `siphon-mail` — **0.1.1** · `siphon-auth` — **0.1.0**
- **CI on `main`: green** (CI, CodeQL, audit, DevSkim, evadex quality gate).
  **`release` has been red since 2026-09-05**: `deploy/Dockerfile.api`'s
  stub-build touch list omitted `siphon-auth`, so cargo linked the stub rlib
  once `keys`/`telemetry` were added. Fix is PR #510. No siphon-api image has
  been published since.
- **Detection baseline** (evadex, northam tier, 21,805 submissions, HTTP
  transport, 2026-10-14): **80.4%**, up 3.9 points from 2.9.5. Weakest:
  morse 65% bypass, capital markets 39%, unicode whitespace 34.6%,
  structural 34.6%. Per-category numbers are noisy; evadex 3.41.0 adds
  `--seed` so a run can be repeated exactly.

## Open PRs (2026-10-15)

| PR | Branch | State | Notes |
|---|---|---|---|
| #510 | `fix/dockerfile-stub-touch-list` | ready | unbreaks `release`; verified when `build siphon-api` goes green on the merge commit |
| #497 | `fix/overrides-content-version-guard` | ready, clean | one version-token guard for both overrides handlers |
| #494 | `fix/security-audit-round9` | ready | archive extraction trusted declared sizes; `main` merged in 2026-10-15, CHANGELOG resolved |
| #496 | `fix/test-integrity` | conflict | hidden env-var race in siphon-fs + three Windows failures; `src/guard/obfuscate.rs` conflict is two copies of the same CRLF fix — take `main`'s |
| #480 | `fix/security-audit-round8` | **do not merge as-is** | 22 commits; its normalizer half (zero-padding, `noise_embedded`, `base64_partial`, б→6) was re-implemented on `main` in the Oct 13–14 wave under different names; its service half (api/fs/icap/smtp fixes, and PRs #490/#492 merged *into* it) needs the author to rebase onto `main` and drop the core commits |
| #495 | `fix/icap-encapsulated-framing` | stacked on #480 | retarget to `main` after #480 is dealt with |
| #498, #500, #481–#485 | dependabot | | `Cargo.lock` must be refreshed and committed with any `Cargo.toml` change or CodeQL (`--locked`) goes red |

## To resume work

```bash
git checkout main && git pull
cargo build --release                          # default features
cargo build --release --features full          # everything

# Local lab (kind cluster + postgres):
./scripts/lab-up.sh --no-build
#   console: http://127.0.0.1:8080/ui/
```

> Lab auth is `devBypass=true` — **no real auth in the lab**, do not expose it.

## Key commands

- **Build:** `cargo build --release` (`--features full` for everything)
- **Lint (CI parity):** `cargo fmt --check && cargo clippy --lib -- -D warnings -A dead-code -A unused-imports`
- **Test:** `cargo test --lib`, then each suite in `tests/` (13; CI runs all)
- **Conformance matrix:** `scripts/conformance.sh` after touching an extractor, the normalizer or a pattern
- **Scan test:** `echo "4532015112830366" | ./target/release/siphon scan-text --format json`
  (JSON output is a **top-level array** of matches)
- **evadex against Siphon** (from `../evadex`, 3.41.0+):
  ```bash
  python -m evadex scan --tool siphon-cli --exe ../dlpscan-rs/target/release/siphon --tier northam --batch --seed 1
  ```
  `--batch` runs one `scan-dir` per batch instead of one process per submission (same verdicts, ~5x faster); `--seed` makes the run repeatable.

## Architecture summary

- `crates/siphon-core` — engine: 586 patterns / 128 categories, 66 checksum
  validators, 15-step normalizer (`docs/architecture/normalization.md`),
  Aho-Corasick context prefilter, raw-text second pass, alternative decodings,
  `recovery.rs` (Oct 2026) for check-digit identifier de-evasion.
- `crates/siphon-api` — HTTP scan API + Postgres (migrations `0001`–`0007`),
  findings/EDM/LSH/evadex endpoints, admin console API. Routes in `CLAUDE.md`.
- `crates/siphon-fs` — multipart file-scan service.
- `crates/siphon-icap`, `siphon-smtp` — proxy and mail ingress.
- `crates/siphon-mail`, `siphon-auth` — shared libraries (mail model;
  TLS/DB identity, API keys, sensor telemetry).
- `src/` (root crate) — CLI, extractors, conformance matrix, and `api.rs`,
  a second HTTP server that `siphon serve` no longer launches (it delegates
  to `siphon-api`); `masking.rs`/`rbac.rs` live here only because siphon-api
  has no lib target.
- `console/` — analyst console (Vite + React). `deploy/` — Dockerfiles,
  compose, Helm, k8s lab.

## Biggest remaining gaps

1. **"Clean verdict for unread content" keeps recurring** (nine audit rounds:
   extractors returning `Ok("")`, ICAP framing with no body, oversize files,
   uninspected mail parts, stream ring). `siphon_mail::inspection()` has the
   right shape — a strict `Scanned` allowlist, "no parts = Incomplete" — but
   only mail uses it. One typed inspection outcome in `siphon-core`, consumed
   by the CLI exit code, siphon-fs, ICAP and the milter, would close the class.
2. **The evadex gate cannot catch a regression**: threshold 70% against an
   80% baseline, 2.5 h per run, not required, and its uploaded report was
   always empty (`tee` on stdout while `evadex ci` prints to stderr).
   evadex 3.41.0 (`batch`, `--seed`, real `--max-fp`) is what fixes the
   runtime; the threshold, `2>&1` and required-check settings are on this side.
3. **Normalizer accretion**: seven `fix(core): recover …` commits on Oct 13–14,
   each a counter to one evadex template, in a linear rewrite pipeline where a
   global stage can break a pattern class (6c vs ZIP+4) and a compensating pass
   gets bolted on. Measure with a seeded evadex run before adding another.
4. **Root crate boundary**: 25k lines hosting a dead HTTP server and code
   shared with siphon-api only for want of a lib target.
5. **Docs**: `CLAUDE.md` is 1,235 lines of architecture-plus-history; the
   conventions in it are ~250 lines. `docs/api-reference.md` is the Rust
   library surface, not HTTP; `docs/enterprise/api.md` describes the legacy
   embedded server. The siphon-api HTTP routes are documented only in
   `CLAUDE.md`.

## Resumption checklist

1. Merge #510, confirm `release` → `build siphon-api` is green.
2. Merge #497 and #494; resolve #496 (take `main`'s `obfuscate.rs`); ask the
   author to rebase #480 onto `main` without its normalizer commits.
3. Merge evadex #30/#31/#32, then update `evadex-quality-gate.yml`
   (`batch: true`, `--seed`, `--fp-category`, `2>&1 | tee`, threshold ≈ baseline − 3).
4. Start the inspection-outcome type (gap 1).
