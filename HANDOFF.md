# Siphon — Handoff Notes

Last updated: 2026-10-27

Companion doc to `CLAUDE.md` (architecture/conventions), `BACKLOG.md`
(work queue) and `FUTURE.md` (roadmap). This file is the "resume here after
a break" quick-start. Treat anything here older than the date above with
suspicion: the 2026-07-04 version of this file named versions and PRs three
months stale, and the 2026-10-15 one was overtaken within a fortnight.

## Current state

- **Versions** (per-crate SemVer — see `CLAUDE.md` "Versioning"), read from
  each `Cargo.toml` on the date above:
  - `siphon` (root CLI, package `siphon-cli`) — **2.9.0**
  - `siphon-core` — **2.12.0**
  - `siphon-api` — **2.12.2**
  - `siphon-fs` — **1.8.0**
  - `siphon-launcher` — **2.1.2**
  - `siphon-icap` — **0.4.0** · `siphon-smtp` — **0.4.0** · `siphon-mail` — **0.2.0** · `siphon-auth` — **0.1.0**
- **CI on `main`: green** on every workflow (CI, CodeQL, audit, DevSkim,
  release, release-tags, evadex quality gate). `release` was red from
  2026-09-05 to 2026-10-15 (#510); images have published since.
- **Inspection ADR complete** (`docs/architecture/inspection-outcome.md`,
  steps 1–7). Every ingress reports what its verdict covers through
  `siphon_core::Inspection`; the strings and bools it replaced are gone
  (step 6); the members a reader passes over — an image in a zip, an OLE
  object in a docx — are named as the informational `Unread::NotText`, and
  fail-closed consumers read `Inspection::has_gap()` (step 7). The next
  reading gap is embedded PDFs under `*/embeddings/`: named, not opened.
- **Detection baseline** (evadex, northam tier, 21,805 submissions, 2026-10-14,
  siphon-core 2.10.0): **80.4%**, up 3.9 points from 2.9.5. The gate measures
  the same tier per strategy on every detection-bearing PR: text 78.8% ·
  docx 76.8% · xlsx 75.4% · pdf 75.2% (2026-10-19, seed 20261015, evadex
  3.42.0) against floors 75 / 73 / 72 / 71. Weakest techniques on the
  baseline: morse 65% bypass, capital markets 39%, unicode whitespace 34.6%,
  structural 34.6%. Per-category numbers are noisy; `--seed` fixes the
  sentences but not the sample size.
- **Dependabot** lockfile PRs are folded by hand into one PR per wave
  (`CLAUDE.md` "Lockstep PRs"; #535, #542). `sbom-refresh.yml` was removed
  (#545, #537).

## Open PRs (2026-10-27)

| PR | Branch | State | Notes |
|---|---|---|---|
| #480 | `fix/security-audit-round8` | **do not merge as-is**, untouched since September | 22 commits; its normalizer half (zero-padding, `noise_embedded`, `base64_partial`, б→6) was re-implemented on `main` in the Oct 13–14 wave under different names; its service half (api/fs/icap/smtp fixes, and PRs #490/#492 merged *into* it) needs the author to rebase onto `main` and drop the core commits |
| #495 | `fix/icap-encapsulated-framing` | stacked on #480 | retarget to `main` after #480 is dealt with |

Open issue: **#515** — make the four `Run evadex quality gate (…)` jobs
required status checks on `main`. #544 made them run-or-skip on every PR;
the flip itself needs an `oxide11/dlpscan-rs` admin.

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

1. **Reading gaps the inspection now names but does not close.** Embedded
   PDFs and other non-OOXML objects under `*/embeddings/` are listed as
   `not_text` and passed over; so are non-text archive members. Opening an
   embedded PDF with the PDF reader, one level deep under the host's budget,
   is the next step of the Office reader (#538 read the hidden text parts;
   this would read the hidden documents). The "clean verdict for unread
   content" class itself is closed: ADR steps 1–7 landed 2026-10-15 → 10-27.
2. **The evadex gate is not yet a required check** (#515). Everything on this
   side is done — per-strategy floors near the measured baseline, batched
   transport, seeded sentences, `2>&1 | tee`, run-or-skip on every PR
   (#544) — and the remaining step is a branch-protection setting only an
   `oxide11/dlpscan-rs` admin can flip. Until then a PR that drops detection
   below a floor can still be squash-merged red.
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

1. `git fetch && git log --oneline -5 origin/main` — confirm the versions
   above are what `main` carries; if a lockstep PR landed since, the
   CHANGELOG's top block names it.
2. Ask an `oxide11/dlpscan-rs` admin to flip #515; ask the author of #480 to
   rebase it onto `main` without its normalizer commits.
3. Next feature: open embedded PDFs under `*/embeddings/` (gap 1), with
   `tests/office_parts_test.rs` cases and a conformance `structural` fixture.
4. Next measurement: a local pdf re-baseline on evadex 3.42.0 to attribute
   the remaining pdf-vs-text gap per technique (≈20 min with `--batch`), and
   a repeat-run variance figure (evadex BACKLOG) so a rate change has an
   error bar.
