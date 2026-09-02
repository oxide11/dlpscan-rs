# CI/CD

Siphon's pipelines live in `.github/workflows/`. There are seven, split into
three groups: **correctness** runs on every push, **security** runs against
`main` plus a weekly cron, and **delivery** only runs when something should
actually be published.

| Workflow | File | Trigger |
|---|---|---|
| CI | `ci.yml` | every push, PRs to `main` |
| evadex quality gate | `evadex-quality-gate.yml` | detection-path changes, dispatch |
| audit | `audit.yml` | `main`, PRs, weekly cron |
| CodeQL | `codeql.yml` | `main`, PRs, weekly cron |
| DevSkim | `devskim.yml` | `main`, PRs, weekly cron |
| release | `release.yml` | `main`, `v*` tags, dispatch |
| deploy-cloudflare | `deploy-cloudflare.yml` | `deploy/cloudflare/**` changes, dispatch |

The toolchain is pinned to **Rust 1.95** in every workflow, matching
`rust-toolchain.toml` and each `Cargo.toml`'s `rust-version`. Bump all of
them together (see `CLAUDE.md` → Toolchain).

---

## Correctness

### CI (`ci.yml`)

Runs on **every** push to any branch and every PR into `main`. Six
independent jobs; `test` is the only one that waits on `build`.

| Job | What it runs |
|---|---|
| Build | `cargo build --release` |
| Test | `--lib`, `audit_spec`, `integration_test`, `evasion_test`, `forensics_test`, `evadex_regressions` |
| Clippy | `cargo clippy --lib -- -D warnings -A dead-code -A unused-imports` |
| Format | `cargo fmt --check` |
| Version sync | `scripts/check-version-sync.sh` |
| UI | pnpm `typecheck`, `lint`, `build` in `ui/` |

Reproduce the Rust jobs locally before pushing:

```bash
cargo fmt --check
cargo clippy --lib -- -D warnings -A dead-code -A unused-imports
cargo test --lib
cargo test --test integration_test
cargo test --test evasion_test
```

**Version sync** is the job most likely to surprise you: every place a
version is declared — workspace crates, `ui/package.json`, the Helm
`appVersion` and image tags — must agree with the root `Cargo.toml`. A
forgotten Helm tag lands as a red check, not a silent drift.

### Harnesses CI does not run

`detection_quality`, `fp_probe`, and `encoding_diag` appear in **no**
workflow. They are the harnesses listed in `CLAUDE.md` under "Other test
harnesses", and they have to be run by hand:

```bash
cargo test --test detection_quality   # labeled-corpus recall + FP
cargo test --test fp_probe            # false-positive investigation
```

Run `detection_quality` after any change to normalization, scoring, or
dedup. It is **not** currently green on `main` — a `GPS Coordinates` recall
miss and a `US Phone Number` false positive on an implausible number predate
the current branch — so compare against a baseline run rather than expecting
a clean pass, and fix that before wiring it into CI or it will only add
noise.

`audit_spec` used to be in this list and is now part of the `test` job. It
guards the lockstep between `PatternDef.specificity` / `.context_required`
in `patterns/mod.rs` and `pattern_specificity()` / `is_context_required()`
in `models.rs`; the scanner consults both, so a disagreement means one
source is lying. Nothing ran it automatically for a long time, which is how
the Malta TIN, Chile RUN/RUT and Tanzania NIDA divergences accumulated
unnoticed.

### evadex quality gate (`evadex-quality-gate.yml`)

Path-filtered to the detection path — `normalize/`, `patterns/`, `scanner/`,
`validation/` under `crates/siphon-core/src/`. Builds the CLI, checks out the
external [`evadex`](https://github.com/tbustenk/evadex) adversarial harness,
and enforces thresholds on the `northam` tier:

- `--min-detection 70` (0–100 scale)
- `--max-fp 5`

The report uploads as the `evadex-quality-gate-report` artifact, retained 30
days, even on failure. Because it is path-filtered, a change to scoring or
context matching that lands outside those four directories will not trigger
it — run it manually via dispatch if you touch detection from elsewhere.

---

## Security

All three publish SARIF into GitHub's code-scanning view and run on a weekly
cron so a dormant branch is re-checked against current advisory data. The
crons are deliberately staggered — CodeQL Monday 13:17 UTC, DevSkim Monday
14:23 UTC, audit Tuesday 14:23 UTC — so reports land on different days and
off-the-hour to dodge cron stampede.

- **`audit.yml`** — `cargo deny check` over all four `deny.toml` sections:
  advisories (RustSec vulnerable/yanked are fatal, unmaintained warns),
  licenses (allow-list), sources (crates.io only), bans (multi-version
  warns). Add exceptions sparingly and always with a rationale. The triage
  log lives in `docs/dependency-audit.md`.
- **`codeql.yml`** — `security-extended,security-and-quality` query packs.
- **`devskim.yml`** — Microsoft DevSkim SAST.

CI declares `permissions: contents: read, actions: read` — the minimum
scope. This is intentional: it closes CodeQL's "Workflow does not contain
permissions" finding and stops a compromised action escalating to write
access. Keep new workflows equally narrow.

---

## Delivery

### release (`release.yml`)

Builds container images for `siphon-api` and `siphon-fs` and pushes them to
GHCR. Deliberately **not** run on ordinary feature-branch pushes, so those
don't burn minutes on Docker builds.

| Trigger | Tags produced |
|---|---|
| push to `main` | `:main`, `:sha-<short>` |
| tag `v2.1.0` | `:2.1.0`, `:2.1`, `:latest` |
| manual dispatch | `:<branch>`, `:sha-<short>` — `push: false` builds without publishing |

Two constraints worth knowing before you change it:

- **amd64 only.** Cross-building arm64 under QEMU failed with exit 101 —
  emulation roughly triples the memory footprint of `rav1e`/`arrow` codegen
  and `rustc` has known miscompiles under it. Adding arm64 means splitting
  the matrix across `ubuntu-latest` and `ubuntu-24.04-arm`, then combining
  per-arch images in a manifest job.
- **`CARGO_BUILD_JOBS=2`.** Caps cargo parallelism so codegen doesn't peak
  past the 16 GB runner (each codegen unit can reach ~1 GB).

GitHub Actions layer caching (`type=gha,mode=max`) cuts re-run builds from
roughly 5 minutes to 1.

### deploy-cloudflare (`deploy-cloudflare.yml`)

Deploys the demo endpoint to Cloudflare Workers + Containers. Path-filtered
to `deploy/cloudflare/**` and `deploy/Dockerfile.api`.

- PRs run **typecheck only**; the deploy job is gated to `push`/dispatch so
  a fork PR can never reach the live Worker.
- `cloudflare/wrangler-action@v4` handles auth and uploads `SIPHON_API_KEY`
  as a Worker secret on each run, so rotating the key is a repository-secret
  change rather than a manual `wrangler` invocation.
- A retrying `/health` smoke test follows the deploy, allowing for the cold
  start a freshly deployed container pays.

Requires repository secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
and `SIPHON_API_KEY`. Full setup and the cost/trade-off notes are in
[`deploy/cloudflare/README.md`](../../deploy/cloudflare/README.md).

---

## Local pre-commit

`scripts/install-hooks.sh` wires `scripts/check-semver.sh` as a pre-commit
hook, which runs `cargo-semver-checks` against modified library crates so an
accidental breaking change is caught before it reaches CI.

## Other platforms

The workflows above are GitHub Actions. Porting to another runner means
reproducing the same gates — the commands are all plain `cargo` and `pnpm`
invocations, so a minimal GitLab equivalent of the Rust half is:

```yaml
stages: [check, test]

variables:
  CARGO_TERM_COLOR: always

check:
  stage: check
  image: rust:1.95
  script:
    - cargo fmt --check
    - cargo clippy --lib -- -D warnings -A dead-code -A unused-imports
    - bash scripts/check-version-sync.sh

test:
  stage: test
  image: rust:1.95
  script:
    - cargo test --lib
    - cargo test --test integration_test
    - cargo test --test evasion_test
```

The security workflows have no direct equivalent — `cargo deny check` ports
cleanly, but CodeQL and DevSkim are GitHub-specific.
