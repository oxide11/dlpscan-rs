# CLAUDE.md

Project standards for AI-assisted development on Siphon (dlpscan-rs).

## Project overview

Siphon is a high-performance DLP scanner built as a Rust Cargo workspace. The
top-level crate (`siphon`) is the CLI; the workspace members in `crates/` are
long-running services:

- `siphon-core` — scanner engine (patterns, validators, detection pipeline)
- `siphon-api` — sync HTTP scan service with RBAC, API-key auth, audit chain
- `siphon-fs` — multipart file-scan service (PDF, Office, archives, etc.)
- `siphon-launcher` — local-dev process manager

Deployment assets live under `deploy/` (Dockerfiles, docker-compose, Helm
chart, k8s manifests). Ruleset TOML lives in `rulesets/`.

## Toolchain

- **Rust: 1.95** (pinned in `rust-toolchain.toml`, mirrored in every
  `Cargo.toml` `rust-version`, CI workflows, and Dockerfile base images). Bump
  all five in lockstep when upgrading.
- **Edition: 2021**
- `Cargo.lock` is committed. Dockerfiles build with `--locked`; do not
  regenerate the lockfile without intent.

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

1. `deploy/Dockerfile.<name>` — add or update `LABEL version="X.Y.Z"`. The
   image is rebuilt from the same source, so the label is the truth-of-record
   for which crate version produced the image.
2. `deploy/helm/siphon/values.yaml` — the matching `<name>.image.tag: "X.Y.Z"`.
   Never leave a service tag empty in production values; never use `latest`.
3. `deploy/docker-compose.yml` — the matching `image: <name>:X.Y.Z` line. The
   dev compose may use `:latest` for local builds, but any compose file that
   ships in a release artifact must pin.
4. `CHANGELOG.md` — add a `## <name> X.Y.Z — YYYY-MM-DD` heading with the
   commit's user-facing description. One CHANGELOG, scoped sections per crate.

When you bump the Helm chart's own `version:`, also update its `appVersion:`
to match the highest crate version moved in this release wave.

### Core MAJOR cascades

`siphon-core` is a `path =` dep of every other crate. A `siphon-core` MAJOR
bump means downstream crates (`siphon`, `siphon-api`, `siphon-fs`,
`siphon-launcher`) had to be edited to keep compiling — that's a user-visible
change to each, so each gets at least a MINOR bump in the same wave. A
`siphon-core` PATCH or MINOR doesn't force a downstream bump unless the
downstream actually changed.

### Inter-crate dep pinning

Today the workspace uses `path =` only (no `version =`) for inter-crate deps
in `Cargo.toml`. `Cargo.lock` records the exact resolved versions, so this is
safe inside the repo. Add a `version =` constraint alongside the `path =`
**only** when publishing a crate to a registry — until then it's noise that
duplicates `Cargo.lock`.

### Image-tag policy

| File | Rule |
|---|---|
| `deploy/helm/siphon/values.yaml` | every `*.image.tag:` is a fully pinned `X.Y.Z` string. Never empty, never `latest`, never floating `X.Y`. |
| `deploy/Dockerfile.*` | base images (`rust:1.95-bookworm`, `nginx:1.27-alpine`, etc.) pinned by major+minor; consider digest-pinning for prod. |
| `deploy/docker-compose.yml` | `:latest` is acceptable for the local dev profiles; any release-shipped compose pins to `X.Y.Z`. |
| `deploy/k8s/**` | raw manifests are dev-only, but if they pin a tag, pin to `X.Y.Z`. |

## Releases

### Git tags

One tag per crate per release, namespaced so they don't collide:

- `siphon-core-vX.Y.Z`
- `siphon-api-vX.Y.Z`
- `siphon-fs-vX.Y.Z`
- `siphon-launcher-vX.Y.Z`
- `siphon-cli-vX.Y.Z`
- `siphon-chart-vX.Y.Z` — chart structure tag (independent of `appVersion`)

A "release wave" is a single commit on `main` that bumps one or more crates
and gets one tag per bumped crate (annotated, signed where possible). Tags
are immutable — never re-point.

### Changelog

A single top-level `CHANGELOG.md` at the repo root, [Keep a
Changelog](https://keepachangelog.com/) format, per-crate sections. Example
release block:

    ## 2026-04-30

    ### siphon-fs 1.0.0
    - First stable release of the multipart file-scan service.
    - **BREAKING:** `/scan` endpoint now requires `Content-Type: multipart/form-data`.

    ### siphon-api 2.2.0
    - feat(api): /v1/k8s/pods returns `in_cluster: false` outside a cluster
      instead of a 503 init error.

The CHANGELOG is the user-facing release notes — every entry is something an
operator or developer needs to know. `chore:` / `ci:` / `test:` commits don't
appear unless they're user-visible.

### Pre-release flow

1. Branch off `main` (`feat/<scope>-<short-summary>`).
2. Make changes; commits use Conventional Commits with scope.
3. In a final commit, bump the crate version per "Lockstep updates" above and
   add a CHANGELOG entry. Don't bump until the rest of the work is reviewed —
   easier to amend the version commit than to re-version on every iteration.
4. Open PR; CI runs (see "CI expectations" below).
5. After merge to `main`, push the per-crate tag(s) on the merge commit.

## Commits

Use Conventional Commits with a scope:

    <type>(<scope>): <short summary>

Types:

- `feat:` new capability
- `fix:` bug fix
- `chore:` tooling / deps / non-behavioral
- `docs:` documentation only
- `refactor:` internal cleanup, no user-visible change
- `test:` test-only change
- `ci:` CI/CD config only
- `breaking:` (or `feat!:` / `fix!:`) API/behavior break — call it out in the
  body and require a MAJOR bump in the affected crate

Scopes are listed in "What bumps when" above. Use exactly one scope per
commit. Subject under ~70 characters; put detail in the body.

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

When `cargo-semver-checks` is wired up (see roadmap), it will run on the
modified crate and gate MAJOR bumps. Until then, manually inspect public-API
diffs before bumping.

## Security

- Dependabot watches `cargo`, `github-actions`, and `docker` ecosystems
  weekly. Keep the dep graph clean — don't suppress advisories without a
  documented reason in `deny.toml`.
- DevSkim SAST runs on push/PR (`.github/workflows/devskim.yml`).
- `deny.toml` gates advisories; add exceptions sparingly with a rationale.
- API-key auth is SHA-256 hashed at rest. TLS (rustls) is optional but
  recommended; the audit chain uses HMAC-SHA256 when
  `SIPHON_AUDIT_SIGNING_KEY_HEX` is set.

## Where things live

- Scanner patterns: `crates/siphon-core/src/` + `rulesets/*.toml`
- HTTP handlers: `src/api.rs` (CLI-embedded server) and
  `crates/siphon-api/src/`
- File extractors: `src/extractors.rs` and `crates/siphon-fs/src/`
- RBAC: `src/rbac.rs`
- Policy engine: `src/policy.rs`
- SIEM / webhooks: gated by the `siem` / `webhooks` features in the root
  crate
- Integration tests: `tests/`
- Architecture / patterns docs: `docs/`
- Per-crate version source of truth: `Cargo.toml` (root) and
  `crates/*/Cargo.toml`. The Helm chart, Dockerfiles, compose files, and
  CHANGELOG are downstream and must be updated in lockstep — see
  "Lockstep updates within one crate".
