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

SemVer `MAJOR.MINOR.PATCH`. Today the workspace ships a single version across
all crates (`2.1.0`). When bumping, update in lockstep:

- every `[package] version` in `Cargo.toml` (root + `crates/*`)
- every `appVersion` / image tag in `deploy/helm/**/Chart.yaml` and
  `deploy/helm/**/values.yaml`
- any pinned tag in `deploy/docker-compose.yml`

Docker image tags in Helm charts must be pinned to an exact version — never
`latest` in production values.

## Commits

Use Conventional Commits:

- `feat:` new capability
- `fix:` bug fix
- `chore:` tooling / deps / non-behavioral
- `docs:` documentation only
- `breaking:` (or `feat!:` / `fix!:`) API/behavior break — call it out in the
  body

Keep subjects under ~70 characters; put detail in the body.

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
