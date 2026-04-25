# Dependency Audit

Living triage doc for Cargo dependencies that still need a major-version
bump. Dependabot (see `.github/dependabot.yml`) opens individual PRs as
upstream releases; this doc is the human-readable "where are we" snapshot
+ the recommended order for bumps that need code changes.

Minor / patch updates flow through Dependabot directly and don't show up
here. Only `MAJOR.MINOR` bumps that require deliberate code surgery are
tracked.

CI runs `cargo deny check` on every push (see `.github/workflows/audit.yml`)
to keep the live advisory feed honest. Configuration: [`deny.toml`](../deny.toml).

---

**Status as of 2026-04-25.** Compare against `Cargo.toml` /
`crates/*/Cargo.toml`. Last sweep landed in commits b53f483 (kube),
427da14 (toml), 8101ef0 (calamine + redis), 01d51a0 (prometheus +
quick-xml + axum-server), 04e4152 (sha2 + hmac), and e7d6484 (criterion).

## Pending · high impact

Each touches substantial surface area. Plan + test each in a dedicated
branch; don't batch.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `arrow` + `parquet` | 53.4.1 | 58.1.0 | Column-store API churn across 5 majors; impacts the Parquet extractor in `siphon-core/extractors`. Add Parquet-specific extractor tests before bumping so behavioural drift is caught. |
| `zip` | 2.4.2 | 8.5.1 | Six majors of API reshuffling (iterator vs visitor API, encoding changes). Used in the zip extractor + the password-attack helper. |
| `rand` | 0.8.6 | 0.10.1 | Rand ecosystem moved to generic `TryRngCore`; `thread_rng()` → `rand::rng()`. Many call sites across scoring + obfuscation + tests. |
| `pyo3` | 0.24.2 | 0.28.3 | Four majors of FFI lifetime changes. Consumer: the python-bindings feature (off by default in CI). |

## Pending · medium impact

Fewer call sites but still require real review.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `reqwest` | 0.12.28 | 0.13.2 | HTTP client. Tight to the tower / hyper stack — coordinate with axum + tower-http compat. |
| `ratatui` | 0.29.0 | 0.30.0 | TUI widgets; `src/tui.rs` consumer. |
| `crossterm` | 0.28.1 | 0.29.0 | Paired with ratatui — bump together. |

## Pending · low impact

Small APIs, mostly mechanical.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `cfb` | 0.10.0 | 0.14.0 | OLE / Compound File parser; legacy Office `.xls`/`.doc` extraction. |
| `rusqlite` | 0.32.1 | 0.39.0 | Error type + bundled feature changes. |
| `rxing` | 0.6.6 | 0.8.5 | QR decoder; `src/extractors.rs` consumer. |

## Recently shipped

For history; no action. Each landed via its own dependabot PR + a follow-up
chore commit when code changes were needed.

| Dep | Was | Now | Commit |
|---|---|---|---|
| `kube` | 0.88.1 | 3.1.0 | b53f483 |
| `k8s-openapi` | 0.21.1 | 0.27.1 | b53f483 |
| `toml` | 0.8.23 | 1.1.2 | 427da14 |
| `calamine` | 0.26.1 | 0.34.0 | 8101ef0 |
| `redis` | 0.27.6 | 1.2.0 | 8101ef0 |
| `prometheus` | 0.13.4 | 0.14.0 | 01d51a0 |
| `quick-xml` | 0.37.5 | 0.39.2 | 01d51a0 |
| `axum-server` | 0.7.3 | 0.8.0 | 01d51a0 |
| `sha2` | 0.10.9 | 0.11.0 | 04e4152 |
| `hmac` | 0.12.1 | 0.13.0 | 04e4152 |
| `criterion` | 0.5.1 | 0.8.2 | e7d6484 |

## Recommended order

Pick from `Pending · high impact` first — these block downstream work the
most. Bump strategy:

1. **arrow + parquet 58** together — extractor surgery, gate on
   adding unit tests for the parquet extractor first.
2. **zip 8** — password-attack helper + zip extractor, medium surface
   area but well-covered by existing tests.
3. **rand 0.10** — touches many files; sweep with a coverage-guided test
   run + verify the obfuscator's PRNG output is stable post-bump.
4. **pyo3 0.28** — feature-gated, isolated; queue last unless someone
   explicitly needs the Python bindings.

After the high-impact list clears, sweep medium/low in any order. None of
the remaining items have known security advisories — they're cleanup, not
remediation.

## Non-recommendations

Don't bump these blindly. Dependabot will surface PRs for every release;
each should be reviewed independently against the notes above. The `Bans`
warning from `cargo deny` about multiple-versions in the dep graph is
expected during the transition (e.g. `rand 0.8` + `rand_core 0.6` because
some transitive dep hasn't bumped yet); resolve naturally as the upstream
graph converges.
