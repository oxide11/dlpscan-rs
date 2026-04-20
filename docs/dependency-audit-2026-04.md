# Dependency Audit · 2026-04

Snapshot of Cargo deps with available major-version bumps, at the
time of the D1-D4 hygiene pass. Dependabot (see
`.github/dependabot.yml`) picks these up automatically going
forward — this doc is the triage starting point when a batch of
breaking-change PRs lands.

Minor/patch updates are already current (see D3 commit) — this is
only the long-tail work that requires code changes.

## Triage · high impact

Each touches substantial surface area. Plan + test each in a
dedicated branch; don't batch.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `kube` | 0.88.1 | 3.1.0 | Major arch shift from 0.x to 3.x — new `Api<T>` ergonomics, watch-stream changes. Feature flag `k8s-roll` in `siphon-api` is the only consumer; rewrite is scoped to the roll handler. |
| `k8s-openapi` | 0.21.1 | 0.27.1 | Pins to `kube`. Bump together. |
| `arrow` + `parquet` | 53.4.1 | 58.1.0 | Column-store API churn across 5 majors; impacts parquet extractor in `siphon-core/extractors`. |
| `zip` | 2.4.2 | 8.5.1 | Six majors of API reshuffling (iterator vs. visitor API, encoding changes). Used in the zip extractor + password-attack helper. |
| `rand` | 0.8.6 | 0.10.1 | Rand ecosystem moved to generic `TryRngCore` traits; `thread_rng()` → `rand::rng()`. Many call sites across scoring + obfuscation. |
| `redis` | 0.27.6 | 1.2.0 | First 1.0; async/sync module split, `redis::aio::connect` shape change. Consumer: `src/redis_rate_limit.rs`. |
| `pyo3` | 0.24.2 | 0.28.3 | Four majors of FFI lifetime changes. Consumer: python bindings (if enabled). |

## Triage · medium impact

Fewer call sites, but still require real review.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `criterion` | 0.5.1 | 0.8.2 | Benchmark harness — `benches/scanning.rs` rewrite. Dev-only. |
| `reqwest` | 0.12.28 | 0.13.2 | HTTP client. Minor API adjustments around middleware. |
| `toml` | 0.8.23 | 1.1.2 | First 1.0 — parser/serializer split. Config loaders in `siphon-core`. |
| `ratatui` | 0.29.0 | 0.30.0 | TUI widgets; `src/tui.rs` consumer. |
| `crossterm` | 0.28.1 | 0.29.0 | Paired with ratatui; bump together. |
| `sha2` | 0.10.9 | 0.11.0 | Digest ecosystem bump — if we take this, `digest` + `hmac` + `sha1` should all move together to avoid version-skew issues. |
| `hmac` | 0.12.1 | 0.13.0 | Companion to sha2. |

## Triage · low impact

Small APIs, mostly mechanical.

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `axum-server` | 0.7.3 | 0.8.0 | Shutdown-signal ergonomics updated. |
| `prometheus` | 0.13.4 | 0.14.0 | Metrics registry; flat registry → Builder pattern in places. |
| `calamine` | 0.26.1 | 0.34.0 | Excel reader; iterator API stabilized. |
| `cfb` | 0.10.0 | 0.14.0 | OLE / Compound File parser. |
| `rusqlite` | 0.32.1 | 0.39.0 | Error type + bundled feature changes. |
| `rxing` | 0.6.6 | 0.8.5 | QR decoder; `src/extractors.rs` consumer. |
| `quick-xml` | 0.37.5 | 0.39.2 | XML parser; error types shifted. |
| `matchit` | 0.8.4 | 0.8.6 | Transitive pin via axum — will clear naturally on axum bump. |
| `unicode-width` | 0.2.0 | 0.2.2 | Transitive pin; clears on dependent bump. |

## Recommended order

1. **sha2 + hmac together** — low risk, clears the "digest ecosystem skew" warning that propagates into many places.
2. **axum-server 0.8** — small, isolated.
3. **toml 1.0** — heavily used for config; shake out API surface early.
4. **kube 3.0 + k8s-openapi 0.27** — only touches the `k8s-roll` feature. Isolated, testable behind a feature flag.
5. **arrow + parquet 58** — extractor changes; gate on adding unit tests for the parquet extractor first.
6. **zip 8** — password-attack helper + zip extractor, medium surface.
7. **reqwest 0.13** — tight to tower/hyper stack; watch for tower-http compat.
8. **rand 0.10** — touches many files; sweep with a coverage-guided test run.
9. **redis 1.0** — rate limiter re-test against a live Redis in CI.
10. **pyo3, criterion, ratatui, rxing, calamine** — feature-gated or dev-only, queue behind the above.

## Non-recommendations

Don't bump these blindly; Dependabot will surface PRs, each should be reviewed independently per the above notes.
