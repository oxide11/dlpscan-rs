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

## 2026-04-26

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
