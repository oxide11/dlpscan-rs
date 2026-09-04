# Security

## Reporting vulnerabilities

Please report security issues to the security team directly rather than opening
a public issue. Include a description of the vulnerability, reproduction steps,
and the affected version.

---

## siphon-launcher threat model

`siphon-launcher` is a local-development process manager. It is explicitly
**not a production component**. The following security properties apply:

### Intentional design choices

**No authentication.** The launcher's start/stop API is unauthenticated by
design. Its sole compensating control is that it hard-exits if
`SIPHON_LAUNCHER_BIND` is set to a non-loopback address — it can only bind
to `127.0.0.1` or `::1`. Never expose it on a network-facing interface.

**Loopback-only enforcement is the trust boundary.** Any process on the same
host can call the launcher API. In a multi-tenant or shared-host environment
this is unacceptable; the launcher must not be used there.

**Environment injection is limited by BLOCKED_KEYS.** The launcher's
`POST /start` endpoint accepts an `env` map for spawned child processes. Keys
are filtered by an allowlist (`SIPHON_*`, `RUST_LOG`, `RUST_BACKTRACE`) and a
blocklist (`BLOCKED_KEYS`) that prevents injection of security-critical
variables:

| Blocked key | Risk if injected |
|---|---|
| `SIPHON_API_KEY` | Substitutes a known key, bypassing auth |
| `SIPHON_AUDIT_LOG_PATH` | Redirects or suppresses the audit trail |
| `SIPHON_BIND` / `SIPHON_FS_BIND` | Moves child to a network-facing address |
| `SIPHON_ALLOW_PRIVATE_DESTINATIONS` | Disables SSRF guards |
| `SIPHON_ALLOW_UNAUTHENTICATED` | Disables bearer-token auth on the child |
| `SIPHON_DEV_MODE` | Disables audit-log enforcement |

This blocklist is the compensating control for the lack of launcher
authentication. It must be kept up to date as new security-critical env vars
are added.

### Production deployment

In production, orchestrate `siphon-api` and `siphon-fs` directly via:
- Helm chart in `deploy/helm/siphon/`
- Docker Compose in `deploy/docker-compose.yml`
- Kubernetes manifests in `deploy/k8s/`

Do not run `siphon-launcher` in production or on any shared host.

---

## SIPHON_ALLOW_UNAUTHENTICATED

This env var disables bearer-token authentication on `siphon-api` and
`siphon-fs`. Two layered controls prevent accidental production use:

1. **Runtime guard:** The service refuses to start with this flag set on any
   non-loopback bind address (`SIPHON_BIND` / `SIPHON_FS_BIND`).
2. **Compile-time gate:** The env var only takes effect in binaries compiled
   with `--features allow-unauthenticated`. Production binaries are built
   without this feature, so the escape hatch is absent at the binary level.

Production Dockerfiles and Helm values must not enable `allow-unauthenticated`.

---

## Findings persistence and data residency

Findings rows in Postgres contain matched sensitive-data snippets. The
connection is encrypted (`SIPHON_DATABASE_TLS=require` by default). Operators
are responsible for:

- Ensuring the Postgres instance is not publicly reachable
- Setting `SIPHON_FINDINGS_RETENTION_DAYS` to a value consistent with their
  data-retention policy (default 90 days)
- Enabling `SIPHON_AUDIT_SIGNING_KEY_HEX` for tamper-evident audit chains in
  regulated environments

---

## API key rotation

Siphon supports zero-downtime API key rotation via a secondary key accepted in
parallel with the primary.

### Procedure

1. Generate a new key: `openssl rand -hex 32`
2. Set `SIPHON_API_KEY_SECONDARY=<new key>` on every pod. Both the old and new
   keys are now accepted simultaneously.
3. Update all clients to present the new key.
4. Once all clients are migrated, promote the new key:
   `SIPHON_API_KEY=<new key>` — and remove `SIPHON_API_KEY_SECONDARY`.
5. Restart pods to complete the rotation.

### Security properties

- Both keys are SHA-256 hashed at rest. Neither plaintext key is stored in
  process memory after startup.
- Both keys are checked with the same constant-time XOR-fold. There is no
  timing oracle that distinguishes the primary from the secondary key.
- The secondary key accepts all the same permissions as the primary. It is a
  temporary escape valve for rotation — not a separate role.

---

## Per-pod findings ring

Each `siphon-api` and `siphon-fs` replica maintains an in-memory ring buffer
of recent findings (`SIPHON_FINDINGS_RING_CAP`, default 1000). This ring is
**not durable** — pod death clears it. Use the Postgres-backed
`GET /v1/findings/pg` endpoint for durable findings history. The C2 dashboard's
**Findings History** tab uses Postgres; the live ring is supplementary.
