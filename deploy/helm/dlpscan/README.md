# dlpscan — Helm chart

Kubernetes deployment for the Siphon DLP scanner. This chart
currently deploys the workspace as a **single image** (the default
`siphon` CLI binary serving `/scan` over HTTP). A per-service split
into separate `siphon-api` / `siphon-fs` Deployments is tracked in
the Phase 3 roadmap — today's monolithic shape is intentional and
matches the public `oxide11/dlpscan-rs` image.

## Quick start

```sh
helm install siphon ./deploy/helm/dlpscan \
  --namespace siphon \
  --create-namespace \
  --set secrets.apiKey=$(openssl rand -hex 32)
```

Update an existing release the same way — Helm treats `install` +
`--upgrade` as idempotent.

## Values worth knowing

| Key | Default | Notes |
|-----|---------|-------|
| `image.repository` | `ghcr.io/oxide11/dlpscan-rs` | GHCR publishes from `release.yml` |
| `image.tag` | pinned to chart `appVersion` | Bump via `scripts/bump-version.sh` — never `latest` in prod |
| `replicaCount` | `2` | HPA (below) can scale beyond this |
| `autoscaling.enabled` | `false` | Flip to `true` to hand control to the HPA |
| `linkerd.enabled` | `false` | Opt in to Linkerd sidecar injection for pod-to-pod mTLS (see [`docs/AUTHENTICATION.md`](../../../docs/AUTHENTICATION.md)) |
| `networkPolicy.enabled` | `true` | Default-deny egress beyond DNS + HTTPS |
| `podDisruptionBudget.enabled` | `true` | `minAvailable: 1` so voluntary evictions can't take the Deployment fully offline |
| `secrets.apiKey` | `""` | Required for non-dev deploys; empty disables bearer auth |
| `config.siem.enabled` | `false` | Turn on to forward findings to Splunk / ES / Datadog / Syslog |

See `values.yaml` for the exhaustive list (rate-limit, max payload,
SIEM type/endpoint, vault backend, probe tuning, etc.).

## Security posture

- `runAsNonRoot: true`, `runAsUser: 1000`, `fsGroup: 1000`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: [ALL]`
- `allowPrivilegeEscalation: false`
- `seccompProfile.type: RuntimeDefault`
- `NetworkPolicy` locks egress to DNS (UDP/53) and HTTPS (TCP/443)
- `/tmp` and `/var/log/dlpscan` are `emptyDir` mounts so the
  read-only root FS still has writable scratch space

## Secrets — don't check them in

The chart expects secrets in a Kubernetes `Secret` created outside
the chart. Pick one of the supported paths:

1. **External Secrets Operator** — source from AWS Secrets Manager,
   GCP Secret Manager, Vault, etc. Recommended for prod.
2. **Sealed Secrets** — encrypted YAML safe to commit.
3. **`helm install --set`** — inline on the command line. Fine for
   lab work, awful for audit trails.

Never set `secrets.apiKey` or `secrets.vaultEncryptionKey` in a
committed values file.

## Version bumps

The chart's **`appVersion`** (image to deploy) is kept in lockstep
with `Cargo.toml`'s `[package] version` and the workspace crates.
Use `scripts/bump-version.sh 2.2.0` — it updates every declaration
in one pass. The chart's own `version:` evolves independently; bump
it by hand when templates change.

A CI check (`version-sync` in `.github/workflows/ci.yml`) fails
the build if any of these drift.

## What's deliberately out of scope here

- **Per-service split.** `siphon-api` and `siphon-fs` currently
  share a single Deployment backed by the `siphon` image's embedded
  server. Phase 3 of the roadmap breaks them apart.
- **Authelia + Nginx.** The zero-trust front door lives at
  `deploy/authelia/` and `deploy/nginx/` and isn't a chart yet —
  compose or manual `kubectl apply` for now.
- **ServiceMonitor / PodMonitor CRDs.** Metrics scrape via
  Prometheus annotations today; swap to a monitor CRD once the
  target cluster runs Prometheus Operator.
