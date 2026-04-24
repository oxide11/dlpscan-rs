# siphon — enterprise Helm chart

Ships every Siphon component — REST scanner, file scanner, analyst
UI, OIDC authentication — under a single `helm install`. Replaces
the legacy `dlpscan` chart which only deployed the CLI image as a
monolithic Pod.

## What's in the box

| Component | Kind | Purpose |
|---|---|---|
| **siphon-api** | Deployment + Service | REST scanner, k8s discovery + rollout endpoints |
| **siphon-fs** | Deployment + Service | Multipart file-scan service |
| **nginx** | Deployment + Service | Reverse proxy + bundled Next.js SPA (forward-auth via Authelia) |
| **authelia** | Deployment + Service + PVC + ConfigMap | OIDC provider with Passkey / WebAuthn |
| — shared — | ConfigMap + Ingress + 4× NetworkPolicy | Overrides, single DNS entry, default-deny network |
| — siphon-api RBAC — | ServiceAccount + Role + RoleBinding | Pod list/watch + Deployment patch for the Ops UI's live pod view |

## Quickstart

```sh
# 1. Create the namespace.
kubectl create namespace siphon

# 2. Create the two secrets Helm values.yaml points at. Don't
#    check these into git.
kubectl -n siphon create secret generic siphon-api-auth \
  --from-literal=api-key="$(openssl rand -hex 32)"

kubectl -n siphon create secret generic siphon-authelia \
  --from-literal=jwt_secret="$(openssl rand -hex 32)" \
  --from-literal=session_secret="$(openssl rand -hex 32)" \
  --from-literal=storage_encryption_key="$(openssl rand -hex 32)"

# 3. Install.
helm install siphon ./deploy/helm/siphon \
  --namespace siphon \
  --set api.auth.secretName=siphon-api-auth \
  --set authelia.secretName=siphon-authelia \
  --set ingress.host=siphon.example.com

# 4. Wait for every pod Ready.
kubectl -n siphon rollout status deploy -l app.kubernetes.io/instance=siphon
```

The install message (`NOTES.txt`) prints the next steps based on
the enabled components and warns when required secrets are
missing.

## Values you usually tune

```yaml
# values.override.yaml — what a production deployment tends to set.

global:
  # Rotate mesh identities every 24h for free.
  linkerd:
    enabled: true

ingress:
  host: siphon.corp.example.com
  tls:
    enabled: true
    secretName: siphon-tls

api:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 12
  auth:
    secretName: siphon-api-auth
  # Tighten the list to exactly the Deployments you want the
  # /v1/overrides/roll endpoint to touch. The RBAC Role locks to
  # these names.
  k8sRoll:
    enabled: true
    deployments:
      - siphon-siphon-api
      - siphon-siphon-fs

authelia:
  secretName: siphon-authelia
  persistence:
    storageClassName: fast-ssd
    size: 5Gi
  # Paste your production configuration.yml here or pull it via
  # --set-file authelia.configYaml=./authelia-prod.yml
  configYaml: |
    # ... full Authelia config block ...
```

Apply with `helm upgrade --install siphon ./deploy/helm/siphon -f values.override.yaml`.

## The k8s-roll RBAC

`siphon-api`'s Ops UI needs to see pods and restart Deployments.
The chart creates a namespace-scoped Role + RoleBinding when
`api.k8sRoll.enabled=true`:

- `pods`, `pods/log`, `events` — `get`, `list`, `watch`
- `deployments` (in `apiGroups: ["apps"]`) — `get`, `list`,
  `watch`, `patch`, narrowed to the exact names in
  `api.k8sRoll.deployments`

Cluster-scoped access is never granted. A compromised siphon-api
pod can't touch anything outside the release namespace, and
within it is limited to the Deployments you name.

## Linkerd mTLS

`global.linkerd.enabled: true` adds `linkerd.io/inject: enabled`
to every pod. Prereq: the control plane is installed in the
cluster (`linkerd install | kubectl apply -f -`). Pods come up
with a sidecar, every in-chart call is mTLS'd with an identity
rotated every 24h, and `linkerd viz stat deploy -n siphon`
shows MESHED=1/1 across the board.

## Production checklist

Before pointing real traffic at the release:

- [ ] Create `siphon-api-auth` and `siphon-authelia` secrets out of
      band (External Secrets Operator / Sealed Secrets / Vault).
- [ ] Override `authelia.configYaml` with a real config —
      `storage` on Postgres, `notifier` on SMTP, real OIDC
      client secrets, real access-control rules.
- [ ] Pin every image to an exact version tag (`:2.1.0`, not
      `latest`) — the chart already does this for siphon-*
      images via `appVersion`, but `authelia.image.tag` is
      `4.38` and should match the Authelia version you've
      exercised in staging.
- [ ] Flip `ingress.tls.enabled=true` and provide `secretName`.
- [ ] Set `global.linkerd.enabled=true` (or bring your own
      mesh) so pod-to-pod traffic is authenticated.
- [ ] Verify `kubectl auth can-i patch deployments.apps -n siphon
      --as=system:serviceaccount:siphon:siphon-siphon-api` returns
      `yes` only for the Deployments you listed in
      `api.k8sRoll.deployments`.

## Out of scope for this chart

- **Prometheus Operator CRDs.** Metrics scrape uses pod annotations
  today; add a ServiceMonitor subchart when the cluster runs the
  Operator.
- **External findings database (Postgres / Neo4j / ClickHouse).**
  Phase 3 of the roadmap lands the database; this chart assumes
  in-memory findings rings until then.
- **Pod log streaming.** The k8s-roll RBAC grants `pods/log`
  read so a follow-up endpoint can stream logs, but the endpoint
  itself isn't wired yet.

## Upgrade from the legacy `dlpscan` chart

The old `dlpscan` chart deployed a single Pod running the `siphon`
CLI image with an embedded HTTP server. This chart deploys
per-service Deployments instead, so upgrading in place isn't
possible. Standard path:

```sh
helm uninstall dlpscan -n siphon
helm install siphon ./deploy/helm/siphon -n siphon -f values.override.yaml
```

Values keys from `dlpscan` that have equivalents here:

| Legacy | Current |
|---|---|
| `replicaCount` | `api.replicaCount` |
| `image.*` | `api.image.*` (plus `fs.image.*`, `nginx.image.*`, `authelia.image.*`) |
| `secrets.apiKey` | `api.auth.secretName` + secret key `api-key` |
| `networkPolicy.*` | `networkPolicy.*` (unchanged) |
| `podDisruptionBudget.*` | `api.podDisruptionBudget.*` |
| `autoscaling.*` | `api.autoscaling.*` |
| `config.*` | Mostly gone — overrides live in `overrides.config` now |
