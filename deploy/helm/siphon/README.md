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

## Postgres (findings persistence)

The chart bundles an optional single-replica Postgres that backs
findings history and C2 shared state. It is **enabled by default**
(`postgres.enabled: true`). To bring up the full stack with findings
persistence:

```sh
# Create the postgres secret before installing (or upgrading).
kubectl -n siphon create secret generic siphon-postgres \
  --from-literal=password="$(openssl rand -hex 32)"

helm install siphon ./deploy/helm/siphon \
  --namespace siphon \
  --set postgres.secretName=siphon-postgres \
  --set api.auth.secretName=siphon-api-auth \
  --set authelia.secretName=siphon-authelia \
  --set ingress.host=siphon.example.com
```

`siphon-api` picks up `SIPHON_DATABASE_URL` automatically when
`postgres.enabled=true`; findings history endpoints and C2 shared state
activate without further configuration.

To use an **external Postgres** instead:

```sh
helm install siphon ./deploy/helm/siphon \
  --set postgres.enabled=false \
  --set "api.extraEnv[0].name=SIPHON_DATABASE_URL" \
  --set "api.extraEnv[0].value=postgres://user:pass@host:5432/siphon"
```

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

## Local development (kind)

Run the full stack on your laptop with no registry or ingress controller.
Requires [kind](https://kind.sigs.k8s.io/) and Docker.

```sh
# 1. Create a cluster (once).
kind create cluster --name siphon-lab

# 2. Build the three images. Pass CARGO_BUILD_JOBS to cap parallelism
#    if the build OOMs on a memory-constrained machine.
docker build --build-arg CARGO_BUILD_JOBS=4 \
  -f deploy/Dockerfile.api -t siphon-api:lab .
docker build --build-arg CARGO_BUILD_JOBS=4 \
  -f deploy/Dockerfile.fs -t siphon-fs:lab .
docker build -f deploy/nginx/Dockerfile -t siphon-nginx:lab .

# 3. Load the images into kind (no registry push needed).
kind load docker-image siphon-api:lab   --name siphon-lab
kind load docker-image siphon-fs:lab    --name siphon-lab
kind load docker-image siphon-nginx:lab --name siphon-lab

# 4. Create namespace + secrets.
kubectl create namespace siphon
kubectl -n siphon create secret generic siphon-api-auth \
  --from-literal=api-key="$(openssl rand -hex 32)"
kubectl -n siphon create secret generic siphon-authelia \
  --from-literal=jwt_secret="$(openssl rand -hex 32)" \
  --from-literal=session_secret="$(openssl rand -hex 32)" \
  --from-literal=storage_encryption_key="$(openssl rand -hex 32)"

# 5. Install.
#    global.imageRegistry=""   -- images were loaded without a registry prefix
#    authelia.externalUrl      -- must be https:// even for local; the redirect
#                                 never fires with devBypass=true but Authelia
#                                 4.38 rejects http:// at startup validation
helm install siphon ./deploy/helm/siphon \
  --namespace siphon \
  --set global.imageRegistry="" \
  --set api.image.repository=siphon-api \
  --set api.image.tag=lab \
  --set api.image.pullPolicy=Never \
  --set fs.image.repository=siphon-fs \
  --set fs.image.tag=lab \
  --set fs.image.pullPolicy=Never \
  --set nginx.image.repository=siphon-nginx \
  --set nginx.image.tag=lab \
  --set nginx.image.pullPolicy=Never \
  --set authelia.devBypass=true \
  --set authelia.secretName=siphon-authelia \
  --set authelia.cookieDomain=127.0.0.1 \
  --set authelia.externalUrl=https://127.0.0.1:8080 \
  --set authelia.scheme=http \
  --set api.auth.secretName=siphon-api-auth \
  --set ingress.enabled=false \
  --set api.replicaCount=1 \
  --set nginx.replicaCount=1

# 6. Wait for rollout.
kubectl -n siphon rollout status deploy -l app.kubernetes.io/instance=siphon --timeout=300s

# 7. Access the UI.
kubectl -n siphon port-forward svc/siphon-nginx 8080:80
# Open http://localhost:8080 in your browser.
```

To rebuild and redeploy after code changes:

```sh
# Rebuild only the image you changed, then reload + upgrade.
docker build --build-arg CARGO_BUILD_JOBS=4 \
  -f deploy/Dockerfile.api -t siphon-api:lab .
kind load docker-image siphon-api:lab --name siphon-lab
kubectl -n siphon rollout restart deploy/siphon-api
```

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
      - siphon-api
      - siphon-fs

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
      --as=system:serviceaccount:siphon:siphon-api` returns
      `yes` only for the Deployments you listed in
      `api.k8sRoll.deployments`.

## Out of scope for this chart

- **Prometheus Operator CRDs.** Metrics scrape uses pod annotations
  today; add a ServiceMonitor subchart when the cluster runs the
  Operator.
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
