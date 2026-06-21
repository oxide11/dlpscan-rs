# Siphon k8s Lab

Local single-node `kind` cluster running **siphon-api** + **siphon-fs**
behind an nginx ingress so you can pressure-test the two-pod
architecture on a laptop.

## Prerequisites

- Docker Desktop (or any Docker daemon), running
- [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start/) — `brew install kind`
- `kubectl` ≥ 1.27

On a 16GB MacBook Air the full lab sits around ~2GB RAM. On 8GB
machines, skip the lab and run `cargo run -p siphon-api` + `cargo run -p siphon-fs` locally instead.

## Stand it up

```bash
./scripts/lab-up.sh
```

The script is idempotent — re-running it rebuilds the images,
reloads them into the cluster, and rolls the Deployments.

## Hit it

Once `lab-up.sh` reports ready, the API key is printed and stored in
the `siphon-api-auth` secret. siphon-nginx injects it automatically,
so `/api/*` and `/fs/*` routes work without a manual Authorization header.

```bash
# Health endpoints (unauthenticated)
curl http://localhost/api/health
curl http://localhost/fs/health

# Scan via siphon-nginx (API key injected by nginx — no header needed)
curl -s -X POST http://localhost/api/scan \
  -H 'content-type: application/json' \
  -d '{"text":"Email: alice@example.com · card 4242 4242 4242 4242"}'

# File scan via siphon-fs (nginx injects auth)
curl -s -X POST http://localhost/fs/scan -F "file=@/path/to/file.pdf"

# Read the API key if you need it for direct access
API_KEY=$(kubectl get secret siphon-api-auth -n siphon-lab \
  -o jsonpath='{.data.api-key}' | base64 -d)
curl -s http://localhost/api/scan \
  -H "Authorization: Bearer ${API_KEY}" \
  -H 'content-type: application/json' \
  -d '{"text":"test"}'
```

## Point the admin console at it

Open http://localhost/ui/ in a browser — siphon-nginx routes to siphon-ui
and injects the API key automatically. No localStorage setup needed.

If opening `docs/wireframes/siphon-c2.html` as a local file instead:

```js
localStorage.setItem('c2:apiUrl', 'http://localhost/api');
location.reload();
```

## Layout

```
deploy/k8s/lab/
├── 00-namespace.yaml            siphon-lab
├── 05-postgres.yaml             Postgres Deployment + Service
├── 06-postgres-secret.yaml      Postgres connection string Secret
├── 10-configmap-overrides.yaml  shared pattern-overrides ConfigMap
├── 15-rbac-roller.yaml          SA + Role + RoleBinding for auto-roll
├── 20-siphon-api.yaml           Deployment (2) + Service (reads SIPHON_API_KEY)
├── 25-siphon-ui.yaml            Deployment (1) + Service (nginx static files)
├── 30-siphon-fs.yaml            Deployment (1) + Service (reads SIPHON_API_KEY)
├── 35-siphon-nginx.yaml         Deployment (1) + Service (reverse proxy, ConfigMap-mounted config)
├── 40-ingress.yaml              nginx-ingress: all traffic → siphon-nginx
├── evadex-lab.yaml              evadex bridge Deployment + Service
├── nginx-config/nginx.conf      source template for siphon-nginx ConfigMap
│                                (API key placeholder __SIPHON_API_KEY__ substituted by lab-up.sh)
└── kind-cluster.yaml            kind single-node spec w/ port 80 forward
```

### API key and nginx ConfigMap

`lab-up.sh` generates a stable lab API key on first run and stores it in
a k8s Secret (`siphon-api-auth`). On re-runs the key is read from the
existing secret so the same key is used across restarts. The key is then
substituted into `nginx-config/nginx.conf` and applied as the
`siphon-nginx-config` ConfigMap.

`siphon-api` and `siphon-fs` read `SIPHON_API_KEY` from the same secret,
so bearer auth is enforced. `siphon-nginx` injects the `Authorization`
header for `/api/*` and `/fs/*` requests, so the C2 console works without
any localStorage setup.

Both Deployments mount the same `siphon-overrides` ConfigMap at
`/etc/siphon/overrides.json`. Phase 3 teaches the scanner to layer
that file on top of the compile-time patterns; Phase 4 adds the
admin-console "Apply" flow that writes the ConfigMap; Phase 6's
auto-roll (`POST /v1/overrides/roll`) patches each Deployment's
annotations to trigger a rolling restart so the new overrides take
effect without `kubectl` access.

### Auto-roll RBAC

`15-rbac-roller.yaml` creates a `siphon-api` ServiceAccount + a
namespace-scoped Role that grants `get`/`patch` on the two
Deployments by name. The siphon-api Deployment pins
`serviceAccountName: siphon-api` so the pod's in-cluster client
picks up the mounted token. The roller cannot touch anything else:
different namespace, different Deployment, different resource kind
all return 403.

The `Dockerfile.api` enables `--features k8s-roll` so the endpoint
ships compiled in. Without the feature the endpoint responds 501.

## Tear it down

```bash
./scripts/lab-down.sh
```

Leaves the `siphon-api:lab` and `siphon-fs:lab` Docker images behind —
`docker rmi siphon-api:lab siphon-fs:lab` if you want the disk back.
