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

Once `lab-up.sh` reports ready:

```bash
curl http://localhost/api/health   # siphon-api
curl http://localhost/fs/health    # siphon-fs

# text scan (via siphon-api)
curl -s -X POST http://localhost/api/scan \
  -H 'content-type: application/json' \
  -d '{"text":"Email: alice@example.com · card 4242 4242 4242 4242"}'

# file scan (via siphon-fs)
curl -s -X POST http://localhost/fs/scan -F "file=@/path/to/file.pdf"
```

## Point the admin console at it

In the browser console on `docs/wireframes/siphon-c2.html`:

```js
localStorage.setItem('c2:apiUrl', 'http://localhost/api');
location.reload();
```

## Layout

```
deploy/k8s/lab/
├── 00-namespace.yaml            siphon-lab
├── 10-configmap-overrides.yaml  shared pattern-overrides ConfigMap
├── 15-rbac-roller.yaml          SA + Role + RoleBinding for auto-roll
├── 20-siphon-api.yaml           Deployment (2) + Service
├── 30-siphon-fs.yaml            Deployment (1) + Service
├── 40-ingress.yaml              nginx-ingress: /api/*, /fs/*
└── kind-cluster.yaml            kind single-node spec w/ port 80 forward
```

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
