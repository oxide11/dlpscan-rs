# Testing Siphon in a Codespace

This walks through standing up the full Siphon stack — siphon-api,
siphon-fs, the Next.js SPA, Authelia, and the Nginx reverse proxy
— inside a GitHub Codespace, using the `deploy/helm/siphon` chart.

The environment is fully scripted. End-to-end first-run time is
~10 minutes on a default 4-core Codespace (most of that is `cargo
build` inside the Dockerfiles). Subsequent iterations land in ~1
minute.

## Why k3d over minikube

The shipped `.devcontainer/` uses **k3d** (kind-ish, but lighter).
Reasons:

- Codespaces is already a VM. Running another VM inside it
  (minikube's default) doubles resource use. k3d runs Kubernetes
  directly as a Docker container, which is what the devcontainer
  feature already gives you.
- Cold-boot time is ~10 s vs. ~90 s for minikube.
- `k3d image import` reloads locally-built images faster than
  minikube's `image load`.

If you already have minikube workflows and prefer them, skip this
doc — the Helm chart doesn't care which cluster-in-a-box backs it.

## One-time setup

1. Push your branch, then **Code → Create codespace on <branch>**
   from the GitHub UI.
2. Wait for the terminal banner that ends with "✅ Devcontainer
   ready." (the `postCreateCommand` runs `.devcontainer/setup.sh`
   automatically — kubectl, helm, k3d, pnpm deps, cargo fetch).

## Stand up the stack

```sh
./scripts/codespace-deploy.sh
```

First run: builds three images (siphon-api, siphon-fs,
siphon-nginx + SPA), creates a k3d cluster named `siphon`, imports
the images, generates dev secrets, and runs `helm upgrade --install
siphon ./deploy/helm/siphon` pinned at those `:dev` tags. Waits
until every pod is Ready before printing the access hint.

When the script exits you'll see something like:

```
NAME                                READY   STATUS    RESTARTS
siphon-siphon-api-7c5b...-abcde     1/1     Running   0
siphon-siphon-fs-6f9a...-xyz12      1/1     Running   0
siphon-nginx-7aaa...-qwert          1/1     Running   0
siphon-authelia-8b9c...-mnbvc       1/1     Running   0

✅ Siphon stack is live in namespace "siphon".
Cluster LB maps to localhost:8080...
```

The Codespaces **Ports** panel pops up a forwarded URL for port
8080. Click it and append `/ui/` to reach the SPA. Everything else
routes through Nginx:

| Path | Goes to |
|---|---|
| `/ui/` | Next.js SPA (Pods, Overview, Scan, Findings) |
| `/api/` | siphon-api REST endpoints (gated on the dev API key) |
| `/auth/` | Authelia login + OIDC endpoints |
| `/fs/` | siphon-fs multipart upload |

## Iterate

After edits to siphon-* source:

```sh
./scripts/codespace-deploy.sh --rebuild
```

Rebuilds images, re-imports, `helm upgrade`s. The existing PVC
for Authelia persists so you don't lose session data on redeploy.

After edits to the Helm chart only (no image rebuild needed):

```sh
helm -n siphon upgrade siphon ./deploy/helm/siphon \
    --reuse-values
```

## Debug

Pods stuck in `Pending`:

```sh
kubectl -n siphon describe pod <name>
```

Usually it's a missing image (`ImagePullBackOff` — you changed
image.tag without rebuilding) or a PVC with no available storage
class (k3d's default is `local-path`, which should be there by
default).

Authelia can't start:

```sh
kubectl -n siphon logs deploy/siphon-authelia
```

First-time runs usually succeed, but a rogue `configYaml` value
(malformed YAML, placeholder RSA key) shows up here.

siphon-api can't list pods (Ops UI shows "Pod discovery
unavailable"):

```sh
kubectl -n siphon auth can-i list pods \
  --as=system:serviceaccount:siphon:siphon-siphon-api
# → should print `yes`
```

If `no`, the RBAC Role didn't install correctly. Re-running
`./scripts/codespace-deploy.sh` should fix it; check the
`serviceaccount-api.yaml` template if it doesn't.

## Tear down

```sh
./scripts/codespace-deploy.sh --clean
```

or the longer form:

```sh
helm -n siphon uninstall siphon
kubectl delete namespace siphon
k3d cluster delete siphon
```

Deleting the Codespace itself removes everything.

## Gotchas

- **First build is slow.** rav1e + arrow + parquet have heavy
  codegen. The Dockerfiles cap `CARGO_BUILD_JOBS=2` to stay under
  Codespaces' memory limit, so expect ~5 min per image on first
  build. Subsequent builds hit the cargo cache and take ~30 s.
- **Default Codespace machine is 4 CPU / 8 GiB.** Enough for a
  single-replica k3d cluster. Scale siphon-api up to 3 replicas
  (`--set api.replicaCount=3`) and you'll OOM; bump the Codespace
  to 8 CPU / 16 GiB first.
- **The script tags images `:dev`, not `:2.1.0`.** That's
  intentional — you don't want your Codespace pulling the
  published GHCR image over the chart's default tag. The
  `--set image.tag=dev` overrides in the script stay in lockstep
  with the `docker build -t siphon-*:dev` calls.
- **Ingress host is `siphon.local`.** You browse via localhost +
  the forwarded port, so the `Host:` header doesn't matter — the
  k3d LB routes on port alone. If you want real DNS, set
  `/etc/hosts` or the Codespace's hostname to `siphon.local`.
