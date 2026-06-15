#!/usr/bin/env bash
# Siphon k8s lab — stand up a single-node kind cluster with the full
# stack: siphon-api, siphon-fs, postgres, evadex bridge, nginx ingress.
# Idempotent: safe to run against an existing cluster (re-applies
# manifests and re-rolls Deployments picking up any new images).
#
# Prereqs:
#   · docker    running
#   · kind      https://kind.sigs.k8s.io/docs/user/quick-start/
#   · kubectl   >= 1.27
#
# On a MacBook Air the full cluster (2 api + 1 fs + 1 postgres +
# 1 evadex + nginx-ingress) sits around ~2.5GB RAM.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVADEX_ROOT="$(cd "${REPO_ROOT}/../evadex" 2>/dev/null && pwd || true)"
CLUSTER_NAME="siphon-lab"
CLUSTER_SPEC="${REPO_ROOT}/deploy/k8s/lab/kind-cluster.yaml"
MANIFESTS="${REPO_ROOT}/deploy/k8s/lab"
API_IMAGE="siphon-api:lab"
FS_IMAGE="siphon-fs:lab"
EVADEX_IMAGE="evadex:lab"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0 · prereqs ──────────────────────────────────────────────────
for bin in docker kind kubectl; do
  command -v "$bin" >/dev/null || die "missing required tool: $bin"
done
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# ── 1 · cluster ──────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  bold "[1/8] kind cluster '${CLUSTER_NAME}' already exists — reusing"
else
  bold "[1/8] creating kind cluster '${CLUSTER_NAME}'"
  kind create cluster --name "$CLUSTER_NAME" --config "$CLUSTER_SPEC"
fi
kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null

# ── 2 · nginx ingress controller ─────────────────────────────────
if ! kubectl get ns ingress-nginx >/dev/null 2>&1; then
  bold "[2/8] installing nginx-ingress-controller"
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
else
  bold "[2/8] nginx-ingress-controller already installed"
fi
# `kubectl apply` returns before the controller pod is actually
# scheduled, so wait for the Deployment object to appear first, then
# let rollout status handle the ready-state check.
for _ in $(seq 1 30); do
  kubectl -n ingress-nginx get deployment ingress-nginx-controller >/dev/null 2>&1 && break
  sleep 1
done
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=180s

# ── 3 · build siphon images ──────────────────────────────────────
bold "[3/8] building ${API_IMAGE} + ${FS_IMAGE}"
docker build -t "$API_IMAGE" -f "${REPO_ROOT}/deploy/Dockerfile.api" "$REPO_ROOT"
docker build -t "$FS_IMAGE"  -f "${REPO_ROOT}/deploy/Dockerfile.fs"  "$REPO_ROOT"

# ── 4 · build evadex image ───────────────────────────────────────
bold "[4/8] building ${EVADEX_IMAGE}"
if [[ -z "$EVADEX_ROOT" || ! -d "$EVADEX_ROOT" ]]; then
  die "evadex repo not found at ../evadex — clone it alongside dlpscan-rs"
fi
docker build -t "$EVADEX_IMAGE" \
  -f "${EVADEX_ROOT}/deploy/Dockerfile.bridge" \
  "$EVADEX_ROOT"

# ── 5 · load images into kind ────────────────────────────────────
bold "[5/8] loading images into kind cluster"
kind load docker-image "$API_IMAGE"    --name "$CLUSTER_NAME"
kind load docker-image "$FS_IMAGE"     --name "$CLUSTER_NAME"
kind load docker-image "$EVADEX_IMAGE" --name "$CLUSTER_NAME"

# ── 6 · apply manifests ──────────────────────────────────────────
bold "[6/8] applying lab manifests"
kubectl apply -f "$MANIFESTS"
# Bounce siphon-api and siphon-fs so they pick up any freshly-loaded
# image even when the tag didn't change (imagePullPolicy: IfNotPresent
# won't re-pull; an annotation flip triggers a roll).
kubectl -n siphon-lab rollout restart deployment/siphon-api
kubectl -n siphon-lab rollout restart deployment/siphon-fs
kubectl -n siphon-lab rollout restart deployment/evadex

# ── 7 · wait for postgres ────────────────────────────────────────
bold "[7/8] waiting for postgres"
kubectl -n siphon-lab rollout status deployment/postgres --timeout=120s

# ── 8 · wait for all rollouts ────────────────────────────────────
bold "[8/8] waiting for rollouts"
kubectl -n siphon-lab rollout status deployment/siphon-api --timeout=120s
kubectl -n siphon-lab rollout status deployment/siphon-fs  --timeout=120s
kubectl -n siphon-lab rollout status deployment/evadex     --timeout=120s

# ── health summary ───────────────────────────────────────────────
printf '\n'
bold "Lab is up."
printf '\n'

# Pod table
kubectl get pods -n siphon-lab

printf '\n'
printf 'Endpoints:\n'
printf '  siphon-api  → http://localhost/api/health\n'
printf '  siphon-fs   → http://localhost/fs/health\n'
printf '  evadex      → http://localhost/evadex/healthz\n'
printf '\n'

# Postgres ready check (runs inside the postgres pod)
PG_STATUS="$(kubectl exec -n siphon-lab deploy/postgres -- \
  pg_isready -U siphon -d siphon 2>/dev/null && echo ready || echo NOT READY)"
printf 'Postgres:     %s\n' "$PG_STATUS"

printf '\n'
printf 'Admin console (siphon-c2.html) — set localStorage key:\n'
printf "  c2:apiUrl = 'http://localhost/api'\n"
printf '\n'
printf 'Tear down with: scripts/lab-down.sh\n'
