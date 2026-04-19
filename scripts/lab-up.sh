#!/usr/bin/env bash
# Siphon k8s lab — stand up a single-node kind cluster with the
# siphon-api + siphon-fs pods and nginx ingress. Idempotent: safe to
# run against an existing cluster (it'll re-apply manifests and
# re-roll Deployments picking up any new images).
#
# Prereqs:
#   · docker    running
#   · kind      https://kind.sigs.k8s.io/docs/user/quick-start/
#   · kubectl   >= 1.27
#
# On a MacBook Air the full cluster (2 api + 1 fs + nginx-ingress)
# sits around ~2GB RAM.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="siphon-lab"
CLUSTER_SPEC="${REPO_ROOT}/deploy/k8s/lab/kind-cluster.yaml"
MANIFESTS="${REPO_ROOT}/deploy/k8s/lab"
API_IMAGE="siphon-api:lab"
FS_IMAGE="siphon-fs:lab"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0 · prereqs ──────────────────────────────────────────────────
for bin in docker kind kubectl; do
  command -v "$bin" >/dev/null || die "missing required tool: $bin"
done
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# ── 1 · cluster ──────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  bold "[1/6] kind cluster '${CLUSTER_NAME}' already exists — reusing"
else
  bold "[1/6] creating kind cluster '${CLUSTER_NAME}'"
  kind create cluster --name "$CLUSTER_NAME" --config "$CLUSTER_SPEC"
fi
kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null

# ── 2 · nginx ingress controller ─────────────────────────────────
# Standard kind-hosted manifest. `--wait` on the rollout means the
# ingress is ready by the time this block exits.
if ! kubectl get ns ingress-nginx >/dev/null 2>&1; then
  bold "[2/6] installing nginx-ingress-controller"
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
else
  bold "[2/6] nginx-ingress-controller already installed"
fi
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=180s

# ── 3 · build images ─────────────────────────────────────────────
bold "[3/6] building ${API_IMAGE} + ${FS_IMAGE}"
docker build -t "$API_IMAGE" -f "${REPO_ROOT}/deploy/Dockerfile.api" "$REPO_ROOT"
docker build -t "$FS_IMAGE"  -f "${REPO_ROOT}/deploy/Dockerfile.fs"  "$REPO_ROOT"

# ── 4 · load images into kind ────────────────────────────────────
bold "[4/6] loading images into kind cluster"
kind load docker-image "$API_IMAGE" --name "$CLUSTER_NAME"
kind load docker-image "$FS_IMAGE"  --name "$CLUSTER_NAME"

# ── 5 · apply manifests ──────────────────────────────────────────
bold "[5/6] applying lab manifests"
kubectl apply -f "$MANIFESTS"
# Bounce the Deployments so they pick up any freshly-loaded image
# even when the tag didn't change (kind's imagePullPolicy is
# IfNotPresent, so the annotation flip is needed to trigger a roll).
kubectl -n siphon-lab rollout restart deployment/siphon-api
kubectl -n siphon-lab rollout restart deployment/siphon-fs

# ── 6 · wait for rollouts ────────────────────────────────────────
bold "[6/6] waiting for rollouts"
kubectl -n siphon-lab rollout status deployment/siphon-api --timeout=120s
kubectl -n siphon-lab rollout status deployment/siphon-fs  --timeout=120s

printf '\n'
bold "Lab is up."
printf '  siphon-api  → http://localhost/api/health\n'
printf '  siphon-fs   → http://localhost/fs/health\n'
printf '\n'
printf 'Admin console (siphon-c2.html) — set localStorage key:\n'
printf "  c2:apiUrl = 'http://localhost/api'\n"
printf '\n'
printf 'Tear down with: scripts/lab-down.sh\n'
