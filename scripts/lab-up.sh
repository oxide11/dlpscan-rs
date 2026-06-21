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
UI_IMAGE="siphon-ui:lab"
EVADEX_IMAGE="evadex:lab"
BUILD=true; [[ "${1:-}" == "--no-build" ]] && BUILD=false

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0 · prereqs ──────────────────────────────────────────────────
for bin in docker kind kubectl; do
  command -v "$bin" >/dev/null || die "missing required tool: $bin"
done
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# ── 1 · cluster ──────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  bold "[1/9] kind cluster '${CLUSTER_NAME}' already exists — reusing"
else
  bold "[1/9] creating kind cluster '${CLUSTER_NAME}'"
  kind create cluster --name "$CLUSTER_NAME" --config "$CLUSTER_SPEC"
fi
kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null

# ── 2 · nginx ingress controller ─────────────────────────────────
if ! kubectl get ns ingress-nginx >/dev/null 2>&1; then
  bold "[2/9] installing nginx-ingress-controller"
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
else
  bold "[2/9] nginx-ingress-controller already installed"
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
if $BUILD; then
bold "[3/9] building ${API_IMAGE} + ${FS_IMAGE} + ${UI_IMAGE}"
docker build -t "$API_IMAGE" -f "${REPO_ROOT}/deploy/Dockerfile.api" "$REPO_ROOT"
docker build -t "$FS_IMAGE"  -f "${REPO_ROOT}/deploy/Dockerfile.fs"  "$REPO_ROOT"
docker build -t "$UI_IMAGE"  -f "${REPO_ROOT}/deploy/Dockerfile.ui"  "$REPO_ROOT"
fi

# ── 4 · build evadex image ───────────────────────────────────────
if $BUILD; then
bold "[4/9] building ${EVADEX_IMAGE}"
if [[ -z "$EVADEX_ROOT" || ! -d "$EVADEX_ROOT" ]]; then
  die "evadex repo not found at ../evadex — clone it alongside dlpscan-rs"
fi
docker build -t "$EVADEX_IMAGE" \
  -f "${EVADEX_ROOT}/deploy/Dockerfile.bridge" \
  "$EVADEX_ROOT"
fi

# ── 5 · load images into kind ────────────────────────────────────
if $BUILD; then
bold "[5/9] loading images into kind cluster"
kind load docker-image "$API_IMAGE"    --name "$CLUSTER_NAME"
kind load docker-image "$FS_IMAGE"     --name "$CLUSTER_NAME"
kind load docker-image "$UI_IMAGE"     --name "$CLUSTER_NAME"
kind load docker-image "$EVADEX_IMAGE" --name "$CLUSTER_NAME"
fi

# ── 6 · API key + nginx configmap ────────────────────────────────
bold "[6/9] setting up API key + nginx configmap"
kubectl -n siphon-lab apply -f "${MANIFESTS}/00-namespace.yaml" >/dev/null 2>&1 || true

# Generate a stable lab API key on first run; read it on re-runs.
if ! kubectl get secret siphon-api-auth -n siphon-lab >/dev/null 2>&1; then
  API_KEY="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)"
  kubectl create secret generic siphon-api-auth \
    --from-literal=api-key="${API_KEY}" \
    -n siphon-lab
  printf 'API key generated and stored in secret siphon-api-auth\n'
else
  API_KEY="$(kubectl get secret siphon-api-auth -n siphon-lab \
    -o jsonpath='{.data.api-key}' | base64 -d)"
  printf 'API key read from existing secret siphon-api-auth\n'
fi

# Build ConfigMap with the real API key substituted in.
TMP_NGINX="$(mktemp)"
sed "s|__SIPHON_API_KEY__|${API_KEY}|g" \
  "${REPO_ROOT}/deploy/k8s/lab/nginx-config/nginx.conf" > "$TMP_NGINX"
kubectl create configmap siphon-nginx-config \
  --from-file=nginx.conf="${TMP_NGINX}" \
  -n siphon-lab \
  --dry-run=client -o yaml | kubectl apply -f -
rm -f "$TMP_NGINX"

# ── 7 · apply manifests ──────────────────────────────────────────
bold "[7/9] applying lab manifests"
find "$MANIFESTS" -maxdepth 1 -name "*.yaml" ! -name "kind-cluster.yaml" | sort | xargs -I{} kubectl apply -f {}
# Bounce all deployments so they pick up any freshly-loaded image
# even when the tag didn't change (imagePullPolicy: IfNotPresent
# won't re-pull; an annotation flip triggers a roll).
kubectl -n siphon-lab rollout restart deployment/siphon-api
kubectl -n siphon-lab rollout restart deployment/siphon-fs
kubectl -n siphon-lab rollout restart deployment/siphon-ui
kubectl -n siphon-lab rollout restart deployment/siphon-nginx
kubectl -n siphon-lab rollout restart deployment/evadex

# ── 8 · wait for postgres ────────────────────────────────────────
bold "[8/9] waiting for postgres"
kubectl -n siphon-lab rollout status deployment/postgres --timeout=120s

# ── 9 · wait for all rollouts ────────────────────────────────────
bold "[9/9] waiting for rollouts"
kubectl -n siphon-lab rollout status deployment/siphon-api   --timeout=120s
kubectl -n siphon-lab rollout status deployment/siphon-fs    --timeout=120s
kubectl -n siphon-lab rollout status deployment/siphon-ui    --timeout=120s
kubectl -n siphon-lab rollout status deployment/siphon-nginx --timeout=60s
kubectl -n siphon-lab rollout status deployment/evadex       --timeout=120s

# ── health summary ───────────────────────────────────────────────
printf '\n'
bold "Lab is up."
printf '\n'

# Pod table
kubectl get pods -n siphon-lab

printf '\n'
printf 'Endpoints:\n'
printf '  C2 UI       → http://localhost/ui/\n'
printf '  siphon-api  → http://localhost/api/health\n'
printf '  siphon-fs   → http://localhost/fs/health\n'
printf '  evadex      → http://localhost/evadex/healthz\n'
printf '  nginx proxy → http://localhost/ (siphon-nginx, API key injected)\n'
printf '\n'
printf 'API key: %s\n' "${API_KEY}"
printf '  (stored in secret siphon-api-auth in namespace siphon-lab)\n'
printf '  nginx injects it automatically — no localStorage setup needed\n'
printf '\n'

# Postgres ready check (runs inside the postgres pod)
PG_STATUS="$(kubectl exec -n siphon-lab deploy/postgres -- \
  pg_isready -U siphon -d siphon 2>/dev/null && echo ready || echo NOT READY)"
printf 'Postgres:     %s\n' "$PG_STATUS"

# ── Service health verification ──────────────────────────────────
check_service() {
  local name="$1"
  local url="$2"
  if curl -sf --max-time 5 "$url" > /dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %-15s %s\n' "$name" "$url"
    return 0
  else
    printf '  \033[33m✗\033[0m %-15s %s — not responding\n' "$name" "$url"
    return 1
  fi
}

printf 'Service health:\n'
_all_healthy=true
check_service "siphon-api"  "http://localhost/api/health"    || _all_healthy=false
check_service "siphon-fs"   "http://localhost/fs/health"     || _all_healthy=false
check_service "evadex"      "http://localhost/evadex/healthz" || _all_healthy=false
check_service "siphon-ui"   "http://localhost/ui/"           || _all_healthy=false
printf '\n'
if $_all_healthy; then
  printf '\033[32m✓ All services healthy\033[0m\n'
else
  printf '\033[33m⚠ Some services not yet healthy — they may still be starting.\033[0m\n'
  printf '  Wait a moment and recheck: curl http://localhost/api/health\n'
fi

printf '\n'
printf 'Admin console served at http://localhost/ui/ (or open docs/wireframes/siphon-c2.html locally)\n'
printf 'If using the file:// version, set localStorage key:\n'
printf "  c2:apiUrl = 'http://localhost/api'\n"
printf '\n'
printf 'Tear down with: scripts/lab-down.sh\n'
