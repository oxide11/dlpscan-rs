#!/usr/bin/env bash
# One-command "stand up the Siphon stack" for a Codespace / kind /
# k3d-on-laptop environment. Idempotent: re-running re-installs
# the chart and re-imports images so edits pick up on the next run.
#
# Usage:
#   scripts/codespace-deploy.sh            # first run: build, cluster, install
#   scripts/codespace-deploy.sh --rebuild  # rebuild images + helm upgrade
#   scripts/codespace-deploy.sh --clean    # tear down and start fresh
#
# Opinionated: uses k3d + a namespace called `siphon` + dev-only
# secrets created inline. For production, use your own secret flow
# and point the Helm values at it.

set -Eeuo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-siphon}"
NAMESPACE="${NAMESPACE:-siphon}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

REBUILD=false
CLEAN=false
for arg in "$@"; do
    case "${arg}" in
        --rebuild) REBUILD=true ;;
        --clean)   CLEAN=true ;;
        -h|--help)
            sed -n '1,25p' "$0"
            exit 0
            ;;
        *) echo "unknown flag: ${arg}" >&2; exit 64 ;;
    esac
done

need() { command -v "$1" >/dev/null || { echo "missing: $1 — run .devcontainer/setup.sh" >&2; exit 1; }; }
for bin in docker k3d kubectl helm; do need "${bin}"; done

# --- 1. Tear down if asked -------------------------------------------------
if ${CLEAN}; then
    echo "▶ Tearing down cluster ${CLUSTER_NAME}…"
    k3d cluster delete "${CLUSTER_NAME}" || true
    exit 0
fi

# --- 2. Cluster ------------------------------------------------------------
if ! k3d cluster list | awk 'NR>1 {print $1}' | grep -qx "${CLUSTER_NAME}"; then
    echo "▶ Creating k3d cluster ${CLUSTER_NAME}…"
    # -p 8080:80@loadbalancer maps the cluster's LB port 80 to
    # localhost:8080 so Codespaces's forwarded-port panel picks it
    # up automatically. If you're running locally and want a
    # different host port, set K3D_HOST_PORT.
    k3d cluster create "${CLUSTER_NAME}" \
        --agents 1 \
        -p "${K3D_HOST_PORT:-8080}:80@loadbalancer" \
        --wait
fi
kubectl config use-context "k3d-${CLUSTER_NAME}" >/dev/null

# --- 3. Build images -------------------------------------------------------
# Always build on first run; also build on --rebuild. Tag as
# siphon-*:dev so the chart values.yaml override below points here.
if ${REBUILD} || [[ -z "$(docker images -q siphon-api:dev 2>/dev/null)" ]]; then
    echo "▶ Building siphon-api (cargo-build inside Dockerfile.api)…"
    docker build \
        -f deploy/Dockerfile.api \
        --build-arg CARGO_BUILD_JOBS=2 \
        -t siphon-api:dev .

    echo "▶ Building siphon-fs…"
    docker build \
        -f deploy/Dockerfile.fs \
        --build-arg CARGO_BUILD_JOBS=2 \
        -t siphon-fs:dev .

    echo "▶ Building siphon-nginx (bundles the Next.js SPA)…"
    docker build \
        -f deploy/nginx/Dockerfile \
        -t siphon-nginx:dev .
fi

# --- 4. Import images into the cluster ------------------------------------
# `--mode=direct` bypasses the default shared-volume tarball path,
# which is broken under Codespaces' Docker-outside-of-Docker
# pattern. k3d silently reports success even when each node fails
# to access the tarball; direct mode docker-execs a `ctr import`
# into each node container instead. Slightly slower, always works.
echo "▶ Importing images into k3d…"
k3d image import -c "${CLUSTER_NAME}" --mode=direct \
    siphon-api:dev \
    siphon-fs:dev \
    siphon-nginx:dev

# --- 5. Namespace + dev secrets ------------------------------------------
kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || \
    kubectl create namespace "${NAMESPACE}"

# siphon-api bearer token. Random, only exists for this cluster.
if ! kubectl -n "${NAMESPACE}" get secret siphon-api-auth >/dev/null 2>&1; then
    echo "▶ Generating dev siphon-api-auth secret…"
    kubectl -n "${NAMESPACE}" create secret generic siphon-api-auth \
        --from-literal=api-key="$(openssl rand -hex 32)"
fi

# Authelia JWT + session + storage seeds.
if ! kubectl -n "${NAMESPACE}" get secret siphon-authelia >/dev/null 2>&1; then
    echo "▶ Generating dev siphon-authelia secret…"
    kubectl -n "${NAMESPACE}" create secret generic siphon-authelia \
        --from-literal=jwt_secret="$(openssl rand -hex 32)" \
        --from-literal=session_secret="$(openssl rand -hex 32)" \
        --from-literal=storage_encryption_key="$(openssl rand -hex 32)"
fi

# --- 6. Helm install/upgrade ---------------------------------------------
#
# Browser-origin resolution. Authelia bakes the cookie Domain= and
# the portal redirect URLs at chart-install time, so they have to
# match whatever the browser types in the URL bar — otherwise the
# portal sets a cookie the browser refuses to send back.
#
#   * GitHub Codespaces: the forwarded port shows up at
#     https://${CODESPACE_NAME}-<port>.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}
#     (typically app.github.dev). Pulled from env.
#   * Local k3d:          browser is on http://localhost:<port>.
#     Cookie domain is `localhost` (no port — browsers reject ports
#     in Set-Cookie Domain=).
#
# ingress.host stays empty in both cases so k3d's Traefik matches
# any Host header. The browser-facing host is carried by
# authelia.cookieDomain + authelia.externalUrl, which only feed the
# Authelia ConfigMap.
#
# devBypass is forced on. This script is explicitly a dev/smoke-test
# entrypoint; there's no user directory seeded, so leaving
# two_factor on just locks everyone out. Production deploys should
# run `helm upgrade` by hand with their own values override and
# devBypass left false (the chart default).
K3D_PORT="${K3D_HOST_PORT:-8080}"
if [[ -n "${CODESPACE_NAME:-}" && -n "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}" ]]; then
    PUBLIC_HOST="${CODESPACE_NAME}-${K3D_PORT}.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
    PUBLIC_ORIGIN="https://${PUBLIC_HOST}"
    echo "▶ Detected Codespace — configuring browser origin ${PUBLIC_ORIGIN}"
else
    PUBLIC_HOST="localhost"
    PUBLIC_ORIGIN="http://localhost:${K3D_PORT}"
fi

echo "▶ Installing chart (helm upgrade --install)…"
helm upgrade --install siphon ./deploy/helm/siphon \
    --namespace "${NAMESPACE}" \
    --set api.image.repository=siphon-api \
    --set api.image.tag=dev \
    --set 'api.image.pullPolicy=IfNotPresent' \
    --set fs.image.repository=siphon-fs \
    --set fs.image.tag=dev \
    --set nginx.image.repository=siphon-nginx \
    --set nginx.image.tag=dev \
    --set api.auth.secretName=siphon-api-auth \
    --set authelia.secretName=siphon-authelia \
    --set ingress.host= \
    --set "authelia.cookieDomain=${PUBLIC_HOST}" \
    --set "authelia.externalUrl=${PUBLIC_ORIGIN}" \
    --set authelia.devBypass=true \
    --set global.imageRegistry= \
    --wait --timeout=5m

BROWSE_URL="${PUBLIC_ORIGIN}"

# helm upgrade doesn't roll a Deployment when the image tag is
# unchanged (we always publish :dev) — so rebuilt images silently
# never reach the running pods. After --rebuild, force a restart
# of every image-backed Deployment so the new binary/config
# actually ships. Chart-only edits (no --rebuild) skip this and
# rely on the chart's own checksum/* annotations (ConfigMap hashes)
# for rollout triggering.
if ${REBUILD}; then
    echo "▶ --rebuild requested — forcing rollout of image-baked deployments…"
    kubectl -n "${NAMESPACE}" rollout restart \
        deploy/siphon-api deploy/siphon-fs deploy/siphon-nginx
    kubectl -n "${NAMESPACE}" rollout status \
        deploy/siphon-api deploy/siphon-fs deploy/siphon-nginx \
        --timeout=3m
fi

# --- 7. Print access hints ------------------------------------------------
echo
kubectl -n "${NAMESPACE}" get pods -o wide
cat <<EOF

✅ Siphon stack is live in namespace "${NAMESPACE}".

Browse (authelia.devBypass=true — no login required):

  ${BROWSE_URL}/ui/          ← Next.js SPA
  ${BROWSE_URL}/api/health
  ${BROWSE_URL}/auth/        ← Authelia portal (bypass mode)

Useful commands:

  kubectl -n ${NAMESPACE} get pods            # list pods
  kubectl -n ${NAMESPACE} logs deploy/siphon-api -f
  kubectl -n ${NAMESPACE} logs deploy/siphon-nginx -f
  kubectl -n ${NAMESPACE} describe pod <name> # debug a pending pod
  helm -n ${NAMESPACE} uninstall siphon       # remove the release

Iterate after code edits:

  ./scripts/codespace-deploy.sh --rebuild

EOF
