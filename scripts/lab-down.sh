#!/usr/bin/env bash
# Tear down the Siphon k8s lab created by scripts/lab-up.sh.
# Leaves the Docker images behind (siphon-api:lab, siphon-fs:lab) —
# remove them manually with `docker rmi` if you need the disk.
set -Eeuo pipefail

CLUSTER_NAME="siphon-lab"

if ! command -v kind >/dev/null; then
  printf '\033[1;31merror:\033[0m kind not on PATH\n' >&2
  exit 1
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  printf "cluster '%s' is already gone\n" "$CLUSTER_NAME"
  exit 0
fi

printf 'deleting kind cluster %s...\n' "$CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME"
printf 'done.\n'
