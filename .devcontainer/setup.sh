#!/usr/bin/env bash
# Devcontainer bootstrap for Siphon.
#
# The universal image already has Docker, Node, Rust, pnpm. We
# add the k8s tooling needed to exercise `deploy/helm/siphon/`
# end-to-end inside a Codespace:
#
#   k3d      — lightweight k8s-in-Docker (faster boot than minikube)
#   kubectl  — chart install + port-forward + logs
#   helm     — install the Siphon chart
#
# Deployment itself isn't run here — see scripts/codespace-deploy.sh
# for a single-command build-and-install.

set -Eeuo pipefail

echo "▶ Installing k8s tooling…"

# ---- kubectl ---------------------------------------------------------------
if ! command -v kubectl >/dev/null; then
    K8S_VER="$(curl -sL https://dl.k8s.io/release/stable.txt)"
    curl -sLo /tmp/kubectl "https://dl.k8s.io/release/${K8S_VER}/bin/linux/amd64/kubectl"
    sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl
fi

# ---- helm ------------------------------------------------------------------
if ! command -v helm >/dev/null; then
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# ---- k3d -------------------------------------------------------------------
# k3d boots a kind-ish cluster inside Docker-in-Docker in ~10s.
# Lighter than minikube for Codespaces where the VM is already a VM.
if ! command -v k3d >/dev/null; then
    curl -sL https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
fi

# ---- UI deps --------------------------------------------------------------
# pnpm is in the universal image but the lockfile hasn't been
# installed against this workspace copy yet.
if [[ -d ui && -f ui/package.json ]]; then
    echo "▶ Installing UI deps (pnpm install --frozen-lockfile)…"
    (cd ui && pnpm install --frozen-lockfile) || true
fi

# ---- Cargo dep cache warm --------------------------------------------------
# Fetch without compiling so the first `cargo build` inside the
# Codespace doesn't need to pull the dep tree over the Codespace's
# network too.
#
# The universal:2 image ships Rust at /usr/local/cargo but the
# env file isn't auto-sourced inside non-interactive shells like
# `bash .devcontainer/setup.sh`. Source it explicitly so `cargo`
# resolves. Silent if missing so this still runs on future base
# images that expose cargo differently.
if [[ -f /usr/local/cargo/env ]]; then
    # shellcheck disable=SC1091
    . /usr/local/cargo/env
fi
echo "▶ Warming Cargo registry (cargo fetch)…"
cargo fetch || echo "  (cargo unavailable in postCreate shell — skipping; deploys build inside Docker anyway)"

# ---- Persist PATH in shell rc ---------------------------------------------
# Interactive shells in the Codespace already source cargo via the
# image's /etc/bash.bashrc, but `bash -c` / one-shot scripts don't.
# Adding a tiny export to the user's .bashrc keeps `cargo` +
# `kubectl` + `helm` + `k3d` on PATH for every subsequent shell.
RC="${HOME}/.bashrc"
if [[ -w "${RC}" ]] && ! grep -q 'siphon-devcontainer' "${RC}"; then
    cat >>"${RC}" <<'RCBLOCK'

# siphon-devcontainer: make cargo + k8s tooling visible in every shell
[ -f /usr/local/cargo/env ] && . /usr/local/cargo/env
RCBLOCK
fi

cat <<'EOF'

✅ Devcontainer ready.

Next steps — stand up the Siphon stack in a k3d cluster:

  ./scripts/codespace-deploy.sh

Then browse the forwarded 8080 port (Codespaces shows the URL in
the Ports panel) and you'll land on the UI's /ui/ SPA.

Rebuild + redeploy after edits:

  ./scripts/codespace-deploy.sh --rebuild

Tear down the cluster when done:

  k3d cluster delete siphon

EOF
