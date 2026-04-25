#!/usr/bin/env bash
# scripts/install-hooks.sh — wire the repo's .githooks/ directory
# in as the active git-hooks path for this clone.
#
# Idempotent. Runs `git config core.hooksPath .githooks` and
# chmods every hook executable. The hook bodies are tracked in
# the repo so all developers see the same checks; this one
# command is what makes them active locally.
#
# `.devcontainer/setup.sh` runs this on every Codespace boot, so
# Codespaces users never have to think about it. Local clones
# need it once after the first checkout.

set -Eeuo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

git config core.hooksPath .githooks
chmod +x .githooks/*
echo "▶ git hooks active from .githooks/"
ls -1 .githooks/ | sed 's/^/    /'
