#!/usr/bin/env bash
# Fail-fast check: every place Siphon's version is declared matches
# the root Cargo.toml's `[package] version`.
#
# Run locally before a release (or any PR that bumps the version),
# and wired into CI via .github/workflows/ci.yml so a drift lands as
# a red check.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Source of truth — the first `version = "..."` in the root manifest.
EXPECTED="$(awk -F\" '/^version = /{print $2; exit}' Cargo.toml)"
echo "expected version: ${EXPECTED}"

fail=0

check() {
    local label="$1" actual="$2"
    if [[ "${actual}" == "${EXPECTED}" ]]; then
        printf "  ok   %-55s %s\n" "${label}" "${actual}"
    else
        printf "  MISS %-55s %s (expected %s)\n" "${label}" "${actual}" "${EXPECTED}"
        fail=1
    fi
}

# --- workspace crates -------------------------------------------------------
for c in crates/*/Cargo.toml; do
    v="$(awk -F\" '/^version = /{print $2; exit}' "$c")"
    check "$c" "${v}"
done

# --- ui/package.json --------------------------------------------------------
v="$(awk -F\" '/^[[:space:]]*"version":/{print $4; exit}' ui/package.json)"
check "ui/package.json" "${v}"

# --- Helm Chart.yaml appVersion --------------------------------------------
# The new siphon chart uses appVersion as the default image tag for
# every first-party component (siphon-api, siphon-fs, siphon-nginx).
# Per-component `image.tag` values in values.yaml are intentionally
# empty strings so they fall back to appVersion — no separate tag
# check needed.
v="$(awk -F\" '/^appVersion:/{print $2; exit}' deploy/helm/siphon/Chart.yaml)"
check "deploy/helm/siphon/Chart.yaml (appVersion)" "${v}"

if [[ $fail -ne 0 ]]; then
    echo
    echo "Versions drift — run scripts/bump-version.sh ${EXPECTED} to re-sync." >&2
    exit 1
fi

echo "all in sync ✓"
