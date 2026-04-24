#!/usr/bin/env bash
# Bump Siphon's SemVer across every place the version is declared.
#
# Usage:
#   scripts/bump-version.sh 2.2.0
#
# Updates, in a single transaction:
#   - Cargo.toml              ([package] version)
#   - crates/*/Cargo.toml     ([package] version)
#   - ui/package.json         (version)
#   - deploy/helm/dlpscan/Chart.yaml      (appVersion)
#   - deploy/helm/dlpscan/values.yaml     (image.tag)
#   - Cargo.lock              (regenerated via `cargo update --workspace`)
#   - ui/pnpm-lock.yaml       (regenerated so Node's lockfile matches)
#
# Does NOT bump the Helm Chart.yaml `version:` field — that's the
# chart's own SemVer, which evolves independently from the image
# it deploys. Bump it by hand when the chart templates change.
#
# Prints a diff summary at the end. Run inside a clean working tree
# so `git diff` clearly attributes the change.

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <new-version>" >&2
    exit 64
fi

NEW_VERSION="$1"

if ! [[ "${NEW_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?(\+[A-Za-z0-9.-]+)?$ ]]; then
    echo "error: '${NEW_VERSION}' is not a valid SemVer (MAJOR.MINOR.PATCH[-pre][+build])" >&2
    exit 64
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CURRENT_VERSION="$(awk -F\" '/^version = /{print $2; exit}' Cargo.toml)"

if [[ "${CURRENT_VERSION}" == "${NEW_VERSION}" ]]; then
    # Root is already there — still run the downstream updates in
    # case a prior bump failed partway and left drift. The
    # per-file awk passes below are idempotent.
    echo "root already at ${NEW_VERSION} — re-syncing downstream files"
else
    echo "bumping ${CURRENT_VERSION} → ${NEW_VERSION}"
fi

# --- Cargo.toml files -------------------------------------------------------
# The `[package] version =` line is always the FIRST `version = ` in
# each Cargo.toml (dep versions come later), so a scoped sed suffices.

update_cargo_toml() {
    local f="$1"
    # Only the first match — portable BSD/GNU sed trick is to pipe
    # through awk instead, which keeps this script working on macOS
    # without -i '' quoting.
    awk -v v="${NEW_VERSION}" '
        !bumped && /^version = "/ {
            sub(/"[^"]+"/, "\"" v "\"")
            bumped = 1
        }
        { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

update_cargo_toml Cargo.toml
for c in crates/*/Cargo.toml; do
    update_cargo_toml "$c"
done

# --- ui/package.json --------------------------------------------------------
# awk's sub() doesn't do backrefs, and macOS BSD sed has quoting
# quirks with `-i`. Portable compromise: use a POSIX sed with no
# in-place flag and redirect to a temp file. The `-E` flag is in
# POSIX.1-2024 and works on both GNU and BSD sed.
sed -E "s/(\"version\"[[:space:]]*:[[:space:]]*)\"[^\"]+\"/\\1\"${NEW_VERSION}\"/" \
    ui/package.json > ui/package.json.tmp && mv ui/package.json.tmp ui/package.json

# --- Helm chart -------------------------------------------------------------
awk -v v="${NEW_VERSION}" '
    /^appVersion:/ { print "appVersion: \"" v "\""; next }
    { print }
' deploy/helm/dlpscan/Chart.yaml > deploy/helm/dlpscan/Chart.yaml.tmp \
    && mv deploy/helm/dlpscan/Chart.yaml.tmp deploy/helm/dlpscan/Chart.yaml

awk -v v="${NEW_VERSION}" '
    in_image && /^[[:space:]]+tag:/ {
        sub(/"[^"]+"/, "\"" v "\"")
        in_image = 0
    }
    /^image:/ { in_image = 1 }
    /^[^[:space:]]/ && !/^image:/ { in_image = 0 }
    { print }
' deploy/helm/dlpscan/values.yaml > deploy/helm/dlpscan/values.yaml.tmp \
    && mv deploy/helm/dlpscan/values.yaml.tmp deploy/helm/dlpscan/values.yaml

# --- Regenerate lockfiles ---------------------------------------------------
# Cargo.lock: cargo update -w rewrites just the workspace crates'
# `version = X.Y.Z` lines so the lockfile stays in sync without
# touching any transitive deps.
if command -v cargo >/dev/null 2>&1; then
    cargo update --workspace --quiet
else
    echo "warn: cargo not found — Cargo.lock not regenerated" >&2
fi

# pnpm-lock.yaml: pnpm is the source of truth for the UI tree. If
# it's missing, skip — the developer can regenerate next time they
# run `pnpm install`.
if command -v pnpm >/dev/null 2>&1; then
    (cd ui && pnpm install --lockfile-only --silent)
else
    echo "warn: pnpm not found — ui/pnpm-lock.yaml not regenerated" >&2
fi

# --- Summary ---------------------------------------------------------------
echo
echo "Bumped to ${NEW_VERSION}. Diff summary:"
git diff --stat Cargo.toml crates/*/Cargo.toml ui/package.json \
    deploy/helm/dlpscan/Chart.yaml deploy/helm/dlpscan/values.yaml 2>/dev/null \
    || true
echo
echo "Next steps:"
echo "  git diff            # review the full change"
echo "  git commit -am \"chore(release): ${NEW_VERSION}\""
echo "  git tag -a v${NEW_VERSION} -m '${NEW_VERSION}'"
