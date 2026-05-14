#!/usr/bin/env bash
# Fail-fast check: every downstream declaration of a crate's version
# (Dockerfile LABEL, Helm image tag, compose tag) matches the crate's
# own Cargo.toml. Mirrors the "Lockstep updates within one crate"
# table in CLAUDE.md and the dispatch in scripts/bump-version.sh.
#
# What this enforces:
#   * crates/siphon-api/Cargo.toml    == Dockerfile.api LABEL
#                                     == values.yaml `api.image.tag`
#                                     == docker-compose.yml `siphon-api:VER`
#   * crates/siphon-fs/Cargo.toml     == Dockerfile.fs LABEL
#                                     == values.yaml `fs.image.tag`
#                                     == docker-compose.yml `siphon-fs:VER`
#   * Cargo.toml (root `siphon`)      == ui/package.json `version`
#                                     == Chart.yaml `appVersion`
#
# What this deliberately does NOT enforce: per-crate SemVer is the
# project's policy (see CLAUDE.md "Versioning"), so siphon-core,
# siphon-api, siphon-fs, siphon-launcher, and the root crate all carry
# independent versions. The previous version of this script required
# them to be identical and would fail every PR — that policy was
# reverted in favor of per-crate SemVer but this script was never
# updated.
#
# Runs locally before a release wave and in .github/workflows/ci.yml.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

fail=0
checks=0

cargo_version() {
    # First `version = "X.Y.Z"` after the `[package]` header — anchored
    # past the section break so a `[dependencies]` block with a same-
    # named entry can't shadow the package version.
    awk '
        /^\[package\]/ { in_pkg = 1; next }
        /^\[/ { in_pkg = 0 }
        in_pkg && /^version[[:space:]]*=/ {
            gsub(/[^0-9.]/, "")
            print
            exit
        }
    ' "$1"
}

check() {
    local label="$1" expected="$2" actual="$3"
    checks=$((checks + 1))
    if [[ "${actual}" == "${expected}" ]]; then
        printf "  ok   %-55s %s\n" "${label}" "${actual}"
    else
        printf "  MISS %-55s %s (expected %s)\n" "${label}" "${actual}" "${expected}"
        fail=1
    fi
}

# ---------------------------------------------------------------------------
# siphon-api lockstep
# ---------------------------------------------------------------------------
api_ver="$(cargo_version crates/siphon-api/Cargo.toml)"
echo "siphon-api ${api_ver}"

api_dockerfile_ver="$(awk -F\" '/opencontainers\.image\.version/{print $2; exit}' deploy/Dockerfile.api)"
check "  deploy/Dockerfile.api LABEL"              "${api_ver}" "${api_dockerfile_ver}"

# `api.image.tag` lives two levels deep in values.yaml; awk walks the
# block depth-first by tracking the `api:` header and the first
# `image:` under it.
api_values_tag="$(awk '
    /^api:/ { in_api = 1; next }
    /^[a-z]/ { in_api = 0 }
    in_api && /^  image:/ { in_image = 1; next }
    in_api && /^  [a-z]/ { in_image = 0 }
    in_api && in_image && /^    tag:/ {
        gsub(/[" ]|tag:/, "")
        print
        exit
    }
' deploy/helm/siphon/values.yaml)"
check "  deploy/helm/siphon/values.yaml api.image.tag" "${api_ver}" "${api_values_tag}"

api_compose_ver="$(awk -F: '/image:[[:space:]]+siphon-api:/{gsub(/[[:space:]]/,"",$3); print $3; exit}' deploy/docker-compose.yml)"
check "  deploy/docker-compose.yml siphon-api"     "${api_ver}" "${api_compose_ver}"

# ---------------------------------------------------------------------------
# siphon-fs lockstep
# ---------------------------------------------------------------------------
fs_ver="$(cargo_version crates/siphon-fs/Cargo.toml)"
echo "siphon-fs ${fs_ver}"

fs_dockerfile_ver="$(awk -F\" '/opencontainers\.image\.version/{print $2; exit}' deploy/Dockerfile.fs)"
check "  deploy/Dockerfile.fs LABEL"               "${fs_ver}" "${fs_dockerfile_ver}"

fs_values_tag="$(awk '
    /^fs:/ { in_fs = 1; next }
    /^[a-z]/ { in_fs = 0 }
    in_fs && /^  image:/ { in_image = 1; next }
    in_fs && /^  [a-z]/ { in_image = 0 }
    in_fs && in_image && /^    tag:/ {
        gsub(/[" ]|tag:/, "")
        print
        exit
    }
' deploy/helm/siphon/values.yaml)"
check "  deploy/helm/siphon/values.yaml fs.image.tag"  "${fs_ver}" "${fs_values_tag}"

fs_compose_ver="$(awk -F: '/image:[[:space:]]+siphon-fs:/{gsub(/[[:space:]]/,"",$3); print $3; exit}' deploy/docker-compose.yml)"
check "  deploy/docker-compose.yml siphon-fs"      "${fs_ver}" "${fs_compose_ver}"

# ---------------------------------------------------------------------------
# root siphon CLI + UI + Helm appVersion lockstep
# ---------------------------------------------------------------------------
# The root crate's version is the "headline" release label. Chart.yaml's
# own comment pins appVersion to the root crate, and the UI ships
# alongside the CLI so ui/package.json tracks it too.
root_ver="$(cargo_version Cargo.toml)"
echo "siphon (root) ${root_ver}"

ui_ver="$(awk -F\" '/^[[:space:]]*"version":/{print $4; exit}' ui/package.json)"
check "  ui/package.json"                          "${root_ver}" "${ui_ver}"

chart_app_ver="$(awk -F\" '/^appVersion:/{print $2; exit}' deploy/helm/siphon/Chart.yaml)"
check "  deploy/helm/siphon/Chart.yaml appVersion" "${root_ver}" "${chart_app_ver}"

# ---------------------------------------------------------------------------
# siphon-core + siphon-launcher: standalone — no downstream artifacts to
# check. Their versions live only in their own Cargo.toml.
# ---------------------------------------------------------------------------
core_ver="$(cargo_version crates/siphon-core/Cargo.toml)"
launcher_ver="$(cargo_version crates/siphon-launcher/Cargo.toml)"
echo "siphon-core ${core_ver} (standalone)"
echo "siphon-launcher ${launcher_ver} (standalone)"

# ---------------------------------------------------------------------------
echo
if [[ $fail -ne 0 ]]; then
    echo "Versions drift — run scripts/bump-version.sh <target> <new> to re-sync" >&2
    echo "the affected crate's downstream artifacts. ${checks} checks, ${fail} miss." >&2
    exit 1
fi
echo "all ${checks} lockstep checks in sync ✓"
