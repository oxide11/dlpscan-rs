#!/usr/bin/env bash
# scripts/check-semver.sh — run `cargo semver-checks check-release`
# against any library crate that has source changes staged.
#
# Per CLAUDE.md, cargo-semver-checks gates MAJOR bumps on detected
# public-API breaks. The pre-commit hook calls this script; CI can
# call it too. Warn-only by default — set CHECK_SEMVER_STRICT=1 to
# fail the hook on detected breaks.
#
# Only library crates can be checked (cargo-semver-checks operates
# on rustdoc JSON, which only bin-less crates produce by default).
# In this workspace that's `siphon-core` and the root `siphon`
# crate; the bin-only crates (`siphon-api`, `siphon-fs`,
# `siphon-launcher`) are skipped.
#
# Usage:
#   scripts/check-semver.sh           # check staged changes
#   scripts/check-semver.sh --all     # ignore git, check both libs
#   CHECK_SEMVER_STRICT=1 …           # exit 1 on findings
#
# Setup:
#   cargo install cargo-semver-checks --locked
#   ./scripts/install-hooks.sh        # wires this in as a hook

set -Eeuo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CHECK_ALL=false
case "${1:-}" in
    --all) CHECK_ALL=true ;;
    -h|--help)
        sed -n '1,22p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
esac

if ! command -v cargo-semver-checks >/dev/null; then
    echo "▶ cargo-semver-checks not installed — skipping"
    echo "  install: cargo install cargo-semver-checks --locked"
    exit 0
fi

# crate-name → (cargo-package-flag, source-prefix, tag-prefix)
declare -A LIB_PACKAGES=(
    [siphon-core]="-p siphon-core|crates/siphon-core/|siphon-core-v"
    [siphon]="-p siphon|src/|siphon-cli-v"
)

# --- pick which crates to check ----------------------------------

CHECK=()
if ${CHECK_ALL}; then
    CHECK=(siphon-core siphon)
else
    # Walk the staged file list; if any file under a lib crate's
    # source prefix is staged, mark that crate for checking. We
    # only care about Rust source — Cargo.toml / Cargo.lock changes
    # alone don't shift the API surface.
    STAGED="$(git diff --cached --name-only --diff-filter=ACMR | grep -E '\.rs$' || true)"
    if [[ -z "${STAGED}" ]]; then
        exit 0   # nothing Rust changed
    fi
    for crate in "${!LIB_PACKAGES[@]}"; do
        IFS='|' read -r _flag prefix _tag <<<"${LIB_PACKAGES[$crate]}"
        if echo "${STAGED}" | grep -q "^${prefix}"; then
            CHECK+=("${crate}")
        fi
    done
fi

if (( ${#CHECK[@]} == 0 )); then
    exit 0
fi

# --- run the check ------------------------------------------------

STRICT="${CHECK_SEMVER_STRICT:-0}"
EXIT_CODE=0
for crate in "${CHECK[@]}"; do
    IFS='|' read -r flag _prefix tag_prefix <<<"${LIB_PACKAGES[$crate]}"
    BASELINE="$(git tag --list "${tag_prefix}*" --sort=-v:refname | head -n1)"
    if [[ -z "${BASELINE}" ]]; then
        echo "▶ ${crate}: no ${tag_prefix}* tag yet — skipping (no baseline)"
        continue
    fi
    echo "▶ ${crate}: cargo semver-checks vs ${BASELINE}"
    # shellcheck disable=SC2086
    if ! cargo semver-checks check-release ${flag} \
            --baseline-rev "${BASELINE}" 2>&1; then
        if [[ "${STRICT}" == "1" ]]; then
            EXIT_CODE=1
            echo "  ✖ ${crate}: breaking changes detected and CHECK_SEMVER_STRICT=1"
        else
            echo "  ⚠ ${crate}: breaking changes detected"
            echo "     bump siphon-core MAJOR (or siphon-cli MAJOR) before merging,"
            echo "     OR re-run with CHECK_SEMVER_STRICT=1 once you've decided"
        fi
    fi
done

exit "${EXIT_CODE}"
