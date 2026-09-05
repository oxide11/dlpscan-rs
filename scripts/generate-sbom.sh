#!/usr/bin/env bash
# Generate a CycloneDX 1.6 SBOM for every shipped artifact.
#
# WHY ONE PER ARTIFACT, NOT ONE FOR THE REPO
#
# There is no single bill of materials for this workspace. Each binary links
# a different closure, and the differences are large and security-relevant:
# siphon-api links none of rusqlite, unrar, rxing or the image codecs, while
# siphon-fs and siphon-milter link all of them. A workspace-wide SBOM would
# claim siphon-api ships a bundled SQLite and a C RAR decoder that it does
# not, which is worse than no SBOM — it would send an auditor chasing a
# vulnerability in a component that image never contained.
#
# The resolution has to be per-package for the same reason. `cargo metadata`
# and `cargo tree --workspace` unify features across every member, which
# reports exactly that false picture. `cargo tree -p <pkg>` does not.
#
# DETERMINISM
#
# Output is byte-stable for a given Cargo.lock: components are sorted and no
# timestamp is written unless --timestamp is passed. That is deliberate. An
# SBOM that changes on every run cannot be diffed, so nobody reads the diff,
# so it stops being a review artifact and becomes a file that exists. With
# stable output, `--check` can fail CI when the SBOM no longer matches the
# lockfile, which is what keeps it honest.
#
# Pass --timestamp when producing a release artifact, where "when was this
# generated" is part of the record.
#
# Usage:
#   scripts/generate-sbom.sh              # regenerate sbom/
#   scripts/generate-sbom.sh --check      # verify sbom/ is current (CI)
#   scripts/generate-sbom.sh --timestamp  # release artifact, with a date

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# The platform the images actually run on. Without this, the tree carries
# Windows and wasm crates that no shipped artifact contains — they reach the
# lockfile through dev- and build-dependencies only, and listing them as
# shipped components is a false positive an auditor has to chase down.
TARGET="${SBOM_TARGET:-x86_64-unknown-linux-gnu}"

# Every artifact that leaves the build. siphon-mail is a library rather than
# a binary, but siphon-api and siphon-milter both link it and it owns the
# database schema, so it gets its own document.
ARTIFACTS=(
    siphon
    siphon-core
    siphon-api
    siphon-fs
    siphon-icap
    siphon-launcher
    siphon-mail
    siphon-milter
)

MODE="write"
WITH_TIMESTAMP=0
for arg in "$@"; do
    case "$arg" in
        --check)     MODE="check" ;;
        --timestamp) WITH_TIMESTAMP=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

OUT_DIR="sbom"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${OUT_DIR}"

for pkg in "${ARTIFACTS[@]}"; do
    # -e normal excludes dev- and build-dependencies: a test harness and a
    # proc-macro that ran at compile time are not components of the shipped
    # artifact, and listing them inflates the attack surface being reported.
    cargo tree \
        --package "${pkg}" \
        --edges normal \
        --target "${TARGET}" \
        --prefix none \
        --format "{p}|{l}|{r}" \
        2>/dev/null \
    | sort -u > "${TMP_DIR}/${pkg}.raw"

    python3 scripts/sbom_render.py \
        --package "${pkg}" \
        --input "${TMP_DIR}/${pkg}.raw" \
        --target "${TARGET}" \
        $( [ "${WITH_TIMESTAMP}" = "1" ] && echo --timestamp ) \
        > "${TMP_DIR}/${pkg}.cdx.json"
done

python3 scripts/sbom_render.py --summary \
    --input-dir "${TMP_DIR}" \
    --target "${TARGET}" \
    > "${TMP_DIR}/INVENTORY.md"

if [ "${MODE}" = "check" ]; then
    fail=0
    for pkg in "${ARTIFACTS[@]}"; do
        if ! diff -q "${TMP_DIR}/${pkg}.cdx.json" "${OUT_DIR}/${pkg}.cdx.json" >/dev/null 2>&1; then
            echo "  STALE  ${OUT_DIR}/${pkg}.cdx.json"
            fail=1
        fi
    done
    if ! diff -q "${TMP_DIR}/INVENTORY.md" "${OUT_DIR}/INVENTORY.md" >/dev/null 2>&1; then
        echo "  STALE  ${OUT_DIR}/INVENTORY.md"
        fail=1
    fi
    if [ "${fail}" = "1" ]; then
        echo
        echo "SBOM is out of date with Cargo.lock. Run: scripts/generate-sbom.sh"
        exit 1
    fi
    echo "SBOM is current for ${#ARTIFACTS[@]} artifacts ✓"
    exit 0
fi

for pkg in "${ARTIFACTS[@]}"; do
    cp "${TMP_DIR}/${pkg}.cdx.json" "${OUT_DIR}/${pkg}.cdx.json"
done
cp "${TMP_DIR}/INVENTORY.md" "${OUT_DIR}/INVENTORY.md"

echo "wrote ${#ARTIFACTS[@]} CycloneDX documents + INVENTORY.md to ${OUT_DIR}/"
