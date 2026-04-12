#!/usr/bin/env bash
#
# Build distributable Linux packages for dlpscan.
#
# Produces:
#   target/debian/dlpscan_<version>_amd64.deb
#   target/generate-rpm/dlpscan-<version>-1.x86_64.rpm
#   target/release-tarball/dlpscan-<version>-x86_64-unknown-linux-gnu.tar.gz
#
# Requires:
#   cargo, rustc (>= 1.75)
#   cargo-deb         (cargo install cargo-deb)
#   cargo-generate-rpm (cargo install cargo-generate-rpm)
#
# Usage:
#   ./packaging/build-packages.sh                # all formats
#   ./packaging/build-packages.sh deb            # only .deb
#   ./packaging/build-packages.sh rpm            # only .rpm
#   ./packaging/build-packages.sh tarball        # only .tar.gz
#
# Features included by default: bin-data,metrics
# Override with FEATURES env var:
#   FEATURES=full ./packaging/build-packages.sh

set -euo pipefail

cd "$(dirname "$0")/.."

FEATURES="${FEATURES:-bin-data,metrics}"
TARGETS="${1:-all}"

VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
ARCH=$(uname -m)
TRIPLE="${ARCH}-unknown-linux-gnu"

echo "==> Building dlpscan v${VERSION} for ${TRIPLE}"
echo "    features: ${FEATURES}"

build_release() {
    echo "==> cargo build --release --features ${FEATURES}"
    cargo build --release --features "${FEATURES}"
}

build_deb() {
    if ! command -v cargo-deb >/dev/null 2>&1; then
        echo "ERROR: cargo-deb not installed. Run: cargo install cargo-deb" >&2
        return 1
    fi
    echo "==> Building .deb package"
    cargo deb --no-build --features "${FEATURES}"
    ls -lh target/debian/*.deb
}

build_rpm() {
    if ! command -v cargo-generate-rpm >/dev/null 2>&1; then
        echo "ERROR: cargo-generate-rpm not installed. Run: cargo install cargo-generate-rpm" >&2
        return 1
    fi
    echo "==> Building .rpm package"
    cargo generate-rpm
    ls -lh target/generate-rpm/*.rpm
}

build_tarball() {
    echo "==> Building .tar.gz release archive"
    local outdir="target/release-tarball"
    local stage="${outdir}/dlpscan-${VERSION}"
    rm -rf "${stage}"
    mkdir -p "${stage}/bin" "${stage}/share/doc/dlpscan" "${stage}/share/systemd"

    cp target/release/dlpscan "${stage}/bin/"
    cp README.md LICENSE "${stage}/share/doc/dlpscan/"
    cp -r docs "${stage}/share/doc/dlpscan/"
    cp packaging/dlpscan.service "${stage}/share/systemd/"
    cp packaging/dlpscan.env.example "${stage}/share/systemd/"
    cp packaging/install.sh "${stage}/install.sh"
    chmod +x "${stage}/install.sh"

    local tarball="${outdir}/dlpscan-${VERSION}-${TRIPLE}.tar.gz"
    tar -czf "${tarball}" -C "${outdir}" "dlpscan-${VERSION}"
    rm -rf "${stage}"
    ls -lh "${tarball}"
    sha256sum "${tarball}" > "${tarball}.sha256"
    echo "    sha256: $(cat "${tarball}.sha256")"
}

build_release

case "${TARGETS}" in
    all)
        build_deb || true
        build_rpm || true
        build_tarball
        ;;
    deb) build_deb ;;
    rpm) build_rpm ;;
    tarball|tar|tar.gz) build_tarball ;;
    *)
        echo "Unknown target: ${TARGETS}" >&2
        echo "Usage: $0 [all|deb|rpm|tarball]" >&2
        exit 1
        ;;
esac

echo "==> Done."
