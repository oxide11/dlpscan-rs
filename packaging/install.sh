#!/usr/bin/env bash
#
# Install dlpscan from a release tarball.
#
# Run from the unpacked tarball directory:
#   sudo ./install.sh
#
# Installs:
#   /usr/local/bin/dlpscan
#   /etc/dlpscan/dlpscan.env.example
#   /lib/systemd/system/dlpscan.service (if systemd is detected)
#   /var/lib/dlpscan, /var/log/dlpscan (state + log dirs)
#
# Creates a system user `dlpscan` to run the API server under.

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: install.sh must be run as root (use sudo)" >&2
    exit 1
fi

cd "$(dirname "$0")"

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
SYSTEMDDIR="${SYSTEMDDIR:-/lib/systemd/system}"

echo "==> Installing dlpscan binary to ${PREFIX}/bin/"
install -m 0755 bin/dlpscan "${PREFIX}/bin/dlpscan"

echo "==> Installing documentation"
install -d -m 0755 "${PREFIX}/share/doc/dlpscan"
cp -r share/doc/dlpscan/. "${PREFIX}/share/doc/dlpscan/"

echo "==> Creating system user 'dlpscan'"
if ! getent passwd dlpscan >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir /var/lib/dlpscan dlpscan
fi

echo "==> Creating state and log directories"
install -d -m 0750 -o dlpscan -g dlpscan /var/lib/dlpscan
install -d -m 0750 -o dlpscan -g dlpscan /var/log/dlpscan

echo "==> Installing config example to ${SYSCONFDIR}/dlpscan/"
install -d -m 0755 "${SYSCONFDIR}/dlpscan"
if [[ ! -e "${SYSCONFDIR}/dlpscan/dlpscan.env.example" ]]; then
    install -m 0644 share/systemd/dlpscan.env.example \
        "${SYSCONFDIR}/dlpscan/dlpscan.env.example"
fi

if [[ -d "${SYSTEMDDIR}" ]] && command -v systemctl >/dev/null 2>&1; then
    echo "==> Installing systemd unit"
    install -m 0644 share/systemd/dlpscan.service "${SYSTEMDDIR}/dlpscan.service"
    systemctl daemon-reload
    echo
    echo "    Edit ${SYSCONFDIR}/dlpscan/dlpscan.env (copy from .example),"
    echo "    then enable the service:"
    echo "        sudo systemctl enable --now dlpscan"
fi

echo
echo "==> Installation complete."
echo "    Binary: ${PREFIX}/bin/dlpscan"
echo "    Run 'dlpscan info' to verify."
