#!/usr/bin/env bash
#
# Install siphon from a release tarball.
#
# Run from the unpacked tarball directory:
#   sudo ./install.sh
#
# Installs:
#   /usr/local/bin/siphon
#   /etc/siphon/siphon.env.example
#   /lib/systemd/system/siphon.service (if systemd is detected)
#   /var/lib/siphon, /var/log/siphon (state + log dirs)
#
# Creates a system user `siphon` to run the API server under.

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: install.sh must be run as root (use sudo)" >&2
    exit 1
fi

cd "$(dirname "$0")"

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
SYSTEMDDIR="${SYSTEMDDIR:-/lib/systemd/system}"

echo "==> Installing siphon binary to ${PREFIX}/bin/"
install -m 0755 bin/siphon "${PREFIX}/bin/siphon"

echo "==> Installing documentation"
install -d -m 0755 "${PREFIX}/share/doc/siphon"
cp -r share/doc/siphon/. "${PREFIX}/share/doc/siphon/"

echo "==> Creating system user 'siphon'"
if ! getent passwd siphon >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir /var/lib/siphon siphon
fi

echo "==> Creating state and log directories"
install -d -m 0750 -o siphon -g siphon /var/lib/siphon
install -d -m 0750 -o siphon -g siphon /var/log/siphon

echo "==> Installing config example to ${SYSCONFDIR}/siphon/"
install -d -m 0755 "${SYSCONFDIR}/siphon"
if [[ ! -e "${SYSCONFDIR}/siphon/siphon.env.example" ]]; then
    install -m 0644 share/systemd/siphon.env.example \
        "${SYSCONFDIR}/siphon/siphon.env.example"
fi

if [[ -d "${SYSTEMDDIR}" ]] && command -v systemctl >/dev/null 2>&1; then
    echo "==> Installing systemd unit"
    install -m 0644 share/systemd/siphon.service "${SYSTEMDDIR}/siphon.service"
    systemctl daemon-reload
    echo
    echo "    Edit ${SYSCONFDIR}/siphon/siphon.env (copy from .example),"
    echo "    then enable the service:"
    echo "        sudo systemctl enable --now siphon"
fi

echo
echo "==> Installation complete."
echo "    Binary: ${PREFIX}/bin/siphon"
echo "    Run 'siphon info' to verify."
