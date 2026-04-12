# Linux Packaging

This directory contains the configuration and helper scripts for
building distributable dlpscan packages on Linux.

## What gets built

`./build-packages.sh` produces three artifacts in `target/`:

| Format | Path | Use case |
|---|---|---|
| `.deb` | `target/debian/dlpscan_<version>_amd64.deb` | Debian / Ubuntu / derivatives |
| `.rpm` | `target/generate-rpm/dlpscan-<version>-1.x86_64.rpm` | RHEL / Rocky / Alma / Fedora / SUSE |
| `.tar.gz` | `target/release-tarball/dlpscan-<version>-x86_64-unknown-linux-gnu.tar.gz` | Generic Linux (no package manager) |

Each artifact installs:

- `/usr/bin/dlpscan` (or `/usr/local/bin/dlpscan` for the tarball)
- `/lib/systemd/system/dlpscan.service` — hardened systemd unit
- `/etc/dlpscan/dlpscan.env.example` — annotated config template
- Documentation under `/usr/share/doc/dlpscan/`

The systemd unit creates a dedicated `dlpscan` system user, sandboxes
the process with `ProtectSystem=strict`, and reads runtime config from
`/etc/dlpscan/dlpscan.env`.

## Prerequisites

```bash
# Rust toolchain (any version >= 1.75)
rustup install stable

# Packaging helpers
cargo install cargo-deb
cargo install cargo-generate-rpm
```

## Building

```bash
# All formats with default features (bin-data, metrics)
./packaging/build-packages.sh

# Just one format
./packaging/build-packages.sh deb
./packaging/build-packages.sh rpm
./packaging/build-packages.sh tarball

# Different feature set
FEATURES=full ./packaging/build-packages.sh
```

## Installing

### Debian / Ubuntu

```bash
sudo apt install ./target/debian/dlpscan_2.1.0_amd64.deb
sudo cp /etc/dlpscan/dlpscan.env.example /etc/dlpscan/dlpscan.env
sudoedit /etc/dlpscan/dlpscan.env       # set DLPSCAN_API_KEY
sudo systemctl enable --now dlpscan
```

### RHEL / Rocky / Alma / Fedora

```bash
sudo dnf install ./target/generate-rpm/dlpscan-2.1.0-1.x86_64.rpm
sudo cp /etc/dlpscan/dlpscan.env.example /etc/dlpscan/dlpscan.env
sudoedit /etc/dlpscan/dlpscan.env
sudo systemctl enable --now dlpscan
```

### Generic tarball

```bash
tar xzf dlpscan-2.1.0-x86_64-unknown-linux-gnu.tar.gz
cd dlpscan-2.1.0
sudo ./install.sh
```

## Verifying

```bash
dlpscan info
systemctl status dlpscan
curl http://127.0.0.1:8000/health
```

## Reproducible builds

For reproducible CI builds, pin the Rust version and feature set:

```bash
rustup install 1.78.0
RUSTFLAGS="-C target-cpu=x86-64-v2" \
FEATURES="bin-data,metrics" \
    ./packaging/build-packages.sh
```

The release binary is built with `lto = true`, `strip = true`,
`opt-level = 3`, and `codegen-units = 1` (see `[profile.release]`
in `Cargo.toml`).
