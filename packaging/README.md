# Linux Packaging

This directory contains the configuration and helper scripts for
building distributable siphon packages on Linux.

## What gets built

`./build-packages.sh` produces three artifacts in `target/`:

| Format | Path | Use case |
|---|---|---|
| `.deb` | `target/debian/siphon_<version>_amd64.deb` | Debian / Ubuntu / derivatives |
| `.rpm` | `target/generate-rpm/siphon-<version>-1.x86_64.rpm` | RHEL / Rocky / Alma / Fedora / SUSE |
| `.tar.gz` | `target/release-tarball/siphon-<version>-x86_64-unknown-linux-gnu.tar.gz` | Generic Linux (no package manager) |

Each artifact installs:

- `/usr/bin/siphon` (or `/usr/local/bin/siphon` for the tarball)
- `/lib/systemd/system/siphon.service` — hardened systemd unit
- `/etc/siphon/siphon.env.example` — annotated config template
- Documentation under `/usr/share/doc/siphon/`

The systemd unit creates a dedicated `siphon` system user, sandboxes
the process with `ProtectSystem=strict`, and reads runtime config from
`/etc/siphon/siphon.env`.

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
sudo apt install ./target/debian/siphon_2.1.0_amd64.deb
sudo cp /etc/siphon/siphon.env.example /etc/siphon/siphon.env
sudoedit /etc/siphon/siphon.env       # set DLPSCAN_API_KEY
sudo systemctl enable --now siphon
```

### RHEL / Rocky / Alma / Fedora

```bash
sudo dnf install ./target/generate-rpm/siphon-2.1.0-1.x86_64.rpm
sudo cp /etc/siphon/siphon.env.example /etc/siphon/siphon.env
sudoedit /etc/siphon/siphon.env
sudo systemctl enable --now siphon
```

### Generic tarball

```bash
tar xzf siphon-2.1.0-x86_64-unknown-linux-gnu.tar.gz
cd siphon-2.1.0
sudo ./install.sh
```

## Verifying

```bash
siphon info
systemctl status siphon
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
