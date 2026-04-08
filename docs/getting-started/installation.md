# Installation

## Build from Source

```bash
git clone https://github.com/oxide11/dlpscan-rs.git
cd dlpscan-rs
cargo build --release
```

The binary is at `target/release/dlpscan`.

### With all features

```bash
cargo build --release --features full
```

### With specific features

```bash
# QR code scanning + interactive TUI
cargo build --release --features "barcode,tui"

# API server with TLS
cargo build --release --features "async-support,tls"
```

## As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
dlpscan = { path = "../dlpscan-rs" }
# or from a registry:
# dlpscan = "2.1"
```

## Docker

```bash
docker build -t dlpscan .
docker run -v ./data:/data dlpscan scan /data
```

See [Docker deployment](../deployment/docker.md) for production images.

## Verify Installation

```bash
dlpscan info
```

Expected output:

```
dlpscan v2.1.0

Patterns:    560 across 126 categories
Features:    core, metrics

Supported formats: 59 file types
```

## System Requirements

- Rust 1.75 or later (build only)
- Linux, macOS, or Windows
- No runtime dependencies — single static binary
