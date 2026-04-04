# ── Stage 1: Build ──────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Cache dependencies by building a dummy project first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    echo 'pub fn lib() {}' > src/lib.rs && \
    cargo build --release || true && \
    rm -rf src

# Copy actual source and build
COPY src/ src/
RUN cargo build --release --features full --locked

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r dlpscan && useradd -r -g dlpscan -s /bin/false dlpscan

COPY --from=builder /app/target/release/dlpscan /usr/local/bin/dlpscan

USER dlpscan

ENTRYPOINT ["dlpscan"]
CMD ["--help"]

# Health check for server mode
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8000/health || dlpscan --version || exit 1

LABEL org.opencontainers.image.title="dlpscan" \
      org.opencontainers.image.description="High-performance DLP scanner" \
      org.opencontainers.image.version="2.0.0"
