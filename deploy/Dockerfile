# ── Stage 1: Build ──────────────────────────────────────────────
FROM rust:1.95-bookworm AS builder

WORKDIR /app

# Copy the full workspace. The root Cargo.toml references workspace
# members under crates/ AND a [[bench]] at benches/scanning.rs, so
# both have to be present before any `cargo build` runs or the
# manifest fails to parse.
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/
COPY benches/ benches/

# Cache dependencies by building with a dummy src first. Using the
# real Cargo.toml ensures dep layout + workspace membership match
# the final build.
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
RUN groupadd -r siphon && useradd -r -g siphon -s /bin/false siphon

COPY --from=builder /app/target/release/siphon /usr/local/bin/siphon

USER siphon

ENTRYPOINT ["siphon"]
CMD ["--help"]

# Health check for server mode
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8000/health || siphon --version || exit 1

LABEL org.opencontainers.image.title="siphon" \
      org.opencontainers.image.description="High-performance DLP scanner" \
      org.opencontainers.image.version="2.1.0"
