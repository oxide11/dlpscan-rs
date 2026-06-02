# Siphon-FS — file-scanner HTTP service (multipart in, findings out)
FROM rust:1.96-bookworm AS builder

# Optional cargo parallelism cap. CI pipes CARGO_BUILD_JOBS=2 in
# to keep rav1e / arrow / parquet codegen under the runner's
# memory ceiling; locally the default (all cores) is fine.
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/
COPY src/ src/
# Workspace root declares [[bench]] name = "scanning" — Cargo parses
# the whole workspace even for `-p siphon-fs`, so the bench source
# file has to be present at image-build time.
COPY benches/ benches/

RUN cargo build --release -p siphon-fs --locked

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r siphon && useradd -r -g siphon -s /bin/false siphon

COPY --from=builder /app/target/release/siphon-fs /usr/local/bin/siphon-fs

USER siphon
EXPOSE 8081

ENTRYPOINT ["siphon-fs"]

# K8s liveness/readiness probes hit /health and /ready directly, so
# there's no Docker HEALTHCHECK here — keeps the image slim (no curl
# dep needed) and the single source of health truth is the Deployment
# manifest. Add --with curl if you need standalone docker-compose
# healthchecks.

LABEL org.opencontainers.image.title="siphon-fs" \
      org.opencontainers.image.description="Polygon Siphon file-scanner HTTP service" \
      org.opencontainers.image.version="1.0.0"
