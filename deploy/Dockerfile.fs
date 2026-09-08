# Siphon-FS — file-scanner HTTP service (multipart in, findings out)
FROM rust:1.98-bookworm AS builder

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

# curl for the compose healthcheck, which under mutual TLS has to present the
# pod's own certificate to its own listener — only a real client can.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r siphon && useradd -r -g siphon -s /bin/false siphon

COPY --from=builder /app/target/release/siphon-fs /usr/local/bin/siphon-fs

USER siphon
EXPOSE 8081

ENTRYPOINT ["siphon-fs"]

# No Docker HEALTHCHECK here: the Deployment manifest is the single source
# of health truth (tcpSocket under mutual TLS, since kubelet cannot present
# a client certificate), and docker-compose declares its own curl probe
# with the pod's certificate. curl is installed above for that probe.

LABEL org.opencontainers.image.title="siphon-fs" \
      org.opencontainers.image.description="Polygon Siphon file-scanner HTTP service" \
      org.opencontainers.image.version="1.4.0"
