# Siphon reverse proxy + UI bundle.
#
# Multi-stage:
#
#   stage 1 (ui-builder) — compiles the Next.js SPA in /ui into a
#                          fully-static /out directory.
#   stage 2 (runtime)    — nginx:alpine with forward-auth config
#                          + the /out dir copied into /srv/ui.
#
# Build from the repo root so both the ui/ tree and deploy/nginx/
# are visible to the Docker context:
#
#   docker build -f deploy/nginx/Dockerfile -t siphon-nginx:latest .
#
# The compose service already wires this up; `docker compose --profile
# auth up --build` will produce the same image.

# ---- stage 1 — build the Next.js static export -------------------------
FROM node:22-alpine AS ui-builder

# Keep pnpm on the same major the lockfile was produced with. Using
# corepack ships pnpm from the Node image itself, so we don't pull a
# second global npm package at build time.
RUN corepack enable pnpm

WORKDIR /app

# Cache dep install on the manifest alone — source edits won't bust
# the layer that actually downloads node_modules. pnpm-workspace.yaml
# carries the `onlyBuiltDependencies` allowlist that pnpm 10.4+
# requires before it will run sharp / unrs-resolver postinstalls
# under --frozen-lockfile.
COPY ui/package.json ui/pnpm-lock.yaml ui/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY ui/ ./
RUN pnpm build

# ---- stage 2 — nginx runtime ------------------------------------------
FROM nginx:1.27-alpine AS runtime

# auth_request is in the upstream Alpine package by default, so no
# extra build step is needed for forward-auth.

RUN apk add --no-cache curl \
    && rm /etc/nginx/conf.d/default.conf

COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf

# The nginx.conf serves /ui/ out of /srv/ui/ — drop the built SPA
# right there so the path-based routing Just Works.
COPY --from=ui-builder /app/out /srv/ui

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost/nginx-health || exit 1

EXPOSE 80
# EXPOSE 443  # uncomment once TLS certs are mounted
