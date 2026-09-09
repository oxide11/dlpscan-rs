# Siphon reverse proxy + analyst console.
#
# Two stages: Node builds the console/ SPA, nginx serves the static output
# and proxies /api/ and /fs/. Node exists only in the build stage — the
# runtime image is nginx and static files, so there is no JavaScript runtime
# in the deployed artifact and nothing to patch on the Node CVE cadence.
#
# Build from the repo root so console/ and deploy/nginx/ are both in the
# build context:
#
#   docker build -f deploy/nginx/Dockerfile -t siphon-nginx:latest .

FROM node:22-alpine AS console

RUN corepack enable
WORKDIR /build

# Manifest and lockfile first, so a source-only change reuses the cached
# install layer. `--frozen-lockfile` is the pnpm equivalent of cargo's
# `--locked`: the build fails rather than silently resolving something the
# lockfile does not describe.
COPY console/package.json console/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY console/ ./
# `pnpm build` runs `tsc -b --noEmit && vite build`, so a type error fails the
# image build rather than shipping a console that only fails in the browser.
RUN pnpm build


FROM nginx:1.27-alpine AS runtime

# auth_request is in the upstream Alpine package by default; no
# extra build step is needed for forward-auth.
RUN apk add --no-cache curl \
    && rm /etc/nginx/conf.d/default.conf

COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf

# The console, served at the origin root.
COPY --from=console /build/dist/ /srv/console/

# The old IR wireframe, served at /ir-legacy/. The console now owns /ir, and
# serving the wireframe there shadowed it — so this keeps the prototype
# reachable for the surfaces the console has not absorbed yet without taking
# a path the router needs. The C2 wireframe is not shipped at all; it lives on
# in docs/wireframes/ as the design source.
COPY docs/wireframes/siphon-ir.html  /srv/ir-legacy/index.html
COPY docs/wireframes/siphon-logo.png /srv/ir-legacy/siphon-logo.png

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost/nginx-health || exit 1

EXPOSE 80
# EXPOSE 443  # uncomment once TLS certs are mounted
