# Siphon reverse proxy + wireframe consoles.
#
# Single-stage: nginx serves the static C2 / IR wireframe consoles
# at /ui/. There is no Next.js build step — the wireframes are
# self-contained HTML files (siphon-shared.css and siphon-shared.js
# are inlined into each at sync time via docs/wireframes/sync-shared.sh).
#
# Build from the repo root so the docs/wireframes/ tree and
# deploy/nginx/ are both in the build context:
#
#   docker build -f deploy/nginx/Dockerfile -t siphon-nginx:latest .

FROM nginx:1.27-alpine AS runtime

# auth_request is in the upstream Alpine package by default; no
# extra build step is needed for forward-auth.
RUN apk add --no-cache curl \
    && rm /etc/nginx/conf.d/default.conf

COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf

# The wireframes link to each other via relative paths
# (`<a href="siphon-ir.html">`), so both files must live in the
# same served directory. siphon-logo.png is referenced externally
# from siphon-ir.html (siphon-c2.html inlines its own logo as a
# data: URI).
COPY docs/wireframes/siphon-c2.html  /srv/ui/siphon-c2.html
COPY docs/wireframes/siphon-ir.html  /srv/ui/siphon-ir.html
COPY docs/wireframes/siphon-logo.png /srv/ui/siphon-logo.png

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost/nginx-health || exit 1

EXPOSE 80
# EXPOSE 443  # uncomment once TLS certs are mounted
