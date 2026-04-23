# Nginx reverse proxy for Siphon. Thin layer on top of the official
# Alpine image — just drops the repo's nginx.conf in and exposes 80
# (and eventually 443 once certs are mounted).
FROM nginx:1.27-alpine

# The Alpine image already has the ngx_http_auth_request_module
# compiled in (it's on by default in the upstream package), so no
# extra build step is needed for forward-auth.

RUN apk add --no-cache curl \
    && rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf

# Placeholder for the Phase 0 SPA bundle. Compose / Helm will
# bind-mount the built assets over this empty dir once the UI lands.
RUN mkdir -p /srv/ui

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost/nginx-health || exit 1

EXPOSE 80
# EXPOSE 443  # uncomment once TLS certs are mounted
