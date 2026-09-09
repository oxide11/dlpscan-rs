#!/usr/bin/env bash
# Validate the reverse-proxy configs — syntax, and the authorization and
# transport behaviour they are responsible for.
#
# `nginx -t` alone is close to worthless here. The /api/ location is an
# authorization gate: it decides whether Authelia's group rules run, and it is
# the only thing standing between a client-supplied `Remote-Groups: admins`
# and siphon-api's RBAC. And the upstream hops are mutual TLS: a config can be
# syntactically perfect and still skip `proxy_ssl_verify`, encrypting to
# whatever answers on the port. So this script starts nginx against stubbed
# upstreams — a TLS siphon-api that REQUIRES a client certificate — and
# asserts the behaviour from both sides.
#
#   scripts/validate-nginx.sh            # syntax + behaviour
#   scripts/validate-nginx.sh --syntax   # syntax only (no root needed)
#
# Requires nginx with http_auth_request_module and http_ssl_module
# (Debian/Ubuntu nginx-light has both), openssl, and python3. Behaviour mode
# binds :80 and edits /etc/hosts, so it wants root or a container.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'pkill -f "$WORK/stubs.py" 2>/dev/null || true; nginx -s stop 2>/dev/null || true; rm -rf "$WORK"' EXIT

fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }

command -v nginx >/dev/null || fail "nginx not installed (apt-get install nginx-light)"
nginx -V 2>&1 | grep -q http_auth_request_module \
  || fail "this nginx lacks http_auth_request_module; /api/ cannot be gated"
nginx -V 2>&1 | grep -q http_ssl_module \
  || fail "this nginx lacks http_ssl_module; the upstream hops cannot be mTLS"

# The config names certificate files and nginx opens them at load time, so
# even a syntax check needs real material. Two CAs: ours, and a stranger's,
# to prove nginx refuses an upstream it cannot verify.
"$REPO/scripts/dev/mkcerts.sh" --out "$WORK/certs" --quiet
"$REPO/scripts/dev/mkcerts.sh" --out "$WORK/stranger" --quiet

# Upstreams are resolved at config-load time, so the names must resolve even
# for a syntax check. IPv6 is stripped because many containers have no
# AF_INET6 and `listen [::]:80` then fails for reasons unrelated to the file.
# The certificate paths are redirected at the generated material.
prep() {
  sed -E -e 's/^( *)listen \[::\]:[0-9]+( .*)?;/\1# ipv6 omitted by validate-nginx.sh/' \
      -e "s#/etc/nginx/certs/internal#$WORK/certs/nginx#g" "$1"
}

# ---------------------------------------------------------------- syntax ---
prep "$REPO/deploy/nginx/nginx.conf"            > "$WORK/main.conf"
prep "$REPO/deploy/k8s/lab/nginx-config/nginx.conf" > "$WORK/lab.conf"

if ! grep -q 'siphon-api' /etc/hosts 2>/dev/null; then
  cat >> /etc/hosts <<'HOSTS'
127.0.0.1 siphon-authelia siphon-api siphon-fs siphon-ui
127.0.0.1 siphon-api.siphon-lab.svc.cluster.local siphon-fs.siphon-lab.svc.cluster.local
127.0.0.1 siphon-ui.siphon-lab.svc.cluster.local evadex.siphon-lab.svc.cluster.local
127.0.0.1 authelia.siphon-lab.svc.cluster.local
HOSTS
fi

nginx -t -c "$WORK/main.conf" >/dev/null 2>&1 || { nginx -t -c "$WORK/main.conf"; fail "deploy/nginx/nginx.conf"; }
ok "deploy/nginx/nginx.conf — syntax"
nginx -t -c "$WORK/lab.conf" >/dev/null 2>&1 || { nginx -t -c "$WORK/lab.conf"; fail "lab nginx.conf"; }
ok "deploy/k8s/lab/nginx-config/nginx.conf — syntax"

# The config must not merely mention verification — it must turn it on.
grep -qE '^\s*proxy_ssl_verify\s+on;' "$REPO/deploy/nginx/nginx.conf" \
  || fail "proxy_ssl_verify is not 'on' — nginx would encrypt to any upstream"
ok "proxy_ssl_verify on"

[ "${1:-}" = "--syntax" ] && exit 0

# ------------------------------------------------------------- behaviour ---
# The siphon-api stub is TLS and REQUIRES a client certificate from our CA.
# It reports the CN nginx presented, so the assertion below is not "the
# request arrived" but "the request arrived as siphon-nginx". Which
# certificate the stub serves is an argument, so it can be run once as an
# impostor and once as the real thing.
cat > "$WORK/stubs.py" <<'PY'
import json, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

CERT_DIR, CA = sys.argv[1], sys.argv[2]

class Authelia(BaseHTTPRequestHandler):
    def do_GET(self):
        if "deny" in (self.headers.get("Cookie") or ""):
            self.send_response(401); self.end_headers(); return
        self.send_response(200)
        self.send_header("Remote-User", "alice@example.com")
        self.send_header("Remote-Groups", "operators,viewers")
        self.end_headers()
    do_POST = do_GET
    def log_message(self, *a): pass

class Api(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.connection.getpeercert() or {}
        cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"), None)
        body = json.dumps({
            "remote_user": self.headers.get("Remote-User"),
            "remote_groups": self.headers.get("Remote-Groups"),
            "authorization": self.headers.get("Authorization"),
            "client_cn": cn,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass

def serve(p, h, tls=False):
    srv = HTTPServer(("127.0.0.1", p), h)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{CERT_DIR}/tls.crt", f"{CERT_DIR}/tls.key")
        ctx.load_verify_locations(CA)
        ctx.verify_mode = ssl.CERT_REQUIRED
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
threading.Thread(target=serve, args=(9091, Authelia), daemon=True).start()
threading.Thread(target=serve, args=(8080, Api, True), daemon=True).start()
threading.Event().wait()
PY

mkdir -p /srv/console/assets /srv/ir-legacy
echo '<!doctype html>console' > /srv/console/index.html
echo 'body{}'                 > /srv/console/assets/probe.css
echo '<h1>ir</h1>'            > /srv/ir-legacy/index.html

start_stubs() {
  pkill -f "$WORK/stubs.py" 2>/dev/null || true
  sleep 0.3
  setsid python3 "$WORK/stubs.py" "$1" "$2" >/dev/null 2>&1 </dev/null &
  for _ in $(seq 1 40); do sleep 0.25; curl -sf -o /dev/null http://127.0.0.1:9091/api/verify && break; done
}

CA="$WORK/certs/nginx/ca.crt"
get()  { curl -s --cacert "$CA" "https://127.0.0.1$1" "${@:2}"; }
code() { curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" "https://127.0.0.1$1" "${@:2}"; }

# --- transport: the impostor first --------------------------------------
# A siphon-api whose certificate chains to some other CA. If nginx answers
# anything but 502 here, proxy_ssl_verify is not doing its job.
start_stubs "$WORK/stranger/siphon-api" "$WORK/certs/ca/ca.crt"
nginx -c "$WORK/main.conf" 2>/dev/null || true
for _ in $(seq 1 40); do sleep 0.25; curl -sf -o /dev/null --cacert "$CA" https://127.0.0.1/ && break; done

c=$(code /api/v1/me -H 'Authorization: Bearer k')
[ "$c" = "502" ] || fail "nginx accepted an upstream certificate from a stranger's CA (got $c)"
ok "an upstream certificate from another CA is refused (502)"

# --- transport: the real one --------------------------------------------
start_stubs "$WORK/certs/siphon-api" "$WORK/certs/ca/ca.crt"

r=$(get /api/v1/me -H 'Authorization: Bearer k')
echo "$r" | grep -q '"client_cn": "siphon-nginx"' \
  || fail "nginx did not present its client certificate to siphon-api: $r"
ok "nginx presents its client certificate; upstream sees CN=siphon-nginx"

# --- authorization ------------------------------------------------------
# THE test. Anything that can reach nginx can send these headers; if they were
# forwarded, one curl would be a full privilege escalation.
r=$(get /api/v1/me -H 'Remote-User: mallory' -H 'Remote-Groups: admins')
echo "$r" | grep -q '"remote_groups": "operators,viewers"' \
  || fail "forged Remote-Groups reached the upstream: $r"
echo "$r" | grep -q mallory && fail "forged Remote-User reached the upstream: $r"
ok "forged Remote-* headers are overwritten, not forwarded"

# Machines carry a bearer key and no cookie; they must bypass Authelia and
# arrive with no asserted identity so siphon-api falls back to key auth.
r=$(get /api/v1/me -H 'Authorization: Bearer k' -H 'Remote-Groups: admins')
echo "$r" | grep -q '"remote_groups": null' || fail "bearer path leaked Remote-Groups: $r"
echo "$r" | grep -q '"authorization": "Bearer k"' || fail "bearer token not forwarded: $r"
ok "bearer path bypasses Authelia and carries no identity headers"

get /api/v1/me | grep -q '"remote_user": "alice@example.com"' \
  || fail "session path did not receive Authelia's identity"
ok "session path receives the proxy-asserted identity"

[ "$(code /api/v1/me -H 'Cookie: deny=1')" = "401" ] || fail "denied session was not rejected"
ok "Authelia denial returns 401"

# --- the console ----------------------------------------------------------
# Routes are real URLs carrying filter state; without try_files every shared
# link 404s and the URL-state design is decorative.
get /detections | grep -q console || fail "SPA deep link did not fall back to index.html"

# The IR shell lives at /ir inside the same SPA. A prefix location for the old
# wireframe used to sit on /ir/ and swallow both of these — /ir/ served the
# wireframe and /ir/alerts 404'd — while /detections above kept passing. Ask
# the same question of the surface that was actually broken.
get /ir/        | grep -q console || fail "/ir/ did not reach the console"
get /ir/alerts  | grep -q console || fail "IR deep link did not reach the console"
ok "SPA deep links serve the shell, /ir included"

# --- the listener is TLS-only -------------------------------------------
# Not "redirects to https" — refuses. A port 80 that answers 301 still
# accepts the TCP connection and reads a request line, and this ingress
# carries session cookies and scan payloads. The whole point of the change
# was that there is nothing there at all.
#
# curl exits 7 (couldn't connect) when nothing is listening. Anything that
# completes a plaintext HTTP exchange means a listener came back.
if curl -s -o /dev/null --max-time 5 http://127.0.0.1:80/ 2>/dev/null; then
    fail "something answered plaintext HTTP on :80 — the listener must be TLS-only"
fi
ok "plaintext on :80 is refused, not redirected"

[ "$(code /ui/)" = "301" ] || fail "/ui/ no longer redirects"
[ "$(code /ir-legacy/)" = "200" ] || fail "/ir-legacy/ not served"
ok "/ui/ redirects, /ir-legacy/ serves"

# nginx inherits server-level add_header only into locations that declare
# none, so a Cache-Control add_header would silently strip these.
h=$(curl -sI http://127.0.0.1/)
for want in X-Frame-Options X-Content-Type-Options Referrer-Policy Permissions-Policy; do
  echo "$h" | grep -qi "^$want:" || fail "$want missing on the HTML response"
done
echo "$h" | grep -qi '^Cache-Control: no-cache' || fail "HTML is cacheable"
ok "security headers survive alongside cache headers"

curl -sI http://127.0.0.1/assets/probe.css | grep -qi 'max-age=31536000' \
  || fail "hashed assets are not cached hard"
ok "hashed assets cache for a year"

printf '\n\033[32mall nginx checks passed\033[0m\n'
