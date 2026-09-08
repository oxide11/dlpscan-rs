#!/usr/bin/env bash
# Validate the reverse-proxy configs — syntax, and the authorization
# behaviour they are responsible for.
#
# `nginx -t` alone is close to worthless here. The /api/ location is now an
# authorization gate: it decides whether Authelia's group rules run, and it is
# the only thing standing between a client-supplied `Remote-Groups: admins`
# and siphon-api's RBAC. A config can be syntactically perfect and still
# forward a forged identity header, so this script starts nginx against
# stubbed upstreams and asserts the behaviour.
#
#   scripts/validate-nginx.sh            # syntax + behaviour
#   scripts/validate-nginx.sh --syntax   # syntax only (no root needed)
#
# Requires nginx with http_auth_request_module (Debian/Ubuntu nginx-light
# has it). Behaviour mode binds :80 and edits /etc/hosts, so it wants root
# or a container.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'pkill -f "$WORK/stubs.py" 2>/dev/null || true; nginx -s stop 2>/dev/null || true; rm -rf "$WORK"' EXIT

fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }

command -v nginx >/dev/null || fail "nginx not installed (apt-get install nginx-light)"
nginx -V 2>&1 | grep -q http_auth_request_module \
  || fail "this nginx lacks http_auth_request_module; /api/ cannot be gated"

# Upstreams are resolved at config-load time, so the names must resolve even
# for a syntax check. IPv6 is stripped because many containers have no
# AF_INET6 and `listen [::]:80` then fails for reasons unrelated to the file.
prep() {
  sed 's/^\( *\)listen \[::\]:80 default_server;/\1# ipv6 omitted by validate-nginx.sh/' "$1"
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

[ "${1:-}" = "--syntax" ] && exit 0

# ------------------------------------------------------------- behaviour ---
cat > "$WORK/stubs.py" <<'PY'
import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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
        body = json.dumps({
            "remote_user": self.headers.get("Remote-User"),
            "remote_groups": self.headers.get("Remote-Groups"),
            "authorization": self.headers.get("Authorization"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass

def serve(p, h): HTTPServer(("127.0.0.1", p), h).serve_forever()
threading.Thread(target=serve, args=(9091, Authelia), daemon=True).start()
threading.Thread(target=serve, args=(8080, Api), daemon=True).start()
threading.Event().wait()
PY

mkdir -p /srv/console/assets /srv/ir
echo '<!doctype html>console' > /srv/console/index.html
echo 'body{}'                 > /srv/console/assets/probe.css
echo '<h1>ir</h1>'            > /srv/ir/index.html

setsid python3 "$WORK/stubs.py" >/dev/null 2>&1 </dev/null &
for _ in $(seq 1 40); do sleep 0.25; curl -sf -o /dev/null http://127.0.0.1:9091/api/verify && break; done
nginx -c "$WORK/main.conf" 2>/dev/null || true
for _ in $(seq 1 40); do sleep 0.25; curl -sf -o /dev/null http://127.0.0.1/ && break; done

get()  { curl -s "http://127.0.0.1$1" "${@:2}"; }
code() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1$1" "${@:2}"; }

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

# Routes are real URLs carrying filter state; without try_files every shared
# link 404s and the URL-state design is decorative.
get /findings | grep -q console || fail "SPA deep link did not fall back to index.html"
ok "SPA deep links serve the shell"

[ "$(code /ui/)" = "301" ] || fail "/ui/ no longer redirects"
[ "$(code /ir/)" = "200" ] || fail "/ir/ not served"
ok "/ui/ redirects, /ir/ serves"

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
