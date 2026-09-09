#!/usr/bin/env bash
# Prepare the Siphon lab for a real hostname behind a Cloudflare Tunnel.
#
#   scripts/dev/lab-setup.sh siphon.example.com auth.example.com
#
# Does three things, all of them idempotent and none of them destructive:
#
#   1. renders deploy/authelia/configuration.lab.yml from the committed
#      configuration.yml, with siphon.local replaced by your domain
#   2. creates deploy/authelia/users_database.yml with one admin account,
#      hashing the password with Authelia's own argon2 implementation
#   3. fills in any missing secrets in deploy/.env
#
# It never overwrites an existing users_database.yml or an already-set secret,
# because the second run of a setup script should be safe — that is what makes
# it safe to run when you are not sure whether you ran it.
#
# ── Why a rendered copy rather than editing the original ──────────────────
#
# deploy/authelia/configuration.yml is committed and hardcoded to
# siphon.local: ten occurrences across access_control rules, the session
# cookie domain and default_redirection_url. Editing it in place would put
# your domain into git and break the local-dev stack for everyone else. The
# rendered file is gitignored and mounted over the original by
# docker-compose.tunnel.yml.
#
# The session cookie domain is the one to get right. Authelia sets its cookie
# scoped to `session.cookies[].domain`; if that does not match the hostname the
# browser actually visits, the cookie is set and never sent back, so you land
# in a login loop that reports no error anywhere. That failure mode is why
# this is a script and not a paragraph telling you to sed ten lines.

set -euo pipefail

cd "$(dirname "$0")/../.."

SIPHON_DOMAIN="${1:-}"
AUTH_DOMAIN="${2:-}"

if [ -z "$SIPHON_DOMAIN" ] || [ -z "$AUTH_DOMAIN" ]; then
    cat >&2 <<'USAGE'
usage: scripts/dev/lab-setup.sh <siphon-domain> <auth-domain>

  <siphon-domain>  where the console is served, e.g. siphon.example.com
  <auth-domain>    where Authelia is served,    e.g. auth.example.com

Both must be hostnames you have routed to http://nginx:80 in the Cloudflare
tunnel, and both must sit under one registrable domain — Authelia scopes its
session cookie to the parent, so siphon.example.com and auth.example.com
work while siphon.example.com and auth.example.org cannot.
USAGE
    exit 2
fi

# The registrable parent both hostnames share. Naive last-two-labels, which is
# right for example.com and wrong for example.co.uk — say so rather than
# pretending to a public-suffix list this script has no business carrying.
COOKIE_DOMAIN="$(echo "$SIPHON_DOMAIN" | rev | cut -d. -f1,2 | rev)"

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
dim() { printf '\033[2m%s\033[0m\n' "$1"; }

echo
echo "Siphon lab setup"
echo "  console : https://${SIPHON_DOMAIN}"
echo "  auth    : https://${AUTH_DOMAIN}"
echo "  cookie  : ${COOKIE_DOMAIN}"
if [ "$COOKIE_DOMAIN" != "$(echo "$AUTH_DOMAIN" | rev | cut -d. -f1,2 | rev)" ]; then
    echo >&2
    echo "error: the two hostnames do not share a registrable domain, so the" >&2
    echo "session cookie set at ${AUTH_DOMAIN} will never be sent to" >&2
    echo "${SIPHON_DOMAIN} and login will loop silently." >&2
    exit 1
fi
echo

# ── 1. Authelia configuration ─────────────────────────────────────────────
SRC="deploy/authelia/configuration.yml"
OUT="deploy/authelia/configuration.lab.yml"

sed -e "s|auth\.siphon\.local|${AUTH_DOMAIN}|g" \
    -e "s|https://siphon\.local/|https://${SIPHON_DOMAIN}/|g" \
    -e "s|\bsiphon\.local\b|${SIPHON_DOMAIN}|g" \
    "$SRC" > "$OUT.tmp"

# The session cookie domain must be the shared parent, not the console host,
# or the cookie is scoped too narrowly to cover the auth hostname.
python3 - "$OUT.tmp" "$SIPHON_DOMAIN" "$COOKIE_DOMAIN" <<'PY'
import re, sys
path, console, cookie = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
# Only inside the session block: `- domain: <console>` becomes the parent.
s = re.sub(r'(\n\s+-\s+domain:\s*)' + re.escape(console) + r'(\s*\n)',
           r'\g<1>' + cookie + r'\g<2>', s, count=1)
open(path, 'w').write(s)
PY
mv "$OUT.tmp" "$OUT"
green "  ✓ rendered $OUT"
dim "    ($(grep -c "$SIPHON_DOMAIN\|$AUTH_DOMAIN\|$COOKIE_DOMAIN" "$OUT") lines now name your domain)"

if grep -q 'siphon\.local' "$OUT"; then
    yellow "  ! $OUT still mentions siphon.local:"
    grep -n 'siphon\.local' "$OUT" | sed 's/^/      /'
fi

# ── 2. The admin account ──────────────────────────────────────────────────
USERS="deploy/authelia/users_database.yml"

if [ -f "$USERS" ]; then
    dim "  = $USERS exists — left alone"
else
    printf 'Admin username [admin]: '
    read -r LAB_USER
    LAB_USER="${LAB_USER:-admin}"
    printf 'Admin email [%s@%s]: ' "$LAB_USER" "$COOKIE_DOMAIN"
    read -r LAB_EMAIL
    LAB_EMAIL="${LAB_EMAIL:-${LAB_USER}@${COOKIE_DOMAIN}}"
    printf 'Password (not echoed): '
    stty -echo 2>/dev/null || true
    read -r LAB_PASS
    stty echo 2>/dev/null || true
    printf '\n'
    [ -n "$LAB_PASS" ] || { echo "error: empty password" >&2; exit 1; }

    # Hashed by Authelia itself rather than by an argon2 binary that happens
    # to be lying around: the parameters have to match what Authelia expects
    # to verify against, and its own CLI is the only thing guaranteed to agree.
    echo "  … hashing with Authelia's argon2 (pulls the image if absent)"
    HASH=$(docker run --rm authelia/authelia:4.38 \
             authelia crypto hash generate argon2 --password "$LAB_PASS" 2>/dev/null \
           | sed -n 's/^Digest: //p')
    if [ -z "$HASH" ]; then
        echo "error: could not generate the password hash. Is docker running?" >&2
        exit 1
    fi

    cat > "$USERS" <<YAML
# Siphon lab users. Generated by scripts/dev/lab-setup.sh — gitignored,
# because it holds a password hash.
#
# Siphon itself has no signup: it has never had a user store, a registration
# endpoint or a "create account" page. Human identity comes from Authelia, and
# an account is an entry in this file. The groups below are what siphon-api
# maps to an RBAC role via rbac::Role::from_groups, so the group is the
# permission — "admins" is what makes this account an Admin in the console.
users:
  ${LAB_USER}:
    displayname: "${LAB_USER}"
    password: "${HASH}"
    email: ${LAB_EMAIL}
    groups:
      - admins
YAML
    green "  ✓ created $USERS for '${LAB_USER}' (group: admins)"
fi

# ── 3. Secrets ────────────────────────────────────────────────────────────
ENV_FILE="deploy/.env"
[ -f "$ENV_FILE" ] || { cp deploy/.env.example "$ENV_FILE"; dim "  = seeded $ENV_FILE from .env.example"; }

set_if_empty() {
    local key="$1" val="$2"
    if grep -qE "^${key}=.+" "$ENV_FILE"; then
        dim "  = ${key} already set"
    else
        # Replace an empty assignment, or append if the key is absent.
        if grep -qE "^${key}=" "$ENV_FILE"; then
            sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
        else
            printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
        fi
        green "  ✓ generated ${key}"
    fi
}

set_if_empty AUTHELIA_JWT_SECRET "$(openssl rand -hex 32)"
set_if_empty AUTHELIA_SESSION_SECRET "$(openssl rand -hex 32)"
set_if_empty AUTHELIA_STORAGE_ENCRYPTION_KEY "$(openssl rand -hex 32)"
set_if_empty SIPHON_API_KEY "$(openssl rand -hex 32)"
set_if_empty SIPHON_DATABASE_PASSWORD "$(openssl rand -hex 24)"
set_if_empty SIPHON_TELEMETRY_KEY "$(openssl rand -hex 32)"
# Not generated: the tunnel token is issued by Cloudflare, not by us.
grep -qE '^CLOUDFLARE_TUNNEL_TOKEN=.+' "$ENV_FILE" \
    || yellow "  ! CLOUDFLARE_TUNNEL_TOKEN is not set in $ENV_FILE — paste the token from the Cloudflare dashboard"

echo
echo "Next:"
echo "  1. Route both hostnames to http://nginx:80 in the Cloudflare tunnel"
echo "  2. docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.tunnel.yml \\"
echo "       --profile auth --profile tunnel up -d"
echo "  3. Open https://${SIPHON_DOMAIN}"
echo
dim "Full runbook: docs/getting-started/lab.md"
