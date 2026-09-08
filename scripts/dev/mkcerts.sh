#!/usr/bin/env bash
# Generate a private CA and one certificate per service identity, for the
# mutual-TLS hops described in docs/architecture/api-keys.md §9.
#
#   scripts/dev/mkcerts.sh                     # writes deploy/certs/
#   scripts/dev/mkcerts.sh --out /tmp/certs    # somewhere else
#   scripts/dev/mkcerts.sh --namespace prod    # k8s Service SANs for that namespace
#
# Output, one directory per identity so each can be mounted on its own:
#
#   ca/ca.crt, ca/ca.key         the CA. The key never leaves the machine that
#                                issues certificates
#   siphon-api/tls.{crt,key}     listener identity; SAN covers the compose name,
#                                the k8s Service names and localhost
#   siphon-api/db-client.{crt,key}
#                                Postgres client identity, CN = the database role
#   siphon-fs/…                  the same pair
#   siphon-smtp/db-client.{crt,key}
#   postgres/tls.{crt,key}       the database's server certificate
#   nginx/client.{crt,key}       what nginx presents to siphon-api and siphon-fs
#   */ca.crt                     a copy in every directory, so a mount is
#                                self-contained
#
# Service leaves carry BOTH serverAuth and clientAuth, so a container's own
# certificate is also what its health probe presents to its own listener.
# Client-only identities (nginx, the database clients) carry clientAuth alone.
#
# This is a development and reference-deployment tool. In a cluster,
# cert-manager issues the same identities from `tls.internal.certManager` in
# the Helm chart; in production compose, replace deploy/certs/ with material
# from the organisation's PKI in the same layout.
#
# deploy/certs/ is gitignored (`certs/`, `*.key`, `*.crt`). Nothing here is
# ever committed.
set -Eeuo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deploy/certs"
DAYS=825
NS=siphon
DB_ROLE=siphon
QUIET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)       OUT="$2"; shift 2 ;;
    --days)      DAYS="$2"; shift 2 ;;
    --namespace) NS="$2"; shift 2 ;;
    --db-role)   DB_ROLE="$2"; shift 2 ;;
    --quiet)     QUIET=1; shift ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

say() { [[ $QUIET -eq 1 ]] || printf '%s\n' "$*"; }

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

umask 077

# --- CA ---------------------------------------------------------------------
mkdir -p ca
if [[ -f ca/ca.key && -f ca/ca.crt ]]; then
  say "ca/ca.crt exists — reusing (delete $OUT/ca to rotate the CA)"
else
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout ca/ca.key -out ca/ca.crt -days "$DAYS" \
    -subj "/O=Siphon/CN=Siphon internal CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
  say "ca/ca.crt"
fi

# leaf <dir> <file-stem> <CN> <EKU> <SAN>
leaf() {
  local dir="$1" stem="$2" cn="$3" eku="$4" san="$5"
  mkdir -p "$dir"
  local key="$dir/$stem.key" crt="$dir/$stem.crt"
  local csr ext
  csr="$(mktemp)"; ext="$(mktemp)"
  cat > "$ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$eku
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$san
EOF
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$key" -out "$csr" -subj "/O=Siphon/CN=$cn" 2>/dev/null
  openssl x509 -req -in "$csr" -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -days "$DAYS" -out "$crt" -extfile "$ext" 2>/dev/null
  rm -f "$csr" "$ext"
  chmod 600 "$key"
  chmod 644 "$crt"
  cp ca/ca.crt "$dir/ca.crt"
  say "$crt"
}

# Every name a service is reached by: the compose service name, the Helm
# Service name and its in-cluster FQDNs, and localhost for its own probe.
svc_san() {
  local n="$1"
  printf 'DNS:%s,DNS:siphon-%s,DNS:siphon-%s.%s,DNS:siphon-%s.%s.svc,DNS:siphon-%s.%s.svc.cluster.local,DNS:localhost,IP:127.0.0.1' \
    "$n" "$n" "$n" "$NS" "$n" "$NS" "$n" "$NS"
}

# Listeners. Both EKUs: the service's own health probe presents this same
# certificate to its own mTLS listener.
leaf siphon-api tls siphon-api "serverAuth,clientAuth" "$(svc_san api)"
leaf siphon-fs  tls siphon-fs  "serverAuth,clientAuth" "$(svc_san fs)"

# The database's server certificate. `postgres` is the compose name;
# `siphon-postgres` the Helm Service.
leaf postgres tls postgres "serverAuth" \
  "DNS:postgres,DNS:siphon-postgres,DNS:siphon-postgres.$NS,DNS:siphon-postgres.$NS.svc,DNS:siphon-postgres.$NS.svc.cluster.local,DNS:localhost,IP:127.0.0.1"

# Postgres client identities. CN is the DATABASE ROLE, not the service: with
# `clientcert=verify-full` the server checks the CN against the connecting
# user name, and a certificate that chains correctly but carries the wrong CN
# is refused with an error that looks like a bad password. One key pair per
# service all the same, so a single leaked key revokes one writer, not three.
for svc in siphon-api siphon-fs siphon-smtp; do
  leaf "$svc" db-client "$DB_ROLE" "clientAuth" "DNS:$svc"
done

# What nginx presents upstream.
leaf nginx client siphon-nginx "clientAuth" "DNS:siphon-nginx"

chmod 644 ca/ca.crt

say ""
say "wrote $OUT ($(find . -name '*.crt' | wc -l | tr -d ' ') certificates, CA valid $DAYS days)"
say "namespace SANs: $NS   database role CN: $DB_ROLE"
