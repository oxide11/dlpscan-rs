#!/usr/bin/env bash
# Reset an Authelia user's password in users_database.yml.
#
# Break-glass helper for when Authelia's self-service flow is
# unreachable — typically because the SMTP notifier isn't
# configured (or is broken) and reset-link emails can't be
# delivered. The chart's prod path is `authelia.notifier.smtp.*`
# in deploy/helm/siphon/values.yaml; this script is for the
# moments when you can't wait for SMTP to come back.
#
# What it does:
#   1. Reads the target users_database.yml.
#   2. Confirms the user block exists (won't silently create one).
#   3. Mints an argon2id hash via the official Authelia container,
#      using the same parameters Authelia uses by default
#      (m=65536, t=3, p=4, k=32, salt=16) so a self-service reset
#      and a CLI reset produce indistinguishable hashes.
#   4. Writes the file back in place, with the previous version
#      tucked alongside as `<file>.bak.<unix-ns>`.
#
# Usage:
#   scripts/reset-authelia-password.sh --user admin
#   scripts/reset-authelia-password.sh --user admin --password 'new-pw'
#   scripts/reset-authelia-password.sh --user admin --print
#       # mint the hash but don't touch the file — handy for
#       # piping into a `kubectl edit secret/configmap` flow.
#
# Without --password the script prompts twice with `read -s`.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_FILE="${REPO_ROOT}/deploy/authelia/users_database.yml"
AUTHELIA_IMAGE="authelia/authelia:4.38"

USER=""
PASSWORD=""
FILE="${DEFAULT_FILE}"
PRINT_ONLY=0

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,/^set -Eeuo/p' "$0" | sed 's/^# \?//;$d'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)     USER="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --file)     FILE="${2:-}"; shift 2 ;;
    --print)    PRINT_ONLY=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
done

[[ -n "${USER}" ]] || die "--user is required"

# Pick whichever container runner is on PATH. Authelia ships an
# official OCI image; we deliberately don't try to reimplement
# argon2id in bash — getting the parameters wrong silently
# produces hashes Authelia rejects.
RUNNER=""
for candidate in docker podman; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    RUNNER="${candidate}"
    break
  fi
done
[[ -n "${RUNNER}" ]] || die "neither docker nor podman is installed — install one to mint the hash"

# Read the password if not supplied. Twice, like passwd(1) — the
# whole point of a break-glass reset is precision.
if [[ -z "${PASSWORD}" ]]; then
  read -rsp "New password for ${USER}: " PASSWORD
  printf '\n'
  read -rsp "Confirm: " CONFIRM
  printf '\n'
  [[ "${PASSWORD}" == "${CONFIRM}" ]] || die "passwords don't match"
  unset CONFIRM
fi
[[ -n "${PASSWORD}" ]] || die "empty password rejected"

bold "→ minting argon2id hash via ${AUTHELIA_IMAGE}"
# `authelia crypto hash generate argon2` writes a one-line hash
# prefixed with `Digest: $argon2id$...`. Strip the prefix to get
# the bare hash that goes into users_database.yml.
HASH_RAW="$(${RUNNER} run --rm \
  "${AUTHELIA_IMAGE}" \
  authelia crypto hash generate argon2 \
  --password "${PASSWORD}" \
  --variant id \
  --iterations 3 \
  --memory 65536 \
  --parallelism 4 \
  --key-size 32 \
  --salt-size 16 \
  2>/dev/null)" || die "authelia hash command failed (is the image pullable?)"

HASH="$(printf '%s' "${HASH_RAW}" | awk -F': ' '/^Digest:/ {print $2; exit}')"
[[ "${HASH}" == \$argon2id\$* ]] || die "couldn't parse hash from authelia output: ${HASH_RAW}"

if [[ "${PRINT_ONLY}" -eq 1 ]]; then
  bold "→ generated hash (not writing to ${FILE})"
  printf '%s\n' "${HASH}"
  exit 0
fi

[[ -f "${FILE}" ]] || die "users database not found at: ${FILE}"

# Confirm the user block exists. The file-backed Authelia
# provider uses a top-level `users:` map keyed by username, so
# `^  ${USER}:` is the canonical anchor.
if ! grep -qE "^  ${USER}:$" "${FILE}"; then
  die "user '${USER}' not found in ${FILE} (add the block first, then re-run)"
fi

# Back up before writing. Nanos-resolution suffix so two resets
# in the same second don't clobber each other's backup.
TS="$(date +%s%N)"
BACKUP="${FILE}.bak.${TS}"
cp "${FILE}" "${BACKUP}"
bold "→ backed up ${FILE} → ${BACKUP}"

# Replace the `password:` line *inside the target user's block*.
# awk pass: stay disabled until we see the user's anchor, switch
# active=1, then on the first `password:` line replace and switch
# active=0 so we don't bleed into the next user's block. Anchor
# de-asserts on any non-indented top-level key (defence against
# malformed files).
awk -v user="${USER}" -v hash="${HASH}" '
  BEGIN { active = 0 }
  # Top-of-block anchor: "  <user>:"
  $0 ~ "^  " user ":$" { active = 1; print; next }
  # Any other top-of-block flips us back off.
  active && /^  [A-Za-z0-9_.-]+:$/ { active = 0 }
  # Inside the active block, swap the password line.
  active && /^[[:space:]]+password:/ {
    sub(/password:.*/, "password: \"" hash "\"")
    active = 0
    print
    next
  }
  { print }
' "${FILE}" > "${FILE}.tmp"

mv "${FILE}.tmp" "${FILE}"
bold "✓ password reset for user '${USER}' in ${FILE}"
bold "  next step: redeploy / restart authelia so the file is reloaded"
bold "             (kubectl rollout restart deploy/<authelia>)"
