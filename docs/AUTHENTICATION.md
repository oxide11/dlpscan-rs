# Authentication & Zero-Trust

Siphon's deployment model separates three authentication layers,
each of which handles a different threat. Don't try to collapse any
two of them — each layer's job is to catch what the next one
doesn't see.

| Layer | What it authenticates | How | Where it lives |
|-------|-----------------------|-----|-----------------|
| 1. Ingress auth | Human or browser client | OIDC + Passkey (WebAuthn) via Authelia | `deploy/authelia/` + `deploy/nginx/` |
| 2. API auth | Machine-to-machine client | Bearer API key (SHA-256 hashed) | `siphon-api` built-in |
| 3. Pod-to-pod auth | Workload identity | Automatic mTLS via Linkerd | Mesh sidecar, transparent |

## Ingress: Authelia + Nginx forward-auth

Authelia sits behind Nginx as an OIDC identity provider with Passkey
(WebAuthn) as the primary second factor and TOTP retained as a
fallback for clients that can't present a discoverable credential
(shared dev machines, CI runners).

Request flow for a browser hitting `https://siphon.local/api/v1/scan`:

```
┌──────────┐     1. GET /api/v1/scan
│ Browser  │ ────────────────────────────────┐
└──────────┘                                  │
                                              ▼
                                 ┌─────────────────────┐
                                 │ Nginx (reverse proxy)│
                                 └─────────────────────┘
                                              │
                           2. sub-request to Authelia /api/verify
                                              │
                                              ▼
                                 ┌─────────────────────┐
                                 │ Authelia            │
                                 │ ├─ Session cookie?  │
                                 │ └─ No → 401         │
                                 └─────────────────────┘
                                              │
                    3. Nginx sees 401, 302 browser to /auth/?rd=...
                                              │
                                              ▼
                                 ┌─────────────────────┐
                                 │ Authelia login UI   │
                                 │ (password + passkey)│
                                 └─────────────────────┘
                                              │
                   4. On success → session cookie, redirect back
                                              │
                                              ▼
                                 ┌─────────────────────┐
                                 │ Nginx → /api/v1/scan │
                                 │ + Remote-User,      │
                                 │   Remote-Groups,    │
                                 │   Remote-Email      │
                                 └─────────────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────┐
                                 │ siphon-api          │
                                 └─────────────────────┘
```

The Remote-* headers land in siphon-api alongside the existing
`Authorization: Bearer <api-key>` path, so today's API-key clients
keep working while human users get a browser-only passkey flow
without needing to provision an API key per person.

### Local dev

```sh
cd deploy
cp authelia/users_database.yml.example authelia/users_database.yml
# Mint a real password hash and paste it into users_database.yml
docker run --rm authelia/authelia:4.38 \
  authelia crypto hash generate argon2 --password 'dev-password'

docker compose --profile auth up --build
```

Then hit `http://localhost:8080/api/v1/scan` — Nginx bounces you to
the Authelia login, and once you finish the passkey flow the
request goes through to siphon-api.

The filesystem notifier writes "password reset" emails to
`deploy/authelia/notification.txt` so you can exercise the reset
flow without SMTP. Tail that file, grab the link, paste into the
browser.

### Password reset (self-service)

Authelia ships a built-in self-service reset flow — the "Forgot
password?" link on the login page. Behaviour depends on which
notifier the chart is rendering:

| Mode | Trigger | Where the reset link lands |
|------|---------|----------------------------|
| `authelia.notifier.smtp.enabled: false` (default) | "Forgot password?" → username | `/config/notification.txt` inside the Authelia pod (`kubectl exec` + `tail`) |
| `authelia.notifier.smtp.enabled: true` | "Forgot password?" → username | the email address recorded for the user in `users_database.yml`, via the configured SMTP relay |

To enable SMTP delivery (the production path), in your values
override:

```yaml
authelia:
  notifier:
    smtp:
      enabled: true
      host: smtp.example.com
      port: 587
      username: authelia@example.com
      sender: "Siphon <noreply@example.com>"
      identifier: "siphon"
      # tls.skipVerify defaults false. Only set true if your relay's
      # TLS chain isn't publicly trusted; accepting any cert lets a
      # MITM see reset links.
      tls:
        skipVerify: false
```

Then add an `smtp_password` key to the Authelia Secret named in
`authelia.secretName`:

```sh
kubectl patch secret siphon-authelia \
  --type merge \
  -p "{\"stringData\":{\"smtp_password\":\"$(cat smtp.pw)\"}}"
```

The chart automatically wires `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE`
to `/secrets/smtp_password` when `smtp.enabled=true` so Authelia
picks the secret up at startup.

### Password reset (break-glass)

When SMTP is broken (or you can't wait for it to come back),
`scripts/reset-authelia-password.sh` rewrites the user's hash in
`users_database.yml` directly. It's a thin wrapper around the
official Authelia container's `crypto hash generate argon2`
command, so the resulting hash is parameter-identical to one a
self-service reset would produce.

```sh
# Prompts twice for the new password, backs the file up, patches
# in place, prints the next-step kubectl rollout command.
scripts/reset-authelia-password.sh --user admin

# Mint the hash but don't touch the file — useful for piping into
# a `kubectl edit secret` flow if your users_database lives in a
# Secret rather than the chart's seeded ConfigMap.
scripts/reset-authelia-password.sh --user admin --print
```

After patching, restart the Authelia Deployment so it re-reads
the file:

```sh
kubectl -n siphon rollout restart deploy/<authelia-release-name>
```

### Production checklist

Before pointing production traffic at this stack:

- [ ] Replace `authelia/configuration.yml` placeholders (`hmac_secret`,
      `issuer_private_key`, `clients[*].secret`) with real
      cryptographic material.
- [ ] Switch `storage` from SQLite to PostgreSQL.
- [ ] Set `authelia.notifier.smtp.enabled: true` (with `host`,
      `username`, `sender`, and the `smtp_password` key on the
      Authelia Secret) so password-reset links reach a real inbox.
- [ ] Swap `access_control` subject groups from the default
      placeholders to your real auth-backend groups.
- [ ] Mount TLS certs at `/etc/nginx/certs/` and uncomment the TLS
      block in `nginx.conf`.
- [ ] Feed all Authelia secrets from a real secret store
      (External Secrets Operator, Vault, Sealed Secrets) — never
      check in `users_database.yml` or a populated `.env`.

## API: bearer API keys

Unchanged from pre-Phase-2. Machine clients POST to `/api/v1/scan`
with `Authorization: Bearer <siphon-api-key>`; siphon-api hashes
the key (SHA-256) and compares against the hash supplied via
`SIPHON_API_KEY`.

RBAC still flows through `src/rbac.rs`: the key-to-role mapping
assigns each issued key a role (`admin`, `operator`, `analyst`,
`viewer`) and the API handlers check role permissions before
accepting a request.

When a browser request arrives through Authelia, siphon-api sees
both the API-key path (empty) and the Remote-Groups header
populated. The handler can then dispatch on group membership
instead of key-role. See the roadmap's Phase 2 follow-up for the
full OIDC resource-server integration (JWT validation inside
siphon-api), which is deliberately out of scope for this
deployment-scaffolding sprint.

## Pod-to-pod: Linkerd mTLS

Pod-to-pod calls inside the cluster (`siphon-api` reaching
`siphon-fs`, both reaching Redis if the rate-limit feature is on,
etc.) are authenticated and encrypted by **Linkerd** — the lighter
of the two mesh options the roadmap proposed.

Why Linkerd over Istio here:

- Automatic identity rotation (24h) with no config.
- ~5 MB sidecar vs Istio's ~50 MB Envoy.
- No CRD sprawl.
- Istio's broader feature set (traffic splitting, advanced
  authz policies) isn't needed for a two-service stack.

### How it's wired

The lab manifests ship with the annotation on the **namespace**:

```yaml
# deploy/k8s/lab/00-namespace.yaml
metadata:
  annotations:
    linkerd.io/inject: enabled
```

Any pod scheduled into `siphon-lab` inherits the injection. The
Helm chart gates the same annotation on a values flag so prod
clusters opt in explicitly:

```yaml
# values.yaml
linkerd:
  enabled: true
```

### Install prerequisite

Linkerd's control plane must be installed once per cluster:

```sh
# CLI first (one-time local install):
curl --proto '=https' --tlsv1.3 -sSfL https://run.linkerd.io/install | sh
export PATH=$HOME/.linkerd2/bin:$PATH

# Then install into the cluster:
linkerd check --pre
linkerd install --crds | kubectl apply -f -
linkerd install           | kubectl apply -f -
linkerd check
```

After the control plane is ready, `kubectl apply -k deploy/k8s/lab/`
(or `helm install`) will bring Siphon up with sidecars. Verify with:

```sh
linkerd viz stat deploy -n siphon-lab
# Expected: MESHED column shows 1/1 for each Deployment
```

### Traffic policy (optional, recommended)

Once injection is working, tighten the mesh with a Linkerd
`Server` + `ServerAuthorization` pair so only siphon-api can call
siphon-fs (and vice versa). Not shipped here yet — slot in after
the Phase 3 multi-tenancy work nails down which identities should
be allowed to talk to which port.

## Roadmap follow-ups (out of scope for this sprint)

1. **OIDC resource-server in siphon-api.** Validate Authelia's
   JWT access tokens directly so machine clients that already
   speak OIDC don't need a separate API key. Requires picking a
   JWT crate, JWKS fetch + cache, and rotation-aware tests.
2. **Linkerd `ServerAuthorization`.** Bind each Service to a
   specific set of caller ServiceAccounts so a compromised
   sidecar can only reach what its identity permits.
3. **WebAuthn-backed admin console.** The Phase 0 SPA will land
   with `/ui/` routes gated by Authelia's two-factor policy, so
   admin actions require a passkey tap.
