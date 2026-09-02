# Siphon on Cloudflare Workers + Containers

Deploys `siphon-api` to `siphon.<your-domain>` as a **demo / testing**
endpoint, using a Worker at the edge and a Container running the unmodified
`deploy/Dockerfile.api` image.

> **Scope: demo and testing.** This configuration deliberately runs without
> Postgres persistence and without the on-disk audit chain — see
> [Trade-offs](#trade-offs). Do not put regulated or production data through
> it.

## Why Containers and not a Worker

Workers run V8 isolates (JS/WASM). `siphon-api` cannot run there without a
substantial port: `siphon-core` fans 568 regexes across cores with `rayon`
(`scanner/mod.rs`), and the service depends on multi-threaded `tokio`,
`axum-server`/rustls, `sqlx`, and `notify` (the `SIPHON_OVERRIDES_PATH` file
watcher). Containers runs a real OCI image, so all of that works unchanged.

## Architecture

```
siphon.<domain>  ->  Worker (src/index.ts)  ->  Container (siphon-api:8080)
                     - client-IP rate limit
                     - public path allowlist
                     - payload cap
                     - injects SIPHON_API_KEY
```

The Worker owns everything that must not be delegated to the origin. In
particular it owns rate limiting, for a concrete reason: every rate-limited
handler in `siphon-api` derives the client from `ConnectInfo<SocketAddr>`
(`main.rs:445`, `561`, `923`, …) and there is **no** `CF-Connecting-IP` or
`X-Forwarded-For` handling anywhere in the crate. Behind any proxy, all
requests appear to originate from one address, so the per-IP limit collapses
into a single global bucket — one noisy client would starve everyone. The
edge limiter keys on `CF-Connecting-IP`, which Cloudflare sets and strips
from client input, so it is trustworthy at this hop.

## Prerequisites

- A Cloudflare account on **Workers Paid** ($5/mo) — Containers requires it.
- The domain active on Cloudflare (the zone must exist; the DNS record and
  certificate are created for you on first deploy).

## Deploy via CI (recommended)

`.github/workflows/deploy-cloudflare.yml` builds and deploys on pushes to
`main` that touch `deploy/cloudflare/**` or `deploy/Dockerfile.api`, and on
manual dispatch. Pull requests run typecheck only and never deploy.

One-time setup — add three **repository secrets** (GitHub → Settings →
Secrets and variables → Actions):

| Secret | Where it comes from |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare dashboard → My Profile → API Tokens. Needs Workers Scripts:Edit and Containers permissions on the zone. |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare dashboard → Workers & Pages (right sidebar). |
| `SIPHON_API_KEY` | Any strong random string you generate. Uploaded to the Worker as a secret on every deploy, so rotating it is just a secret change. |

Then run the workflow (Actions → **deploy-cloudflare** → Run workflow), or
merge a change under `deploy/cloudflare/`. The hostname in `wrangler.jsonc`
`routes` is created automatically — no dashboard clicking.

The deploy job builds `deploy/Dockerfile.api`, a full cargo release build of
the workspace, so it is substantially slower than `ci.yml`. It is
path-filtered so ordinary pushes never trigger it.

## Taking it offline

`.github/workflows/teardown-cloudflare.yml` deletes the Worker, its container
instances and the custom domain binding. Manual dispatch only — deleting a live
public endpoint should not be reachable by merging a branch — and it requires
typing `DELETE` into the confirmation box.

    Actions → teardown-cloudflare → Run workflow → type DELETE

It is reversible. Every piece of configuration lives in this repository, so
`deploy-cloudflare` recreates the Worker, the DNS record and the certificate
from `wrangler.jsonc`. A teardown costs a redeploy, not a rebuild. Repository
secrets are left alone, since they are what a redeploy needs.

Worth knowing before reaching for it: the container already sleeps after 15
minutes idle and charges stop while it sleeps, so an unused demo costs close to
the $5/mo base plan on its own. Tear down to free the hostname or to stop
serving a stale API, not to save money.

## Deploy from a laptop (alternative)

Only needed if you want to deploy without CI. Requires Docker running
locally, since Wrangler shells out to it to build the image.

```bash
cd deploy/cloudflare
npm install
wrangler secret put SIPHON_API_KEY   # one-time
npm run deploy
```

## Verify

```bash
curl https://siphon.<your-domain>/health
curl -X POST https://siphon.<your-domain>/scan \
  -H 'content-type: application/json' \
  -d '{"text":"card 4111-1111-1111-1111 and ssn 536-90-4399"}'
```

## Public surface

The Worker allowlists these paths; everything else returns 404:

| Path | Purpose |
|---|---|
| `GET /health`, `GET /ready` | probes (not rate limited) |
| `POST /scan` | single-text scan |
| `POST /scan/batch` | batch scan |
| `POST /v1/scan/explain` | per-finding pipeline trace |
| `GET /v1/categories` | category catalog |

It is an allowlist, not a denylist, so any route added to `siphon-api` later
is closed by default rather than silently exposed. `siphon-api` also serves
admin and mutating endpoints — `POST /v1/overrides/apply`,
`POST /v1/findings/prune`, `POST /v1/evadex/runs`, `GET /v1/audit` — which
must never be internet-reachable. Edit `PUBLIC_PATHS` in `src/index.ts` to
change the surface.

## Trade-offs

**Cold start.** A fresh process pays ~324 ms building 568 regex DFAs and the
~5,000-keyword Aho-Corasick automaton, versus ~0.5 ms warm (measured on
full-speed multi-core hardware; expect more on ½ vCPU). Container disk is
**ephemeral and reset on every wake**, so every wake is cold. `onStart()`
fires a warmup scan to move that cost off the first user request, and
`sleepAfter = "15m"` keeps a demo session warm across pauses.

**No persistence.** `SIPHON_DATABASE_URL` is unset, so `db.rs` runs in its
`Unconfigured` state: findings live only in the per-instance in-memory ring.
`/v1/findings/pg`, stats, export, and retention are unavailable — which is
why they are not in the allowlist. Add a managed Postgres (Neon, Supabase)
and set the variable if you want history.

**No on-disk audit chain.** `SIPHON_AUDIT_LOG_PATH` / `SIPHON_AUDIT_TAIL_PATH`
are unset on purpose. Ephemeral disk would reset the tamper-evident HMAC
chain on every wake, making it silently discontinuous — worse than absent.

**Sizing.** Siphon is CPU-bound and memory-light (Helm asks 256Mi, limits
1Gi), but Cloudflare bills memory on *provisioned* capacity and custom
instances enforce a minimum 3 GiB per vCPU — so you cannot buy CPU without
buying memory you will not use. `standard-1` (½ vCPU / 4 GiB) is the demo
compromise; `basic` (¼ vCPU) roughly doubles cold start.

## Cost

Billing is per 10 ms while awake: CPU on **actual** usage, memory and disk on
**provisioned** capacity. Charges stop on sleep, so idle time is the lever.

- Idle most of the day (~2 h/day awake), `standard-1`: **≈ $8/mo** including
  the $5 plan.
- Always awake, `standard-1`: **≈ $30/mo** — at which point a small VPS
  running `deploy/docker-compose.yml` behind a Cloudflare Tunnel is cheaper.

Rates change; check the [pricing docs](https://developers.cloudflare.com/containers/pricing/)
before relying on these figures.

## Notes

- TLS terminates at Cloudflare, which therefore sees scan payloads in
  plaintext. For a DLP scanner the submitted data *is* the sensitive data —
  fine for synthetic demo input, a compliance question for anything real.
- Keep `siphon-launcher` out of this deployment. It has no authentication and
  hard-exits on a non-loopback bind by design.
- `SIPHON_BIND` **must** be `0.0.0.0`. It defaults to `127.0.0.1`
  (`main.rs:5300`), which would make the container unreachable from the
  Worker. Set in `envVars` in `src/index.ts`.
