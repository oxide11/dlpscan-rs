# Running Siphon as a lab, on your own hostname

The end state: `https://siphon.polygoncyber.com` serves the C2 console, you log
in with an account you control, and uploads, scans and findings all work
against a real Postgres. A small VPS runs the stack; Cloudflare fronts it
through a tunnel, so the box needs no inbound firewall rule, no public IP and
no certificate.

## Read this first: it is not the Workers deployment

`deploy/cloudflare/` deploys **siphon-api alone** — a Worker in front of one
container, five allowlisted API paths, no console, no Authelia, no Postgres.
It is an API demo. It cannot show a UI and it has no notion of a login, so it
is the wrong shape for a lab and no amount of configuration makes it the right
one.

**The two cannot share a hostname.** `deploy/cloudflare/wrangler.jsonc`
declares `siphon.polygoncyber.com` as a Worker *custom domain*, which is a DNS
record pointing at the Worker. A tunnel needs its own CNAME to
`<tunnel-id>.cfargotunnel.com` on that same name. Deleting the container does
not remove the route — the binding is a separate object, and it will keep
answering for the hostname.

Take the Worker down before you start:

    Actions → teardown-cloudflare → Run workflow → type DELETE

It deletes the Worker, its container instances **and** the custom domain
binding, and it is reversible: every piece of that config is in the repo, so
`deploy-cloudflare` recreates it later if you want the API demo back.

## What actually runs

`docker compose --profile auth` brings up the whole thing:

| Service | Why it is there |
|---|---|
| `nginx` | serves the console bundle, proxies `/api/` and `/fs/`, runs the Authelia forward-auth sub-request |
| `authelia` | **the account system** — see below |
| `siphon-api` | scanning, findings, RBAC, audit chain |
| `siphon-fs` | file uploads and extraction |
| `postgres` | findings, API keys, sensor heartbeats |
| `siphon-icap`, `siphon-smtp` | the network and mail detectors, if you want them |

`docker-compose.tunnel.yml` adds `cloudflared` and removes nginx's host port
binding — with the tunnel in front, publishing `8080` on the host is a second,
unauthenticated way in.

## Accounts: there is no signup, and that is not a gap

Siphon has never had a user store, a registration endpoint or a "create
account" page. Look for one and you will not find it, because human identity
is **Authelia's** job. An account is an entry in
`deploy/authelia/users_database.yml`, and the `groups:` on that entry are what
`rbac::Role::from_groups` maps to a role — so `admins` is what makes an account
an Admin in the console, not a setting inside Siphon.

`/v1/keys` issues **API keys**, which are machine credentials with a role. They
are not user accounts and cannot log into the console.

## Setup

**1. A VPS.** Two cores and 2 GB is comfortable; Siphon is CPU-bound and
memory-light. Install Docker and clone the repo.

**2. A Cloudflare tunnel.** Zero Trust → Networks → Tunnels → Create, name it,
and copy the token. Add two public hostnames, both pointing at the same
service:

| Hostname | Service |
|---|---|
| `siphon.polygoncyber.com` | `http://nginx:80` |
| `auth.polygoncyber.com` | `http://nginx:80` |

Both go to nginx. It is the `default_server` on port 80, so it answers for any
Host, and it routes `/auth/` to Authelia internally. Both hostnames must sit
under one registrable domain — Authelia scopes its session cookie to the
parent, so a cookie set at `auth.polygoncyber.com` is only sent to
`siphon.polygoncyber.com` because both are under `polygoncyber.com`.

**3. Render the config and create your account.**

    scripts/dev/lab-setup.sh siphon.polygoncyber.com auth.polygoncyber.com

It renders `deploy/authelia/configuration.lab.yml` with your domain (the
committed `configuration.yml` is hardcoded to `siphon.local` in ten places and
stays that way for local dev), prompts for an admin username and password,
hashes the password with Authelia's own argon2, and generates any missing
secrets in `deploy/.env`. Re-running it is safe: it never overwrites an
existing account or an already-set secret.

Then paste the tunnel token into `deploy/.env`:

    CLOUDFLARE_TUNNEL_TOKEN=eyJ...

**4. Up.**

    docker compose -f deploy/docker-compose.yml \
                   -f deploy/docker-compose.tunnel.yml \
                   --profile auth --profile tunnel up -d

First run builds the images, including a full cargo release build, so expect
several minutes.

**5. Open `https://siphon.polygoncyber.com`,** log in with the account you just
created, and you land on the C2 console.

## Checks when it does not work

**A login loop with no error anywhere** is almost always the session cookie
domain. `lab-setup.sh` sets it to the registrable parent for exactly this
reason; if you edited the config by hand, check `session.cookies[].domain` is
`polygoncyber.com` and not `siphon.polygoncyber.com`.

**502 from nginx** means it cannot reach a service. `docker compose ps` — the
`certs-init` container generates the internal mTLS material and must have
completed before `siphon-api` and `siphon-fs` start.

**The tunnel is up but nothing answers:** `docker compose logs cloudflared`.
The ingress hostname in the dashboard must be `http://nginx:80`, not
`localhost` — cloudflared resolves it on the compose network.

**Everything works but findings do not persist:** check `postgres` is healthy
and `SIPHON_DATABASE_PASSWORD` in `deploy/.env` matches what the database was
initialised with. Changing it after first boot does not re-initialise the
volume.

## Two things to know before putting real data through it

**TLS terminates at Cloudflare**, so Cloudflare sees scan payloads in
plaintext. For a DLP scanner the submitted content *is* the sensitive data.
Synthetic test data is fine; anything real is a compliance question you should
answer deliberately.

**`SIPHON_API_KEY_ROLE` defaults to `admin`** and warns at startup. The
bootstrap key is a shared machine credential holding every permission — once
the lab is up, issue narrower per-caller keys with `POST /v1/keys` and set the
bootstrap role to the narrowest thing that still works.
