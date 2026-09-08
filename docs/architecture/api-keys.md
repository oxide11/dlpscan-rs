# API keys, and Siphon as a service

Siphon has two jobs. It is the organisation's DLP engine — the thing behind the
mail filter, the proxy and the file gateway — and it is a **data-security
service** that application owners call directly: send text or a file, get back
what is sensitive in it and how sure the engine is. The second job needs
credentials that identify *who* is calling, what they may do, and whose data
they are allowed to see. This document is the design for those credentials,
and the honest account of what a caller gets today.

It is a plan, not a record. Phases 1–3, 8 and 9 of §10 are done — the scan
gates, mutual TLS on every hop (§9), the key store with its endpoints, and
sensor telemetry (§13) with its Running page. Where the implementation
departed from the plan: `rate_limit` was dropped from the
schema rather than shipped as a column nothing enforces; `scans.api_key_hash`
keeps its legacy contents until it is dropped, with `api_key_id` beside it;
and a `Sensor` role was added (§13), because a detector reporting its own
health needs an identity to report as.

## 1. What an external caller can do today

Every machine caller presents the one shared `SIPHON_API_KEY` and scans:

```bash
curl -sS https://siphon.example/api/scan \
  -H "Authorization: Bearer $SIPHON_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Siphon-Tenant: payments-app" \
  -d '{"text": "card 4111 1111 1111 1111 exp 12/27", "options": {"min_confidence": 0.6}}'
```

```json
{
  "source_pod": "siphon-api",
  "request_id": "0c6f…",
  "findings": [
    {
      "category": "Credit Card Numbers",
      "sub_category": "Visa",
      "text": "411•••••••••111",
      "confidence": 0.96,
      "has_context": true,
      "span": [5, 24],
      "metadata": { "bin_issuer": "…", "validated": "true" }
    }
  ],
  "finding_count": 1,
  "scan_duration_ms": 1
}
```

Three things about that contract are right and should survive:

- **The caller keeps the data; Siphon returns positions.** `text` is redacted
  on every scan response regardless of role. The application already holds
  the input, so `span` is all it needs to redact, tokenize or block on its own
  side, and the engine never has to hand personal data back over the wire.
- **`X-Siphon-Tenant` selects a policy.** A tenant name that matches a ruleset
  in `SIPHON_POLICIES_DIR` becomes that scan's floor — categories, minimum
  confidence, context requirement — so one engine serves many applications
  with different appetites.
- **`POST /scan/batch`, `POST /v1/scan/explain`, `POST /fs/scan`** cover the
  bulk, "why did this match" and file cases with the same key.

And five things are wrong, all of which follow from *one key for everyone*:

| | What happens today | Why it matters for a service |
|---|---|---|
| **Identity** | Every caller is `api-key`. `scans.api_key_hash` stores a hash of the **server's own** key hash (`main.rs`, `persist_scan` call site), so every row is attributed to the deployment, not the caller | You cannot answer "which application sent this?", bill, rate-limit or revoke one caller |
| **Tenant** | `X-Siphon-Tenant` is whatever the caller writes. It picks the policy, tags the rows, and scopes `/v1/findings/stats` and `/v1/findings/export` | Tenant isolation is a claim. Any key holder reads or writes any tenant by editing a header |
| **Scan gate** | `/scan`, `/scan/stream` and `/scan/batch` carry no permission extractor at all — `RequireScan` exists only in a comment. `Permission::Scan` is declared and gates nothing (`/v1/scan/explain` is the exception: it is `AdminAction`, because its trace exposes pipeline internals) | An `Auditor` arriving through the proxy can submit scans. The role that is supposed to read and never act, acts |
| **Rotation** | `SIPHON_API_KEY_SECONDARY` plus a redeploy | Rotating one caller means rotating everyone |
| **siphon-fs** | Its own `SIPHON_API_KEY` and `SIPHON_ADMIN_KEY`, no roles, no tenant | A file upload is authenticated by a different secret than a text scan of the same content |

The old CLI-embedded server (`siphon serve`, `src/api.rs`) has a
`DLPSCAN_API_KEY_ROLES` map that `docs/enterprise/api.md` still documents. It
was never ported to siphon-api, and the docs have described siphon-api as
having it ever since. The plan below replaces both.

## 2. Principles

1. **A key is an identity, not a password to a door.** It carries a role, a
   tenant, an owner and a lifetime, and every row it writes and every audit
   event it causes names it.
2. **Roles, not per-key permission sets.** The request was "keys with
   different permissions". The unit of permission is the role table in
   `src/rbac.rs`, which is reviewed, documented and gated in one place. A key
   with a bespoke permission subset is a role nobody wrote down; give a key a
   role, and if a job needs a new combination, add the role where the others
   are.
3. **The tenant comes from the key.** A key bound to `payments-app` scans as
   `payments-app` and reads only `payments-app`, whatever the header says. The
   header is honoured only for unbound keys held by an `Admin` or `Analyst` —
   the operators of the service, not its customers.
4. **Show the secret once.** The server stores a SHA-256 of a 256-bit random
   secret and can never show it again. (Not argon2: slow hashing defends
   low-entropy passwords against offline guessing, and a random 32-byte secret
   has nothing to defend. Constant-time comparison stays.)
5. **Revocation is soft.** A revoked key stops authenticating immediately and
   its row stays, because the scans it wrote still point at it. Deleting the
   row would orphan the attribution the key existed to provide.
6. **The bootstrap key stays.** `SIPHON_API_KEY` remains the break-glass
   admin credential that lets a deployment come up with no Postgres and lets
   an admin issue the first real key. It is labelled `bootstrap` in every
   audit row, and the startup warning that exists today for
   `SIPHON_API_KEY_ROLE` unset extends to "the bootstrap key is still the
   only key".

## 3. The key model

```
api_keys
  id            TEXT PRIMARY KEY      -- 'sk_' + 12 base32 chars, the public half; appears in logs, rows and the console
  secret_hash   BYTEA NOT NULL UNIQUE -- SHA-256 of the secret; the only thing ever stored
  label         TEXT NOT NULL         -- "payments-app prod", chosen by the issuer
  role          TEXT NOT NULL         -- one of Role::label(); CHECK constraint mirrors the enum
  tenant_id     TEXT                  -- NULL = unbound (operators only, see §2.3)
  created_at    TIMESTAMPTZ NOT NULL
  created_by    TEXT NOT NULL         -- AuthContext.actor of the issuer
  expires_at    TIMESTAMPTZ           -- NULL = does not expire; the console defaults to 1 year
  revoked_at    TIMESTAMPTZ
  revoked_by    TEXT
  last_used_at  TIMESTAMPTZ           -- write-behind, at most once a minute per key
```

(A per-key `rate_limit` was planned here and dropped: a column nothing
enforces is a promise the schema makes and the service breaks. It returns
with the enforcement.)

The secret on the wire is `sk_<id>_<secret>` so a leaked key can be matched
to its row from the prefix alone without knowing the secret — that is what
makes a "this key appeared in a public repo" report actionable.

**Which roles a key may hold.** Any of the seven. The two that matter for the
service case already exist:

- `Operator` — `Scan`, `BatchScan`, `ViewStatus`. The application-owner key:
  it scans and reads nothing back except its own responses.
- `Responder`/`ResponderReadOnly`/`Auditor` bound to a tenant — an application
  team's own investigators, seeing only their own findings.

`Admin` keys are issuable but the console warns on it, and an Admin key bound
to a tenant is refused: admin is by definition unscoped.

**Machines that are not callers.** siphon-icap and siphon-smtp do not call
siphon-api at all — each embeds the engine, authenticates its MTA or proxy by
network allowlist, and writes Postgres directly. Neither protocol carries a
bearer token (ICAP can carry a header; a milter cannot). They therefore hold
no key and no role in this design; their rows are attributed by `channel`
(`icap`, `smtp`) as today. See §8 for the optional ICAP attribution header.

## 4. Storage and lookup

**Migration `0013_api_keys.sql`**, owned by a new library crate
**`siphon-auth`** on the `siphon-mail` precedent: it exports `MIGRATION_SQL`
and the lookup code, siphon-api registers the migration in `db.rs`, and
siphon-fs links the same crate. One implementation of "hash this bearer
value, find its row, decide whether it is live" — because siphon-api and
siphon-fs drifting apart is exactly the state we are in.

**Lookup is cached.** siphon-api and siphon-fs each hold a
`RwLock<HashMap<[u8;32], KeyRecord>>` refreshed from Postgres every 30 s and
invalidated immediately on any write through the issuing endpoints. A request
costs one SHA-256 and one map read — no database round-trip on the hot path.

**Failure direction.** If Postgres is unreachable the cache keeps serving what
it last loaded, and a warning is logged once. A key issued or revoked during
the outage is not seen until the database returns. That is the trade the
service makes: scans keep flowing during a database outage (today they
already do — persistence is fire-and-forget), and a revocation is at most one
refresh interval plus the outage late. Fail-closed here would turn every
Postgres blip into a scanning outage across every integration, which is the
wrong failure for a control that sits in front of mail and web traffic.

**`scans.api_key_hash` becomes attribution.** A new nullable column
`scans.api_key_id TEXT` (and on `findings`, `edm_queries`, `lsh_queries`,
`finding_feedback`) records the key's public id. The existing `api_key_hash`
column stops being written and is dropped in a later migration once nothing
reads it. For proxy callers the column is NULL and `actor` is the identity.

## 5. Endpoints

All under `AdminAction`, all audited with the acting identity:

```
POST   /v1/keys                    issue — body {label, role, tenant_id?, expires_at?, rate_limit?}
                                   → 201 {id, secret, label, role, tenant_id, expires_at}  — the ONLY time `secret` appears
GET    /v1/keys                    list, no secrets, ?include_revoked=
GET    /v1/keys/{id}               one key, with last_used_at
DELETE /v1/keys/{id}               revoke (soft). 204. Idempotent
POST   /v1/keys/{id}/rotate        new secret for the same id; the old secret stays valid for
                                   `grace_seconds` (default 86400, max 7 days) → 200 {secret, old_valid_until}
```

Rotation keeps the id, so attribution is continuous across a rotation and an
application can be re-keyed without a "before/after" split in its history.
This retires the `SIPHON_API_KEY_SECONDARY` dance for everything except the
bootstrap key.

Audit events: `KEY_ISSUE`, `KEY_REVOKE`, `KEY_ROTATE`, each with `key_id`,
`label`, `role`, `tenant_id`, and the actor — never the secret. `GET /v1/me`
gains `key_id` for key-authenticated callers, so an application can confirm
which key it is running with.

## 6. Gating and scoping

Two changes to the request path, both of which stand on their own:

**Gate the scan routes.** `RequireScan` on `/scan` and `/scan/stream`,
`RequireBatchScan` on `/scan/batch`, via the `require_permission!` macro.
`Auditor`, `ResponderReadOnly` and `Viewer` get 403 with a `REJECT` audit
row; `Responder` may scan but not batch. `/v1/scan/explain` stays
`AdminAction`. This is a bug fix and ships first (§10).

**Tenant from the key.** `AuthContext` gains `tenant: Option<String>`. For a
key with `tenant_id` set, that value replaces the header on every read and
write; a mismatched header is a 403, not a silent override, because an
application sending the wrong tenant name is misconfigured and should find
out. For unbound keys and proxy identities the header is used as now, but
only if the role is `Admin` or `Analyst`; other roles ignore it.

Every tenant-aware query — `/v1/findings/pg`, `/stats`, `/export`,
`/v1/stats/throughput` — reads the tenant from `AuthContext`, not from
headers. `/v1/lsh/history` and the EDM/LSH registration reads carry no
tenant filter at all today and gain one in the same change; a tenant-bound
key must not see another tenant's document-similarity history either. This is the change that makes "an
application team's own responders" possible: a `Responder` key bound to
`payments-app` cannot see `hr-portal`'s findings however it asks.

**Attribution.** `persist_scan` and its siblings take the key id from
`AuthContext` instead of hashing the server's key. `/v1/findings/pg` gains a
`?key=` filter so an operator can answer "what has this integration sent us".

## 7. siphon-fs joins the key store

siphon-fs links `siphon-auth`, drops `SIPHON_ADMIN_KEY`, and resolves a bearer
value the same way siphon-api does: bootstrap env key, else table lookup. Its
routes gain the gates they never had — `POST /scan` needs `Scan`,
`GET /v1/findings` needs `ViewAlerts`, `/v1/overrides/reload` needs
`AdminAction` — and its persistence writes the key id and the key's tenant.
The one file-scan credential is then the same credential as the text-scan
one, issued in the same place with the same role.

## 8. Detectors that are not callers

siphon-icap and siphon-smtp keep their network allowlists. What they would
gain from the key store is *attribution across proxies* — three Squid tiers
feeding one ICAP service are indistinguishable today. ICAP permits custom
request headers, so an optional `X-Siphon-Key: sk_…` from the proxy could
stamp `api_key_id` on ICAP rows. Recommended as a later phase, not this one:
it changes nothing about what is allowed, only what is recorded, and no
current deployment has more than one proxy.

The milter has no equivalent and gets none. Its identity is the MTA, which
is `SIPHON_SMTP_ALLOWED_NETS`.

## 9. Mutual TLS on every internal hop

A requirement in its own right, and the other half of what `siphon-auth`
exists for: keys say who a *caller* is; certificates say who a *service* is.
Every hop between a detector and the C2/IR surface or the database
authenticates both ends. Not "encrypted" — **mutually authenticated**, so a
pod that can reach siphon-api's port is still nobody until it presents a
certificate the deployment's CA signed.

Where the hops actually are — this is worth being precise about, because two
of the five components have no hop to secure:

| Hop | Today | After |
|---|---|---|
| nginx → siphon-api (the C2/IR consoles reach the engine here) | plaintext `proxy_pass http://` inside the cluster; Linkerd mTLS if the mesh is on | siphon-api serves TLS (exists: `SIPHON_TLS_CERT`/`KEY`) and **requires a client certificate** chaining to `SIPHON_TLS_CLIENT_CA`. nginx presents one: `proxy_pass https://`, `proxy_ssl_certificate`, `proxy_ssl_verify on`, `proxy_ssl_trusted_certificate`, `proxy_ssl_name` |
| nginx → siphon-fs | plaintext; siphon-fs has never served TLS | siphon-fs gains the same listener and the same client-CA requirement |
| siphon-api, siphon-fs, siphon-smtp → Postgres | `SIPHON_DATABASE_TLS=require` — server certificate verified, client anonymous | new mode **`mtls`**: the service presents `SIPHON_DATABASE_CLIENT_CERT`/`_KEY` and refuses to start without them. Postgres side: `ssl=on`, `ssl_ca_file`, and `pg_hba.conf` `hostssl … scram-sha-256 clientcert=verify-full` — password *and* certificate, with the certificate CN required to match the database user |
| siphon-icap → anything | — | nothing to do. It has no database and never calls siphon-api |
| Squid → siphon-icap, Postfix → siphon-smtp | network allowlist | unchanged. ICAP and the milter protocol carry no TLS; these are the MTA's and proxy's hops, not ours, and are outside this requirement. Stated here so nobody reads "all internal traffic is mTLS" as covering them |

**One implementation.** The Postgres TLS builder is currently three
byte-identical copies (`siphon-api/src/db.rs`, `siphon-fs/src/db.rs`,
`siphon-smtp/src/main.rs`), each ending `.with_no_client_auth()`. That is
three places to add client authentication and three places for one of them
to be forgotten. `siphon_auth::db_tls()` replaces all three; the server-side
`rustls::ServerConfig` with a `WebPkiClientVerifier` lives beside it so
siphon-api and siphon-fs require client certificates the same way.

**Certificates.** `scripts/dev/mkcerts.sh` generates a local CA and one leaf
per identity — `nginx` (client), `siphon-api`, `siphon-fs` (server, with the
Service DNS names as SANs), `postgres` (server), and a DB client cert per
writer whose CN is the Postgres role it connects as. docker-compose mounts
them; the Helm chart takes a `tls.internal.issuerRef` for cert-manager and
otherwise expects the same Secret layout. Linkerd stays available and is no
longer the only thing making the claim true — a compose deployment gets the
same property without a mesh.

**Failure direction.** A service with `mtls` configured and no certificate
does not start. A peer with no certificate or the wrong CA gets a TLS
handshake failure, not a 401 — it never reaches the HTTP layer. This is the
one place in the design that fails closed without a grace path, because a
certificate is deployment configuration, not a runtime credential that can
lag.

## 10. Phasing

Each is one PR, mergeable alone, in this order:

| # | Scope | Ships |
|---|---|---|
| 1 | `fix(api)` — gate `/scan`, `/scan/stream`, `/scan/batch` on `Scan`/`BatchScan` | The bug fix. Small, no schema |
| 2 | `feat(auth)` — `siphon-auth` crate with `db_tls()` (client certs, `mtls` mode) and the server client-verifier; siphon-api, siphon-fs and siphon-smtp adopt it; siphon-fs serves TLS; nginx `proxy_ssl_*`; Postgres `clientcert=verify-full` in compose; `scripts/dev/mkcerts.sh`; Helm values | Every detector ↔ C2/IR/database hop is mutually authenticated (§9) |
| 3 | `feat(auth)` — `0013_api_keys.sql`, cache, key resolution in `auth_middleware`; `POST/GET/DELETE /v1/keys`, `/rotate`; `key_id` on `/v1/me`; audit events; `scans.api_key_id` attribution replacing the server-key hash | Keys exist, authenticate, and every scan names its caller |
| 4 | `feat(console)` — C2 Settings → **API keys**: list, issue dialog (label, role, tenant, expiry, limit), the show-once secret with copy, revoke with confirm, rotate. Absence is a state: "no keys yet" and "key store unavailable — no Postgres" are different screens | An admin can issue a key without `psql` |
| 5 | `feat(api)` — tenant on `AuthContext`; every tenant-aware query reads it from there; header semantics per §6 | Tenant isolation is enforced, not claimed |
| 6 | `feat(fs)` — siphon-fs key resolution through `siphon-auth`, role gates, `SIPHON_ADMIN_KEY` removed | One credential across text and file |
| 7 | `docs` — rewrite `docs/AUTHENTICATION.md` §"API: bearer API keys", `docs/enterprise/api.md`, `rbac.md`; a `docs/getting-started/integrating.md` walking an application owner from "ask for a key" to a handled response | The service has an onboarding document |
| 8 | `feat(api)` + `feat(fs,icap,smtp)` — sensor telemetry per §13: `sensor_status` / `sensor_heartbeats`, `POST /v1/sensors/heartbeat`, `GET /v1/sensors`, each detector reporting with a `Sensor` key over mTLS | mTLS health, availability and efficacy per detector, in one place |
| 9 | `feat(console)` — the Running page renders `GET /v1/sensors` | The operator's three questions answered on one screen |
| 10 | *(optional)* `feat(icap)` — `X-Siphon-Key` attribution header | Per-proxy attribution |

Phases 2–6 each bump the crate their scope names per `CLAUDE.md` versioning.

## 11. The service contract, once this lands

What an application owner does:

1. Asks an admin for a key. The admin opens C2 → Settings → API keys, issues
   one with role `Operator`, tenant `payments-app`, a one-year expiry, and
   hands over the `sk_…` string once. If `rulesets/payments-app.yaml` exists,
   that policy applies to every scan the key makes.
2. Calls `POST /api/scan` (or `/api/scan/batch`, `/fs/scan`) with the bearer
   key. No tenant header needed — the key knows.
3. Gets back categories, sub-categories, confidence, validator state and
   spans. Values are redacted; the application holds the input and acts on
   the spans.
4. Optionally asks for a second key with role `ResponderReadOnly` on the same
   tenant for their own on-call team, who then use the IR console and see
   only their application's findings.

What the organisation gets: every scan attributed to an integration, per-key
rate limits and revocation, tenant isolation enforced server-side, and one
audit trail that names who issued what to whom.

## 13. Sensors: mTLS health, availability and efficacy per detector

A detector is a **sensor**: siphon-fs, siphon-icap, siphon-smtp, and
siphon-api itself for the text channel. The operator's questions about each
are the same three — *is it up, is it talking securely, is it catching
things* — and today none can be answered from one place: each service
knows its own uptime and TLS state, and only siphon-api's channel writes
`scan_rollup`.

**Identity first.** A sensor reports *as* something, and that something is
an issued key with the `Sensor` role — `ReportTelemetry` and `ViewStatus`,
nothing else. This is what "update the detectors to support these API keys"
turns out to mean for the two that never call siphon-api: not a permission
to scan, which they do not need, but an identity with which to report.
`SIPHON_TELEMETRY_URL` + `SIPHON_TELEMETRY_KEY`, over the same mTLS — the
sensor presents its own listener certificate as a client certificate, which
is why every service leaf carries `clientAuth`.

**What a heartbeat carries.** `POST /v1/sensors/heartbeat` every 30 s:

```
sensor      siphon-fs | siphon-icap | siphon-smtp | siphon-api
instance    pod id
version, started_at
transport   { listener: { tls, mtls, cert_not_after },
              database: { mode, client_authenticated } | null,
              upstream:  { verified } }          — what this sensor can vouch for
counters    cumulative since start: scans_total, scans_with_findings,
            findings_total, errors_total, bytes_scanned, duration_ms_sum
```

Stored twice: the latest per `(sensor, instance)` in `sensor_status`, and
every row in `sensor_heartbeats`, pruned on the findings retention window.
The log is what makes availability a measurement rather than a claim.

**What `GET /v1/sensors` answers**, per instance and rolled up per sensor:

| Question | Derived from |
|---|---|
| Up? | `last_seen` within 3 intervals → healthy; else stale, with how long |
| Availability 24 h / 7 d | heartbeats received ÷ heartbeats expected over the window |
| Uptime | `started_at` of the current instance; restarts counted from distinct `started_at` values |
| mTLS health | listener mtls on/off, database client-authenticated yes/no, certificate days remaining — each `ok` / `warn` / `off`, and the roll-up is the worst of them |
| Efficacy | detection rate = scans with findings ÷ scans, from heartbeat counter deltas over the window; precision = true positives ÷ reviewed, from analyst verdicts joined to `scans.source_pod`/channel; evadex bypass rate where a run exists |

Efficacy from counter deltas rather than `scan_rollup` because three of the
four sensors never write rollups, and a heartbeat counter is one row a
sensor already sends. The precision figure is only as good as the verdicts
behind it, and says how many reviewed findings it rests on.

**Where it shows.** C2's Running page, which is currently a stub naming what
the engine would need to provide. This is that.

**Not covered.** Whether the *proxy* or the *MTA* is reaching the sensor is
the proxy's and MTA's health, not ours; a sensor that is up and idle looks
the same as one nothing is wired to. The heartbeat carries the last-scan
time so the console can say "up, and idle for 6 h" rather than "healthy".

## 12. Decisions

Taken 2026-09-08: the recommendations below, all eight, plus the mTLS
requirement in §9. Kept here so the reasoning stays next to the choice.

1. **Roles only, no per-key permission sets** (§2.2). The alternative is a
   `permissions TEXT[]` column that lets an admin compose any subset. Cheaper
   to build, impossible to audit.
2. **Key's tenant is authoritative; a mismatched header is 403** (§6). The
   alternative is silently using the key's tenant, which hides
   misconfiguration.
3. **Soft revocation** (§2.5).
4. **Keep `SIPHON_API_KEY` as the bootstrap admin key** (§2.6). The
   alternative — remove it once any table key exists — makes the first
   deployment and every disaster recovery harder for no security gain, since
   the bootstrap key is already the thing that can issue every other key.
5. **Fail-open cache during a Postgres outage, bounded by the refresh
   interval** (§4). The alternative refuses every scan when the database is
   down.
6. **Rotation grace default 24 h, max 7 days** (§5).
7. **ICAP/SMTP unchanged in this wave** (§8).
8. **New crate `siphon-auth` rather than a module copied into two binaries**
   (§4). It is the `siphon-mail` pattern; the cost is one more workspace
   member and version to track.
