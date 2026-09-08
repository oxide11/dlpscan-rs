-- Per-caller API keys. docs/architecture/api-keys.md §3.
--
-- A key is an identity: a role, a tenant, an owner and a lifetime. The
-- secret is never stored — only the SHA-256 of the presented token
-- (`sk_<id>_<secret>`), which is a random 256-bit value and needs no slow
-- hash. The public `id` is what appears in audit rows, scan attribution and
-- the console; a leaked token can be matched to its row from the prefix.
--
-- Revocation is soft: the row stays because scans still point at it.
-- Rotation keeps the id, so attribution is continuous across a re-key; the
-- previous hash stays valid until previous_valid_until.

CREATE TABLE IF NOT EXISTS api_keys (
    id                   TEXT        PRIMARY KEY,
    secret_hash          BYTEA       NOT NULL UNIQUE,
    previous_secret_hash BYTEA,
    previous_valid_until TIMESTAMPTZ,
    label                TEXT        NOT NULL,
    -- Mirrors siphon::rbac::Role::label(). A test in siphon-api asserts the
    -- two lists agree, since the enum and this constraint live in
    -- different crates.
    role                 TEXT        NOT NULL CHECK (role IN (
                             'admin', 'analyst', 'responder', 'responder-readonly',
                             'auditor', 'operator', 'sensor', 'viewer')),
    -- NULL = unbound. Bound keys scan as, and read only, this tenant.
    tenant_id            TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by           TEXT        NOT NULL,
    expires_at           TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ,
    revoked_by           TEXT,
    -- Write-behind, at most once a minute per key.
    last_used_at         TIMESTAMPTZ,
    -- Admin is by definition unscoped.
    CONSTRAINT api_keys_admin_unbound CHECK (NOT (role = 'admin' AND tenant_id IS NOT NULL)),
    CONSTRAINT api_keys_label_nonempty CHECK (length(btrim(label)) > 0)
);

-- The live set is what the auth path loads; revoked rows are history.
CREATE INDEX IF NOT EXISTS api_keys_live_idx
    ON api_keys (id) WHERE revoked_at IS NULL;
