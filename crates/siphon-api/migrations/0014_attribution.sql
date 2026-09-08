-- Attribute scans to the key that submitted them.
--
-- `scans.api_key_hash` recorded a hash of the SERVER's own configured key,
-- so every row was attributed to the deployment rather than the caller —
-- there was one key, so there was nothing else to record. With per-caller
-- keys (0013) the public key id is the attribution. The old column keeps
-- its legacy contents until nothing reads it, then goes.
--
-- NULL for proxy-authenticated humans (their identity is `actor` in the
-- audit trail) and for the bootstrap SIPHON_API_KEY.

ALTER TABLE scans    ADD COLUMN IF NOT EXISTS api_key_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS api_key_id TEXT;

CREATE INDEX IF NOT EXISTS scans_api_key_id_idx
    ON scans (api_key_id) WHERE api_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS findings_api_key_id_idx
    ON findings (api_key_id) WHERE api_key_id IS NOT NULL;
