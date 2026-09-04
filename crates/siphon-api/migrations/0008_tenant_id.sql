-- Add tenant_id to scans and findings for future multi-tenant isolation.
-- Nullable — existing rows and deployments that don't set X-Siphon-Tenant
-- keep NULL, which is treated as the default tenant everywhere. The column
-- is cheap to add now and avoids a large backfill migration later.
ALTER TABLE scans    ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id TEXT;

CREATE INDEX IF NOT EXISTS scans_tenant_id_idx    ON scans(tenant_id)    WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS findings_tenant_id_idx ON findings(tenant_id) WHERE findings.tenant_id IS NOT NULL;
