-- Migration 0004 — findings retention pruning function.
--
-- Existing created_at indexes from 0002_findings.sql already make range
-- deletes fast; no additional index is needed here.

CREATE OR REPLACE FUNCTION prune_findings(older_than_days INTEGER)
RETURNS TABLE(scans_deleted BIGINT, findings_deleted BIGINT) AS $$
DECLARE
    v_scans_deleted BIGINT;
    v_findings_deleted BIGINT;
BEGIN
    DELETE FROM findings
    WHERE created_at < now() - (older_than_days || ' days')::interval;
    GET DIAGNOSTICS v_findings_deleted = ROW_COUNT;

    DELETE FROM scans
    WHERE created_at < now() - (older_than_days || ' days')::interval;
    GET DIAGNOSTICS v_scans_deleted = ROW_COUNT;

    RETURN QUERY SELECT v_scans_deleted, v_findings_deleted;
END;
$$ LANGUAGE plpgsql;
