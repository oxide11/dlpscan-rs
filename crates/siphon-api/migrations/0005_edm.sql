-- Migration 0005 — EDM (Exact Data Match) persistence tables.
--
-- edm_registrations: one row per EDM vault registration call, so operators
-- can audit when vaults were loaded and how many records they contained.
--
-- edm_queries: one row per per-scan EDM lookup, allowing trend analysis of
-- EDM match rates, false-positive investigation, and vault effectiveness.

CREATE TABLE IF NOT EXISTS edm_registrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    category        TEXT NOT NULL,
    record_count    INTEGER NOT NULL,
    api_key_hash    BYTEA,
    source_pod      TEXT
);

CREATE INDEX IF NOT EXISTS edm_registrations_created_at
    ON edm_registrations (created_at DESC);

CREATE TABLE IF NOT EXISTS edm_queries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    matched         BOOLEAN NOT NULL,
    category        TEXT,
    confidence      REAL,
    api_key_hash    BYTEA,
    source_pod      TEXT,
    duration_ms     INTEGER
);

CREATE INDEX IF NOT EXISTS edm_queries_created_at
    ON edm_queries (created_at DESC);

CREATE INDEX IF NOT EXISTS edm_queries_matched
    ON edm_queries (matched, created_at DESC);
