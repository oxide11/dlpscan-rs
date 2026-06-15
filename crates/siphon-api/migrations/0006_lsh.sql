-- Migration 0006 — LSH (Locality-Sensitive Hashing / Document Similarity) persistence tables.
--
-- lsh_registrations: one row per document registered into a vault, so operators
-- can audit vault composition and track registration activity over time.
--
-- lsh_queries: one row per per-scan LSH lookup, allowing trend analysis of
-- document similarity match rates and vault effectiveness.

CREATE TABLE IF NOT EXISTS lsh_registrations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    document_id     TEXT        NOT NULL,
    document_hash   BYTEA       NOT NULL,
    document_length INTEGER,
    api_key_hash    BYTEA,
    source_pod      TEXT,
    scanner_version TEXT
);

CREATE INDEX IF NOT EXISTS lsh_registrations_created_at_idx
    ON lsh_registrations (created_at DESC);

CREATE INDEX IF NOT EXISTS lsh_registrations_doc_id_idx
    ON lsh_registrations (document_id);

CREATE TABLE IF NOT EXISTS lsh_queries (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    query_hash      BYTEA       NOT NULL,
    query_length    INTEGER,
    matched         BOOLEAN     NOT NULL,
    matched_doc_id  TEXT,
    similarity      REAL,
    api_key_hash    BYTEA,
    source_pod      TEXT,
    duration_ms     INTEGER
);

CREATE INDEX IF NOT EXISTS lsh_queries_created_at_idx
    ON lsh_queries (created_at DESC);

CREATE INDEX IF NOT EXISTS lsh_queries_matched_idx
    ON lsh_queries (matched, created_at DESC);
