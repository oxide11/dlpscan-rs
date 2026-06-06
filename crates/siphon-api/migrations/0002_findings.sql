-- Findings table — stores every match from every scan
CREATE TABLE IF NOT EXISTS findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Source
    source_pod      TEXT,
    scanner_version TEXT,
    api_key_hash    BYTEA,

    -- Input
    input_hash      BYTEA,
    input_length    INTEGER,

    -- Match
    category        TEXT        NOT NULL,
    sub_category    TEXT,
    confidence      REAL        NOT NULL,
    span_start      INTEGER,
    span_end        INTEGER,
    matched_text    TEXT,

    -- Context
    has_context     BOOLEAN,
    context_required BOOLEAN,

    -- Enrichment
    metadata        JSONB
);

-- Scans table — one row per scan request
CREATE TABLE IF NOT EXISTS scans (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_pod      TEXT,
    scanner_version TEXT,
    api_key_hash    BYTEA,
    input_hash      BYTEA,
    input_length    INTEGER,
    finding_count   INTEGER     NOT NULL DEFAULT 0,
    duration_ms     INTEGER,
    action          TEXT        NOT NULL DEFAULT 'report'
);

CREATE INDEX IF NOT EXISTS findings_scan_id_idx    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_category_idx   ON findings(category);
CREATE INDEX IF NOT EXISTS findings_created_at_idx ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS scans_created_at_idx    ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS scans_api_key_hash_idx  ON scans(api_key_hash);

CREATE INDEX IF NOT EXISTS findings_category_trgm_idx
    ON findings USING gin(category gin_trgm_ops);
