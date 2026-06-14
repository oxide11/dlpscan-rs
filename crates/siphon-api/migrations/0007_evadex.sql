-- Migration 0007 — evadex adversarial-run persistence.
--
-- evadex_runs: one row per completed evadex scan run, capturing
-- summary statistics for detection-rate trending in C2.
--
-- evadex_findings: one row per test variant (up to 2 000 per run),
-- enabling per-technique bypass analysis without post-processing
-- the raw JSON output.

CREATE TABLE IF NOT EXISTS evadex_runs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    run_id          TEXT        NOT NULL UNIQUE,
    scanner_label   TEXT,
    tier            TEXT,
    evasion_mode    TEXT,
    strategy        TEXT,
    total_variants  INTEGER,
    detected        INTEGER,
    bypassed        INTEGER,
    detection_rate  REAL,
    duration_s      REAL,
    evadex_version  TEXT,
    siphon_version  TEXT
);

CREATE INDEX IF NOT EXISTS evadex_runs_created_at_idx
    ON evadex_runs (created_at DESC);

CREATE INDEX IF NOT EXISTS evadex_runs_run_id_idx
    ON evadex_runs (run_id);

CREATE TABLE IF NOT EXISTS evadex_findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          TEXT        NOT NULL REFERENCES evadex_runs(run_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    category        TEXT        NOT NULL,
    technique       TEXT        NOT NULL,
    variant_value   TEXT,
    detected        BOOLEAN     NOT NULL,
    confidence      REAL
);

CREATE INDEX IF NOT EXISTS evadex_findings_run_id_idx
    ON evadex_findings (run_id);

CREATE INDEX IF NOT EXISTS evadex_findings_technique_idx
    ON evadex_findings (technique, detected, created_at DESC);
