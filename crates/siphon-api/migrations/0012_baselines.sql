-- Per-category detection-quality baselines.
--
-- Stores point-in-time snapshots of per-category precision, recall and F1
-- derived from two sources:
--   Recall    — evadex_findings (evadex planted; scanner found or missed)
--   Precision — findings.analyst_verdict (analyst tp/fp marks from 0011)
--
-- baseline_snapshots groups a set of category rows under one named computation
-- event. Deleting a snapshot cascades to its categories so there is no orphan
-- cleanup needed.
--
-- category_baselines holds one row per (snapshot, category) with computed
-- metrics and Wilson 95% confidence intervals. Categories with no data from a
-- given source carry NULL for that source's columns — the other source can
-- still contribute.
--
-- This is FUTURE.md item 2: the prerequisite that turns "red or green" into
-- "Card Expiry recall -4%" so regressions are visible before they accumulate.

CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    label           TEXT,
    scanner_version TEXT        NOT NULL,
    category_count  INTEGER     NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS category_baselines (
    snapshot_id         UUID  NOT NULL REFERENCES baseline_snapshots(id) ON DELETE CASCADE,
    category            TEXT  NOT NULL,
    -- Recall — from evadex_findings ----------------------------------------
    recall_val          REAL,       -- NULL when no evadex data for category
    recall_tp           INTEGER,    -- detected=true count
    recall_n            INTEGER,    -- total evadex tests for this category
    recall_ci_low       REAL,       -- Wilson 95% CI lower bound
    recall_ci_high      REAL,       -- Wilson 95% CI upper bound
    -- Precision — from analyst verdicts (findings.analyst_verdict) -----------
    precision_val       REAL,       -- NULL when no analyst data for category
    precision_tp        INTEGER,    -- analyst 'tp' count
    precision_n         INTEGER,    -- tp + fp (unsure excluded)
    precision_ci_low    REAL,
    precision_ci_high   REAL,
    -- F1 — harmonic mean; NULL when either side is NULL ---------------------
    f1_val              REAL,
    PRIMARY KEY (snapshot_id, category)
);

-- Snapshot lookup by category for the delta query.
CREATE INDEX IF NOT EXISTS category_baselines_snapshot_idx
    ON category_baselines(snapshot_id, category);
