-- Analyst feedback columns on the findings table.
--
-- analyst_verdict:  Analyst's assessment — 'tp' (true positive), 'fp' (false
--                   positive), or 'unsure'. NULL means the finding has not
--                   been reviewed yet.
-- reviewed_by_hash: SHA-256 of the API key that submitted the verdict,
--                   same derivation as findings.api_key_hash. Never stores
--                   the raw key.
-- reviewed_at:      Timestamp of the most recent verdict submission.
-- review_note:      Optional free-text analyst comment, capped at 2 000 chars
--                   by the application layer.
--
-- This schema is the prerequisite for every calibration item in FUTURE.md —
-- per-category precision/recall, the self-updating specificity table, and the
-- lightweight reranker all require at least one analyst verdict column before
-- they have anything to compute against.

ALTER TABLE findings
    ADD COLUMN analyst_verdict  TEXT CHECK(analyst_verdict IN ('tp', 'fp', 'unsure')),
    ADD COLUMN reviewed_by_hash BYTEA,
    ADD COLUMN reviewed_at      TIMESTAMPTZ,
    ADD COLUMN review_note      TEXT;

-- Partial index: only covers reviewed rows, which are the minority.
-- Keeps the calibration query (GROUP BY category WHERE verdict IS NOT NULL)
-- off the main findings heap when the table is large.
CREATE INDEX IF NOT EXISTS findings_verdict_category_idx
    ON findings(analyst_verdict, category)
    WHERE analyst_verdict IS NOT NULL;
