-- Scan rollup — aggregate counters for every scan, including clean ones.
--
-- Why this exists
-- ---------------
-- Detection rate needs a denominator. Storing a `scans` row per scan supplies
-- one, but at enterprise mail volume (~10^9 messages/year) that is a billion
-- rows a year to record "nothing found" — 99%+ of the table, none of it an
-- identified event, and the single thing that would force a columnar tier.
--
-- So: identified events keep full rows in `scans`/`findings`; everything
-- scanned is counted here. One row per (hour, tenant, channel) regardless of
-- traffic, which makes the storage cost a function of time and cardinality
-- rather than of volume.
--
-- Cardinality: 8,760 hours/year x tenants x channels. At 50 tenants and 3
-- channels that is ~1.3M rows/year — trivially indexable, and it stays that
-- way whether you scan a thousand messages an hour or a million.
--
-- Rates are computed by the caller from these columns rather than stored, so
-- a rate is never wrong because one of its two inputs was updated and the
-- other was not:
--   detection rate  = scans_with_findings / scans_total
--   findings/scan   = findings_total      / scans_total
--   mean latency    = duration_ms_sum     / scans_total
--   coverage gap    = oversize_skipped    / (scans_total + oversize_skipped)

CREATE TABLE IF NOT EXISTS scan_rollup (
    -- Truncated to the hour (date_trunc('hour', ...)). Hour rather than
    -- minute keeps a year of history small enough to scan without an index
    -- for most queries; finer granularity is available from `findings`
    -- timestamps for the 0.4% of traffic that produces them.
    bucket_hour          TIMESTAMPTZ NOT NULL,

    -- Empty string rather than NULL: this is part of the primary key, and
    -- NULLs are not equal to each other in a unique index, which would let
    -- untenanted rows accumulate duplicates instead of aggregating.
    tenant_id            TEXT        NOT NULL DEFAULT '',

    -- Ingest path: 'api' | 'fs' | 'icap'. Deliberately low cardinality —
    -- anything per-user or per-key belongs in `findings`, not here, or the
    -- row count starts tracking traffic again.
    channel              TEXT        NOT NULL,

    -- Everything the scanner accepted and processed.
    scans_total          BIGINT      NOT NULL DEFAULT 0,
    -- Subset that produced at least one finding: the incident count.
    scans_with_findings  BIGINT      NOT NULL DEFAULT 0,
    -- Total matches, which exceeds scans_with_findings when a scan hits more
    -- than one pattern.
    findings_total       BIGINT      NOT NULL DEFAULT 0,

    bytes_scanned        BIGINT      NOT NULL DEFAULT 0,
    duration_ms_sum      BIGINT      NOT NULL DEFAULT 0,

    -- Content that was NOT inspected because it exceeded the size cap
    -- (MAX_INPUT_SIZE, or SIPHON_ICAP_MAX_BODY_BYTES on the ICAP path, where
    -- oversized bodies pass through unscanned). Counted separately and never
    -- folded into scans_total: a scan that did not happen must not inflate
    -- the denominator and quietly improve the apparent detection rate. This
    -- is the coverage gap, and it should be visible.
    oversize_skipped     BIGINT      NOT NULL DEFAULT 0,

    -- Scans that errored. Also excluded from scans_total, for the same
    -- reason.
    scan_errors          BIGINT      NOT NULL DEFAULT 0,

    PRIMARY KEY (bucket_hour, tenant_id, channel)
);

-- Range queries ("last 30 days") are the dominant access pattern; the primary
-- key's leading column already serves them, but an explicit DESC index keeps
-- the common "most recent first" ordering cheap.
CREATE INDEX IF NOT EXISTS scan_rollup_bucket_hour_idx
    ON scan_rollup (bucket_hour DESC);

COMMENT ON TABLE scan_rollup IS
    'Aggregate scan counters per (hour, tenant, channel). Supplies the '
    'denominator for detection-rate metrics without storing a row per '
    'clean scan. Written by additive UPSERT, so pods flush independently '
    'and their counts sum.';
