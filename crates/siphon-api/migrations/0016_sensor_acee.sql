-- Sensor posture, coverage and canary. docs/architecture/acee.md.
--
-- Three additions to the heartbeat row, one per ACEE axis the first cut
-- could not read:
--
--   posture_*        Availability's third term. A heartbeat proves the sensor
--                    is running; this records whether it is doing its whole
--                    job — blocking, annotating or advising; failing closed
--                    or open; and why it is degraded, if it is. NULL means
--                    the sensor did not say, which the reader shows as
--                    "not reported", never as "enforcing".
--   unscanned_total  Coverage at depth: items the sensor saw and passed
--                    without reading. scans ÷ (scans + unscanned) is the
--                    fraction of what reached the sensor that it inspected.
--                    Cumulative, like every other counter.
--   canary_*         Efficacy's recall term. Once per beat the sensor scans
--                    a fixed fixture through its own deployed path and
--                    reports whether every planted category came back. NULL
--                    is "did not run", which the reader shows as unverified.

ALTER TABLE sensor_heartbeats
    ADD COLUMN IF NOT EXISTS posture_on_finding       TEXT,
    ADD COLUMN IF NOT EXISTS posture_on_indeterminate TEXT,
    ADD COLUMN IF NOT EXISTS posture_degraded         TEXT,
    ADD COLUMN IF NOT EXISTS unscanned_total          BIGINT,
    ADD COLUMN IF NOT EXISTS canary_passed            BOOLEAN,
    ADD COLUMN IF NOT EXISTS canary_detail            TEXT;
