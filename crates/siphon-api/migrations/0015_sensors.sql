-- Sensor heartbeats. docs/architecture/api-keys.md §13.
--
-- A sensor is a detector: siphon-fs, siphon-icap, siphon-smtp, and siphon-api
-- itself for the text channel. Each reports on an interval what it is, how
-- it is talking (listener and database transport state) and what it has
-- counted since it started. Every heartbeat is a row; the latest per
-- (sensor, instance) is the sensor's status, and the log is what makes
-- availability a measurement rather than a claim.
--
-- Counters are cumulative since `started_at`. A restart begins a new
-- segment; the reader takes max-min within each segment and sums, so a
-- window's totals survive a restart mid-window. NULL means "this sensor
-- does not count that", which is not zero.
--
-- Pruned on a 30-day window by the retention task. At a 30 s interval one
-- instance writes 2,880 rows a day, so a four-sensor stack holds under half
-- a million rows — small, and the index below is what every read uses.

CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    id                       BIGSERIAL   PRIMARY KEY,
    sensor                   TEXT        NOT NULL,
    instance                 TEXT        NOT NULL,
    -- The Sensor-role key it reported with. NULL for siphon-api's own
    -- heartbeat, which is written in-process.
    api_key_id               TEXT,
    version                  TEXT        NOT NULL,
    started_at               TIMESTAMPTZ NOT NULL,
    received_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The sensor's own cadence, so "expected heartbeats" is per sensor.
    interval_secs            INTEGER     NOT NULL CHECK (interval_secs BETWEEN 5 AND 3600),

    -- Transport. NULL where the sensor has no such hop (the milter has no
    -- listener TLS; siphon-icap has no database).
    listener_tls             BOOLEAN,
    listener_mtls            BOOLEAN,
    listener_cert_not_after  TIMESTAMPTZ,
    db_mode                  TEXT,
    db_client_authenticated  BOOLEAN,

    -- Counters, cumulative since started_at.
    scans_total              BIGINT,
    scans_with_findings      BIGINT,
    findings_total           BIGINT,
    errors_total             BIGINT,
    bytes_scanned            BIGINT,
    duration_ms_sum          BIGINT,
    last_scan_at             TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sensor_heartbeats_recent_idx
    ON sensor_heartbeats (sensor, instance, received_at DESC);
