-- Migration 0003 — add file-scan columns to scans and findings tables.
-- These columns are populated by siphon-fs; siphon-api text scans leave them NULL.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_name TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_hash BYTEA;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS mime_type TEXT;

CREATE INDEX IF NOT EXISTS scans_file_name_idx ON scans(file_name) WHERE file_name IS NOT NULL;
