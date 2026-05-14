-- Bootstrap migration — install the Postgres extensions every
-- subsequent migration assumes is available.
--
-- Why these:
--   pgcrypto — gen_random_uuid() for primary keys without pulling
--              uuid-ossp's heavier surface, and the digest()
--              functions for any column-level hashing we add later.
--   pg_trgm  — trigram indexes for fuzzy substring search across
--              the findings table's matched_text / sub_category
--              columns. The C2's Findings surface will need this
--              for the search box without a full text-search infra
--              build-out.
--
-- Both extensions ship with stock postgres:17-alpine — no extra
-- packages required.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Sanity-check table used by /v1/db/health to round-trip a single
-- row through the pool. Populated on first start and otherwise
-- untouched. Kept tiny on purpose; if it grows, /v1/db/health is
-- doing more than a connection test.
CREATE TABLE IF NOT EXISTS db_health (
    id          INTEGER PRIMARY KEY,
    bootstrapped_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO db_health (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;
