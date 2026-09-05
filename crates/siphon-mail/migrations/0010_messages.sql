-- Migration 0010 — message / message_parts model for the mail path.
--
-- A message is not one scan. It is a tree of parts, each independently
-- scannable, whose results reconcile into one verdict. See
-- docs/architecture/email-dlp.md §2.
--
-- Nothing writes these tables yet; siphon-milter does. They land first
-- because §2 is explicit that this schema is painful to retrofit, and
-- because the fail-closed default (§4.4) makes MTA retries the normal
-- operating mode rather than an edge case — so the idempotency guarantees
-- here have to exist before the milter can rely on them.

CREATE TABLE IF NOT EXISTS messages (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NOT NULL, unlike scans.tenant_id and findings.tenant_id, which are
    -- nullable with NULL meaning the default tenant. The difference is
    -- deliberate: here tenant participates in an identity lookup, and in a
    -- unique index NULL never equals NULL — two retries of the same message
    -- on the default tenant would each insert a new row and the retry guard
    -- below would silently do nothing. A sentinel makes the comparison work.
    tenant_id        TEXT        NOT NULL DEFAULT 'default',

    -- Stable across delivery attempts, supplied by the MTA (Postfix's queue
    -- ID via the {i} macro). This is what makes a retry find its existing
    -- row instead of minting a second one.
    --
    -- The internal UUID is still the identity; this is only the key used to
    -- resolve it on re-delivery. Nullable because a caller that has no such
    -- identifier should get a plain insert rather than a false match — the
    -- partial index below only constrains rows that actually carry one.
    ingest_key       TEXT,

    direction        TEXT        NOT NULL,
    -- RFC 5322 Message-ID: an indexed attribute for investigator lookup,
    -- never an identity. Client-supplied, forgeable, sometimes absent, and
    -- not reliably unique.
    rfc_message_id   TEXT,
    sender           TEXT,
    recipients       TEXT[],
    subject_hash     BYTEA,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    part_count       INTEGER     NOT NULL DEFAULT 0,
    -- Recomputed from message_parts by reconcile, never incremented in
    -- place: a retry re-scanning a part would otherwise count it twice and
    -- the message would look complete while a part was still pending.
    parts_completed  INTEGER     NOT NULL DEFAULT 0,

    verdict          TEXT,
    verdict_at       TIMESTAMPTZ,

    CONSTRAINT messages_direction_ck
        CHECK (direction IN ('inbound', 'outbound')),
    CONSTRAINT messages_verdict_ck
        CHECK (verdict IS NULL OR verdict IN
               ('clean', 'flagged', 'quarantine', 'block', 'indeterminate'))
);

-- The retry guard. Partial so that rows without an MTA identifier are
-- unconstrained rather than colliding with each other on NULL.
--
-- Caveat worth knowing: Postfix reuses queue IDs over long periods (they
-- derive from inode and time). With enable_long_queue_ids=yes collisions are
-- remote, and retention prunes rows long before reuse becomes plausible — but
-- this is a practical guarantee, not a mathematical one.
CREATE UNIQUE INDEX IF NOT EXISTS messages_tenant_ingest_key_uidx
    ON messages (tenant_id, ingest_key)
    WHERE ingest_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS messages_received_at_idx
    ON messages (received_at DESC);
CREATE INDEX IF NOT EXISTS messages_tenant_id_idx
    ON messages (tenant_id);
CREATE INDEX IF NOT EXISTS messages_rfc_message_id_idx
    ON messages (rfc_message_id)
    WHERE rfc_message_id IS NOT NULL;
-- Partial: the interesting query is "what did we fail to fully inspect",
-- and clean is the overwhelming majority of the table.
CREATE INDEX IF NOT EXISTS messages_unresolved_idx
    ON messages (received_at DESC)
    WHERE verdict IS NULL OR verdict = 'indeterminate';


CREATE TABLE IF NOT EXISTS message_parts (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    message_uuid   UUID        NOT NULL REFERENCES messages(id) ON DELETE CASCADE,

    -- NULL at top level. Non-NULL for parts inside a forwarded message or an
    -- expanded archive, which is what makes this table self-referential
    -- without a second table.
    parent_path    TEXT,
    -- Dotted MIME path ("1", "2.1.4"), never an ordinal: MIME nests, and a
    -- path stays stable across an MTA retry where a re-derived index would
    -- not.
    mime_path      TEXT        NOT NULL,

    content_type   TEXT,
    filename       TEXT,
    -- Deduping by content within one message is a legitimate optimisation —
    -- scan once, attribute to every part carrying those bytes. Across
    -- messages it is a bypass (§6), so this is recorded, never used as a
    -- cross-message key.
    content_hash   BYTEA,
    content_length INTEGER,

    -- Joins to scans / findings. NULL while pending, and for parts that were
    -- never scanned.
    scan_id        UUID,
    status         TEXT        NOT NULL DEFAULT 'pending',
    -- Why a part was not scanned, for the statuses that need it. Free text:
    -- it is shown to an analyst, not matched on.
    detail         TEXT,

    finding_count  INTEGER     NOT NULL DEFAULT 0,
    max_confidence REAL,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The idempotency guard §2 names: an MTA retry re-derives the same paths
    -- and upserts rather than duplicating. Load-bearing under the fail-closed
    -- default, where every tempfail produces a redelivery.
    CONSTRAINT message_parts_path_uq UNIQUE (message_uuid, mime_path),

    -- Every status that is not 'scanned' means something was not inspected,
    -- which must never reconcile to clean. Enumerated rather than free text
    -- so a new skip reason has to be added deliberately here and in the
    -- verdict ladder, not just written into a row.
    CONSTRAINT message_parts_status_ck
        CHECK (status IN ('pending', 'scanned', 'skipped_oversize',
                          'skipped_encrypted', 'skipped_nested_archive',
                          'skipped_unsupported', 'error'))
);

CREATE INDEX IF NOT EXISTS message_parts_message_uuid_idx
    ON message_parts (message_uuid);
CREATE INDEX IF NOT EXISTS message_parts_scan_id_idx
    ON message_parts (scan_id)
    WHERE scan_id IS NOT NULL;
-- Partial for the same reason as messages_unresolved_idx: 'scanned' is the
-- overwhelming majority, and the query that matters is the complement.
CREATE INDEX IF NOT EXISTS message_parts_unresolved_idx
    ON message_parts (message_uuid)
    WHERE status <> 'scanned';


-- Retention. messages is the parent, so ON DELETE CASCADE takes the parts
-- with it; deleting parts separately would be both slower and wrong if a
-- message outlived its own parts.
--
-- Kept separate from prune_findings() rather than folded into it: findings
-- and messages have independent lifetimes (a findings row can be pruned
-- while its message is still under investigation), and one function
-- returning four counts reads worse than two returning two.
CREATE OR REPLACE FUNCTION prune_messages(older_than_days INTEGER)
RETURNS TABLE(messages_deleted BIGINT, parts_deleted BIGINT) AS $$
DECLARE
    v_messages_deleted BIGINT;
    v_parts_deleted BIGINT;
BEGIN
    SELECT count(*) INTO v_parts_deleted
    FROM message_parts p
    JOIN messages m ON m.id = p.message_uuid
    WHERE m.received_at < now() - (older_than_days || ' days')::interval;

    DELETE FROM messages
    WHERE received_at < now() - (older_than_days || ' days')::interval;
    GET DIAGNOSTICS v_messages_deleted = ROW_COUNT;

    RETURN QUERY SELECT v_messages_deleted, v_parts_deleted;
END;
$$ LANGUAGE plpgsql;
