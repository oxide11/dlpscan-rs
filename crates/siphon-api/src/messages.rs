//! Message / message-parts model for the mail path.
//!
//! A message is not one scan. It is a tree of parts, each independently
//! scannable, whose results reconcile into one verdict — see
//! `docs/architecture/email-dlp.md` §2 and §4.3.
//!
//! Nothing writes these tables yet; `siphon-milter` does. The schema and this
//! layer land first for two reasons. §2 is explicit that the model is painful
//! to retrofit. And the fail-closed default of §4.4 makes an MTA retry the
//! normal operating mode rather than an edge case: every tempfail — every
//! timeout, extraction failure and oversize part — comes back as a
//! redelivery, so the idempotency guarantees here have to exist before the
//! milter can lean on them.
//!
//! # Identity, and what makes a retry idempotent
//!
//! §2 says `UNIQUE (message_uuid, mime_path)` is the idempotency guard: a
//! retry re-derives the same paths and upserts rather than duplicating. That
//! is only true if `message_uuid` is *the same* on the retry, and §2 does not
//! say how it becomes so — mint a fresh UUID per delivery attempt and the
//! guard protects nothing, because the retry writes a whole new message.
//!
//! So the message row carries an `ingest_key`: an identifier supplied by the
//! MTA that is stable across delivery attempts of one queued message
//! (Postfix's queue ID, the `{i}` macro). [`resolve_message`] upserts on
//! `(tenant_id, ingest_key)` and returns the existing UUID when one is
//! already there. The internal UUID remains the identity; the ingest key is
//! only how a redelivery finds it again.
//!
//! Without an ingest key a caller gets a plain insert. That is the honest
//! behaviour — a false match would attach one message's parts to another —
//! but it means such a caller has no retry protection, which is worth knowing
//! before wiring an MTA that cannot supply one.

use uuid::Uuid;

/// Direction of travel. Stored as text so a `messages` row reads without a
/// lookup table; constrained in SQL by `messages_direction_ck`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// What happened to one part.
///
/// Every value other than `Scanned` means something was not inspected, which
/// must never reconcile to clean. The set is enumerated here and in
/// `message_parts_status_ck` so a new skip reason has to be added
/// deliberately in both places and in the verdict ladder — rather than being
/// written into a row and silently treated as "fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartStatus {
    /// Recorded but not yet scanned.
    Pending,
    Scanned,
    /// Extracted text exceeded `MAX_INPUT_SIZE`. Reported not scanned, never
    /// clean — the extraction work was done and discarded.
    SkippedOversize,
    /// An encrypted archive entry, which cannot be opened without a password.
    SkippedEncrypted,
    /// A nested archive, which is surfaced rather than recursed into.
    SkippedNestedArchive,
    /// No extractor for this format.
    SkippedUnsupported,
    /// Extraction or scanning failed.
    Error,
}

impl PartStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PartStatus::Pending => "pending",
            PartStatus::Scanned => "scanned",
            PartStatus::SkippedOversize => "skipped_oversize",
            PartStatus::SkippedEncrypted => "skipped_encrypted",
            PartStatus::SkippedNestedArchive => "skipped_nested_archive",
            PartStatus::SkippedUnsupported => "skipped_unsupported",
            PartStatus::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => PartStatus::Pending,
            "scanned" => PartStatus::Scanned,
            "skipped_oversize" => PartStatus::SkippedOversize,
            "skipped_encrypted" => PartStatus::SkippedEncrypted,
            "skipped_nested_archive" => PartStatus::SkippedNestedArchive,
            "skipped_unsupported" => PartStatus::SkippedUnsupported,
            "error" => PartStatus::Error,
            _ => return None,
        })
    }

    /// Did we actually look at this part's content?
    ///
    /// The single place that decides what counts as inspected. A new status
    /// added without touching this would default to "not inspected" only
    /// because the match is exhaustive — which is the safe direction.
    pub fn is_inspected(self) -> bool {
        matches!(self, PartStatus::Scanned)
    }
}

/// A message-level verdict.
///
/// Ordering is severity, and it is what [`reconcile`] maxes over, so the
/// declaration order is load-bearing rather than cosmetic.
///
/// `Indeterminate` sits above `Clean` and below `Flagged`, which is the whole
/// point of §4.3:
///
/// * Above `Clean`, because a message with an uninspected part has not been
///   cleared. Nineteen clean attachments and one that timed out is not a
///   clean message.
/// * Below `Flagged`, because a confirmed finding is a stronger and more
///   actionable statement than "something went unlooked-at". A message that
///   is both flagged and incompletely inspected reports `flagged` — and the
///   incompleteness is not lost, because `parts_completed < part_count` and
///   the part rows themselves still record it.
///
/// So `indeterminate` surfaces exactly when it is the most severe thing true
/// of a message: nothing was found, and not everything was examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Clean,
    Indeterminate,
    Flagged,
    Quarantine,
    Block,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Indeterminate => "indeterminate",
            Verdict::Flagged => "flagged",
            Verdict::Quarantine => "quarantine",
            Verdict::Block => "block",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "clean" => Verdict::Clean,
            "indeterminate" => Verdict::Indeterminate,
            "flagged" => Verdict::Flagged,
            "quarantine" => Verdict::Quarantine,
            "block" => Verdict::Block,
            _ => return None,
        })
    }
}

/// One part's contribution to the message verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartOutcome {
    pub status: PartStatus,
    /// The verdict policy assigned to this part's findings.
    ///
    /// Only meaningful when `status` is `Scanned`; ignored otherwise, since a
    /// part that was not inspected has no findings to judge. Policy lives in
    /// the caller — this module maxes verdicts, it does not decide what a
    /// credit-card number is worth.
    pub scanned_verdict: Option<Verdict>,
}

impl PartOutcome {
    pub fn scanned(verdict: Verdict) -> Self {
        Self {
            status: PartStatus::Scanned,
            scanned_verdict: Some(verdict),
        }
    }

    pub fn uninspected(status: PartStatus) -> Self {
        Self {
            status,
            scanned_verdict: None,
        }
    }

    /// This part alone, as a verdict.
    fn verdict(self) -> Verdict {
        if self.status.is_inspected() {
            self.scanned_verdict.unwrap_or(Verdict::Clean)
        } else {
            Verdict::Indeterminate
        }
    }
}

/// Reconcile part outcomes into one message verdict: the maximum severity.
///
/// An empty part list yields `Indeterminate`, not `Clean`. A message we
/// recorded but produced no parts for is one whose walk gave us nothing —
/// possibly a malformed message, possibly a bug — and "we inspected nothing"
/// is not the same claim as "there is nothing here".
pub fn reconcile(parts: &[PartOutcome]) -> Verdict {
    parts
        .iter()
        .map(|p| p.verdict())
        .max()
        .unwrap_or(Verdict::Indeterminate)
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------
//
// Named consts rather than inline strings, matching `db::INSERT_SCAN_SQL`:
// there is no Postgres in the test environment, so asserting on the statement
// text is the only regression guard available for the properties these
// statements exist to provide.

/// Resolve a message to its UUID, creating it if this is the first delivery.
///
/// `DO UPDATE` rather than `DO NOTHING` is load-bearing: `ON CONFLICT DO
/// NOTHING ... RETURNING` returns *no row* on conflict, so a retry would come
/// back empty and the caller would have to fall back to a select. `DO UPDATE`
/// always returns the row, which is what makes redelivery a single round trip
/// and, more importantly, impossible to get subtly wrong.
///
/// The `WHERE ingest_key IS NOT NULL` predicate selects the partial unique
/// index. A row with a NULL ingest key matches no index entry, so it simply
/// inserts — no retry protection, which is the honest outcome for a caller
/// that cannot tell us its MTA identifier.
pub const UPSERT_MESSAGE_SQL: &str = "INSERT INTO messages \
     (tenant_id, ingest_key, direction, rfc_message_id, sender, recipients, \
      subject_hash, received_at, part_count) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()), $9) \
     ON CONFLICT (tenant_id, ingest_key) WHERE ingest_key IS NOT NULL \
     DO UPDATE SET part_count = EXCLUDED.part_count \
     RETURNING id";

/// Record or update one part.
///
/// Idempotent on `(message_uuid, mime_path)` — the guard §2 names. A retry
/// re-derives the same dotted paths and updates in place rather than
/// inserting a second row for the same part.
///
/// Deliberately keyed on the MIME path and never on `content_hash`: content
/// dedup across messages is a bypass (§6), since a repeated corporate
/// disclaimer or signature image would collapse unrelated messages into one
/// another and let an attacker suppress a scan by sending the same attachment
/// twice.
pub const UPSERT_PART_SQL: &str = "INSERT INTO message_parts \
     (message_uuid, parent_path, mime_path, content_type, filename, \
      content_hash, content_length, scan_id, status, detail, \
      finding_count, max_confidence) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     ON CONFLICT (message_uuid, mime_path) DO UPDATE SET \
       content_type = EXCLUDED.content_type, \
       filename = EXCLUDED.filename, \
       content_hash = EXCLUDED.content_hash, \
       content_length = EXCLUDED.content_length, \
       scan_id = EXCLUDED.scan_id, \
       status = EXCLUDED.status, \
       detail = EXCLUDED.detail, \
       finding_count = EXCLUDED.finding_count, \
       max_confidence = EXCLUDED.max_confidence, \
       updated_at = now() \
     RETURNING id";

/// Read back every part's status and verdict inputs, for reconciliation.
pub const SELECT_PART_OUTCOMES_SQL: &str =
    "SELECT status, finding_count, max_confidence FROM message_parts \
     WHERE message_uuid = $1 ORDER BY mime_path";

/// Write the reconciled verdict, recomputing `parts_completed` from the parts
/// table in the same statement.
///
/// Recomputed rather than incremented: a retry re-scanning a part would
/// otherwise bump the counter twice and the message would report itself
/// complete while a part was still pending. A count cannot drift.
pub const RECONCILE_MESSAGE_SQL: &str = "UPDATE messages m SET \
       parts_completed = sub.completed, \
       verdict = $2, \
       verdict_at = now() \
     FROM (SELECT count(*) FILTER (WHERE status = 'scanned') AS completed \
           FROM message_parts WHERE message_uuid = $1) sub \
     WHERE m.id = $1";

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Everything needed to open (or reopen) a message row.
#[derive(Debug, Clone)]
pub struct MessageRecord<'a> {
    pub tenant_id: &'a str,
    /// MTA-supplied, stable across delivery attempts. `None` means no retry
    /// protection — see the module docs.
    pub ingest_key: Option<&'a str>,
    pub direction: Direction,
    pub rfc_message_id: Option<&'a str>,
    pub sender: Option<&'a str>,
    pub recipients: &'a [String],
    pub subject_hash: Option<&'a [u8]>,
    pub part_count: i32,
}

/// Resolve a message to its UUID, inserting on first delivery and returning
/// the existing row on a retry.
///
/// `None` when no database is configured. Persistence is optional throughout
/// this service, and the mail path must still scan and decide without it —
/// what it loses is the retry guard and the investigation record, not the
/// verdict.
pub async fn resolve_message(
    pool: &Option<deadpool_postgres::Pool>,
    record: &MessageRecord<'_>,
) -> Result<Option<Uuid>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else { return Ok(None) };
    let client = pool.get().await?;
    let received_at: Option<chrono::DateTime<chrono::Utc>> = None;
    let row = client
        .query_one(
            UPSERT_MESSAGE_SQL,
            &[
                &record.tenant_id,
                &record.ingest_key,
                &record.direction.as_str(),
                &record.rfc_message_id,
                &record.sender,
                &record.recipients,
                &record.subject_hash,
                &received_at,
                &record.part_count,
            ],
        )
        .await?;
    Ok(Some(row.get(0)))
}

/// One part, as written to the database.
#[derive(Debug, Clone)]
pub struct PartRecord<'a> {
    pub parent_path: Option<&'a str>,
    pub mime_path: &'a str,
    pub content_type: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub content_hash: Option<&'a [u8]>,
    pub content_length: Option<i32>,
    pub scan_id: Option<Uuid>,
    pub status: PartStatus,
    /// Why a part was not scanned. Shown to an analyst, never matched on.
    pub detail: Option<&'a str>,
    pub finding_count: i32,
    pub max_confidence: Option<f32>,
}

/// Record or update one part of a message.
pub async fn upsert_part(
    pool: &Option<deadpool_postgres::Pool>,
    message_uuid: Uuid,
    part: &PartRecord<'_>,
) -> Result<Option<Uuid>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else { return Ok(None) };
    let client = pool.get().await?;
    let row = client
        .query_one(
            UPSERT_PART_SQL,
            &[
                &message_uuid,
                &part.parent_path,
                &part.mime_path,
                &part.content_type,
                &part.filename,
                &part.content_hash,
                &part.content_length,
                &part.scan_id,
                &part.status.as_str(),
                &part.detail,
                &part.finding_count,
                &part.max_confidence,
            ],
        )
        .await?;
    Ok(Some(row.get(0)))
}

/// Store a verdict computed in memory, recomputing `parts_completed` from the
/// parts table in the same statement.
///
/// This is the common path. §4.1 says all parts of a message are scanned on
/// one pod by default, so the outcomes are already in hand and [`reconcile`]
/// — a pure function — produces the verdict. Reading the parts back out of
/// Postgres to decide something we already know would add a round trip and a
/// second source of truth.
pub async fn store_verdict(
    pool: &Option<deadpool_postgres::Pool>,
    message_uuid: Uuid,
    verdict: Verdict,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else { return Ok(()) };
    let client = pool.get().await?;
    client
        .execute(RECONCILE_MESSAGE_SQL, &[&message_uuid, &verdict.as_str()])
        .await?;
    Ok(())
}

/// Read every part back from Postgres, reconcile, and store the verdict.
///
/// For the distributed case of §4.2, where parts were scanned on more than
/// one pod and no single process saw them all. Prefer [`reconcile`] plus
/// [`store_verdict`] when one pod handled the whole message.
///
/// Takes `verdict_for` so policy stays with the caller: this decides *how* to
/// combine part verdicts, not what a scanned part's findings are worth.
pub async fn reconcile_from_db<F>(
    pool: &Option<deadpool_postgres::Pool>,
    message_uuid: Uuid,
    verdict_for: F,
) -> Result<Option<Verdict>, Box<dyn std::error::Error + Send + Sync>>
where
    F: Fn(i32, Option<f32>) -> Verdict,
{
    let Some(pool) = pool else { return Ok(None) };
    let client = pool.get().await?;
    let rows = client
        .query(SELECT_PART_OUTCOMES_SQL, &[&message_uuid])
        .await?;

    let outcomes: Vec<PartOutcome> = rows
        .iter()
        .map(|r| {
            let status_text: &str = r.get(0);
            // An unrecognised status is treated as uninspected rather than
            // ignored. The CHECK constraint should make it impossible; if it
            // happens anyway, failing towards "we did not look at this" is
            // the direction that cannot turn an unscanned part into a clean
            // delivery.
            let status = PartStatus::from_str(status_text).unwrap_or(PartStatus::Error);
            if status.is_inspected() {
                let finding_count: i32 = r.get(1);
                let max_confidence: Option<f32> = r.get(2);
                PartOutcome::scanned(verdict_for(finding_count, max_confidence))
            } else {
                PartOutcome::uninspected(status)
            }
        })
        .collect();

    let verdict = reconcile(&outcomes);
    client
        .execute(RECONCILE_MESSAGE_SQL, &[&message_uuid, &verdict.as_str()])
        .await?;
    Ok(Some(verdict))
}

/// Delete messages older than the retention window.
///
/// Parts go with them by `ON DELETE CASCADE` — deleting parts separately
/// would be slower and would leave a window where a message outlived its own
/// parts and so looked uninspected.
///
/// Signature mirrors `db::prune_old_findings`, including the `&Option<Pool>`
/// no-op, so the retention task treats both the same way.
pub async fn prune_old_messages(
    pool: &Option<deadpool_postgres::Pool>,
    retention_days: u32,
) -> Result<(i64, i64), Box<dyn std::error::Error + Send + Sync>> {
    let Some(pool) = pool else { return Ok((0, 0)) };
    if retention_days == 0 {
        return Ok((0, 0));
    }
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT * FROM prune_messages($1)",
            &[&(retention_days as i32)],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the verdict ladder ------------------------------------------------

    #[test]
    fn severity_order_is_the_declaration_order() {
        assert!(Verdict::Clean < Verdict::Indeterminate);
        assert!(Verdict::Indeterminate < Verdict::Flagged);
        assert!(Verdict::Flagged < Verdict::Quarantine);
        assert!(Verdict::Quarantine < Verdict::Block);
    }

    /// The property §4.3 exists for: an uninspected part must not reconcile
    /// to clean. This is the bypass the whole model is built to prevent.
    #[test]
    fn one_uninspected_part_among_clean_ones_is_not_clean() {
        let mut parts = vec![PartOutcome::scanned(Verdict::Clean); 19];
        parts.push(PartOutcome::uninspected(PartStatus::SkippedOversize));
        assert_eq!(reconcile(&parts), Verdict::Indeterminate);
    }

    #[test]
    fn every_uninspected_status_reconciles_to_indeterminate() {
        for status in [
            PartStatus::Pending,
            PartStatus::SkippedOversize,
            PartStatus::SkippedEncrypted,
            PartStatus::SkippedNestedArchive,
            PartStatus::SkippedUnsupported,
            PartStatus::Error,
        ] {
            assert!(
                !status.is_inspected(),
                "{status:?} must not count as inspected"
            );
            assert_eq!(
                reconcile(&[
                    PartOutcome::scanned(Verdict::Clean),
                    PartOutcome::uninspected(status),
                ]),
                Verdict::Indeterminate,
                "{status:?} should have made the message indeterminate",
            );
        }
    }

    /// A confirmed finding outranks an unlooked-at part. The incompleteness
    /// is not lost — it lives in parts_completed and the part rows — but the
    /// verdict reports the most severe thing that is true.
    #[test]
    fn a_real_finding_outranks_an_uninspected_part() {
        let parts = vec![
            PartOutcome::scanned(Verdict::Flagged),
            PartOutcome::uninspected(PartStatus::Error),
        ];
        assert_eq!(reconcile(&parts), Verdict::Flagged);
    }

    #[test]
    fn verdict_is_the_maximum_severity_across_parts() {
        let parts = vec![
            PartOutcome::scanned(Verdict::Clean),
            PartOutcome::scanned(Verdict::Flagged),
            PartOutcome::scanned(Verdict::Block),
            PartOutcome::scanned(Verdict::Quarantine),
        ];
        assert_eq!(reconcile(&parts), Verdict::Block);
    }

    #[test]
    fn all_clean_is_clean() {
        let parts = vec![PartOutcome::scanned(Verdict::Clean); 5];
        assert_eq!(reconcile(&parts), Verdict::Clean);
    }

    /// A message we produced no parts for was not inspected, whatever the
    /// reason. "We looked at nothing" is not "there is nothing here".
    #[test]
    fn a_message_with_no_parts_is_indeterminate_not_clean() {
        assert_eq!(reconcile(&[]), Verdict::Indeterminate);
    }

    /// A scanned part whose policy verdict is missing falls back to clean,
    /// not to indeterminate: we did inspect it, so the honest statement is
    /// "inspected, nothing to report" rather than "not inspected".
    #[test]
    fn a_scanned_part_without_a_policy_verdict_is_clean() {
        let part = PartOutcome {
            status: PartStatus::Scanned,
            scanned_verdict: None,
        };
        assert_eq!(reconcile(&[part]), Verdict::Clean);
    }

    // --- string round-trips must match the CHECK constraints ---------------

    #[test]
    fn part_status_round_trips_through_its_sql_text() {
        for status in [
            PartStatus::Pending,
            PartStatus::Scanned,
            PartStatus::SkippedOversize,
            PartStatus::SkippedEncrypted,
            PartStatus::SkippedNestedArchive,
            PartStatus::SkippedUnsupported,
            PartStatus::Error,
        ] {
            assert_eq!(PartStatus::from_str(status.as_str()), Some(status));
        }
    }

    #[test]
    fn verdict_round_trips_through_its_sql_text() {
        for verdict in [
            Verdict::Clean,
            Verdict::Indeterminate,
            Verdict::Flagged,
            Verdict::Quarantine,
            Verdict::Block,
        ] {
            assert_eq!(Verdict::from_str(verdict.as_str()), Some(verdict));
        }
    }

    /// The Rust enums and the SQL CHECK constraints are two lists of the same
    /// strings, in different files. This is the only thing keeping them in
    /// step, since there is no Postgres in the test environment to reject a
    /// mismatch.
    #[test]
    fn enum_strings_appear_in_the_migration_check_constraints() {
        let migration = include_str!("../migrations/0010_messages.sql");
        for status in [
            PartStatus::Pending,
            PartStatus::Scanned,
            PartStatus::SkippedOversize,
            PartStatus::SkippedEncrypted,
            PartStatus::SkippedNestedArchive,
            PartStatus::SkippedUnsupported,
            PartStatus::Error,
        ] {
            assert!(
                migration.contains(&format!("'{}'", status.as_str())),
                "status {:?} is missing from message_parts_status_ck",
                status,
            );
        }
        for verdict in [
            Verdict::Clean,
            Verdict::Indeterminate,
            Verdict::Flagged,
            Verdict::Quarantine,
            Verdict::Block,
        ] {
            assert!(
                migration.contains(&format!("'{}'", verdict.as_str())),
                "verdict {:?} is missing from messages_verdict_ck",
                verdict,
            );
        }
        for direction in [Direction::Inbound, Direction::Outbound] {
            assert!(
                migration.contains(&format!("'{}'", direction.as_str())),
                "direction {:?} is missing from messages_direction_ck",
                direction,
            );
        }
    }

    // --- SQL properties ----------------------------------------------------

    /// `DO NOTHING ... RETURNING` returns no row on conflict, which would
    /// make a retry come back empty and silently mint a second message.
    #[test]
    fn message_upsert_returns_the_existing_row_on_retry() {
        assert!(UPSERT_MESSAGE_SQL.contains("DO UPDATE"));
        assert!(UPSERT_MESSAGE_SQL.contains("RETURNING id"));
        assert!(
            !UPSERT_MESSAGE_SQL.contains("DO NOTHING"),
            "DO NOTHING returns no row on conflict, so a retry would not resolve",
        );
    }

    /// The partial unique index needs its predicate named, or Postgres cannot
    /// pick the index and the statement fails at runtime.
    #[test]
    fn message_upsert_names_the_partial_index_predicate() {
        assert!(UPSERT_MESSAGE_SQL.contains("ON CONFLICT (tenant_id, ingest_key)"));
        assert!(UPSERT_MESSAGE_SQL.contains("WHERE ingest_key IS NOT NULL"));
    }

    /// Parts are idempotent on the MIME path and never on content: content
    /// dedup across messages is the §6 bypass.
    #[test]
    fn part_upsert_is_keyed_on_mime_path_not_content() {
        assert!(UPSERT_PART_SQL.contains("ON CONFLICT (message_uuid, mime_path)"));
        assert!(
            !UPSERT_PART_SQL.contains("ON CONFLICT (content_hash"),
            "content-keyed dedup across messages is a scanner bypass",
        );
    }

    /// parts_completed is recomputed, never incremented — an increment
    /// double-counts a re-scanned part and reports a message complete while
    /// one is still pending.
    #[test]
    fn reconcile_recomputes_parts_completed_rather_than_incrementing() {
        assert!(RECONCILE_MESSAGE_SQL.contains("count(*)"));
        assert!(RECONCILE_MESSAGE_SQL.contains("FILTER (WHERE status = 'scanned')"));
        assert!(
            !RECONCILE_MESSAGE_SQL.contains("parts_completed + 1"),
            "incrementing double-counts on retry",
        );
    }
}
