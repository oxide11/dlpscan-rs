//! `/v1/keys` — issue, list, revoke and rotate per-caller API keys.
//!
//! Every handler is `AdminAction`. The secret appears in exactly one
//! response — the 201 from issue and the 200 from rotate — and nowhere
//! else: not in the list, not in the audit row, not in a log line. An
//! operator who loses it rotates.
//!
//! Without Postgres there is no store; the handlers return 503 with a body
//! that says why, which the console renders as "key store unavailable"
//! rather than as an empty list. Absence is a state.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use siphon::rbac::Role;
use siphon_auth::keys::{IssueRequest, KeyError, KeyRecord, KeyStore};
use siphon_core::audit::AuditEvent;

use crate::{
    emit_audit, sanitize_tenant_id, AppState, AuthContextExt, ErrorResponse, RequireAdminAction,
};

type Reply<T> = Result<(StatusCode, Json<T>), (StatusCode, Json<ErrorResponse>)>;

/// Default lifetime when the caller does not say. A year is long enough that
/// rotation is a calendar event rather than a chore, short enough that a
/// forgotten integration stops working before it is forgotten twice.
const DEFAULT_EXPIRY_DAYS: i64 = 365;
const MAX_LABEL_LEN: usize = 64;
const DEFAULT_ROTATE_GRACE_SECS: i64 = 86_400;
const MAX_ROTATE_GRACE_SECS: i64 = 7 * 86_400;

#[derive(Deserialize)]
pub struct IssueBody {
    pub label: String,
    pub role: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Days from now. Omitted → 365. `0` is refused; say `never_expires`.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    #[serde(default)]
    pub never_expires: bool,
}

#[derive(Serialize)]
pub struct KeyView {
    pub id: String,
    pub label: String,
    pub role: String,
    pub tenant_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Set while a rotated-out secret is still accepted.
    pub previous_valid_until: Option<DateTime<Utc>>,
    /// Derived: live, expired or revoked. Saves every client re-deriving it
    /// from three timestamps, and makes the list filterable by eye.
    pub status: &'static str,
}

impl From<KeyRecord> for KeyView {
    fn from(r: KeyRecord) -> Self {
        let status = if r.is_revoked() {
            "revoked"
        } else if r.is_expired_at(Utc::now()) {
            "expired"
        } else {
            "live"
        };
        Self {
            id: r.id,
            label: r.label,
            role: r.role,
            tenant_id: r.tenant_id,
            created_at: r.created_at,
            created_by: r.created_by,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            revoked_by: r.revoked_by,
            last_used_at: r.last_used_at,
            previous_valid_until: r.previous_valid_until,
            status,
        }
    }
}

#[derive(Serialize)]
pub struct IssuedView {
    #[serde(flatten)]
    pub key: KeyView,
    /// Shown once. The server stores a hash and cannot show it again.
    pub secret: String,
}

#[derive(Serialize)]
pub struct KeyList {
    pub keys: Vec<KeyView>,
    pub total: usize,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub include_revoked: bool,
}

#[derive(Deserialize, Default)]
pub struct RotateBody {
    /// How long the old secret stays valid. Default a day, at most a week.
    pub grace_seconds: Option<i64>,
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: msg.into() }))
}

fn store(state: &AppState) -> Result<&Arc<KeyStore>, (StatusCode, Json<ErrorResponse>)> {
    state.keys.as_ref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "key store unavailable: SIPHON_DATABASE_URL is not set, so keys cannot be issued or \
             listed; the bootstrap SIPHON_API_KEY is the only credential",
        )
    })
}

fn map_err(e: KeyError) -> (StatusCode, Json<ErrorResponse>) {
    match e {
        KeyError::NoDatabase => err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        KeyError::NotFound => err(StatusCode::NOT_FOUND, e.to_string()),
        KeyError::Revoked => err(StatusCode::CONFLICT, e.to_string()),
        KeyError::Invalid(why) => err(StatusCode::BAD_REQUEST, why),
        KeyError::Db(_) => {
            tracing::error!(error = %e, "key store operation failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key store operation failed",
            )
        }
    }
}

/// Turn a request body into something the store will accept, or say
/// exactly why not. Pure, so it is tested without a server.
fn validate(body: IssueBody, created_by: &str, now: DateTime<Utc>) -> Result<IssueRequest, String> {
    let label = body.label.trim();
    if label.is_empty() {
        return Err("label is required".into());
    }
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(format!("label is longer than {MAX_LABEL_LEN} characters"));
    }
    if label.chars().any(char::is_control) {
        return Err("label must not contain control characters".into());
    }

    let role = Role::from_label(body.role.trim()).ok_or_else(|| {
        let known: Vec<&str> = Role::ALL.iter().map(|r| r.label()).collect();
        format!("unknown role {:?}; one of {}", body.role, known.join(", "))
    })?;

    let tenant_id = match body.tenant_id.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => Some(sanitize_tenant_id(raw).ok_or_else(|| {
            "tenant_id may contain only letters, digits, '-', '_' and '.', up to 64 characters"
                .to_string()
        })?),
    };
    if role == Role::Admin && tenant_id.is_some() {
        return Err(
            "an admin key cannot be bound to a tenant: admin is by definition unscoped".into(),
        );
    }

    let expires_at = match (body.never_expires, body.expires_in_days) {
        (true, Some(_)) => {
            return Err("never_expires and expires_in_days are mutually exclusive".into())
        }
        (true, None) => None,
        (false, Some(0)) => {
            return Err(
                "expires_in_days must be at least 1; use never_expires for no expiry".into(),
            )
        }
        (false, Some(days)) => Some(now + Duration::days(i64::from(days))),
        (false, None) => Some(now + Duration::days(DEFAULT_EXPIRY_DAYS)),
    };

    Ok(IssueRequest {
        label: label.to_string(),
        role: role.label().to_string(),
        tenant_id,
        expires_at,
        created_by: created_by.to_string(),
    })
}

fn audit(event: &str, actor: &str, rec: &KeyRecord, extra: &[(&str, serde_json::Value)]) {
    if let Ok(ev) = AuditEvent::new(event) {
        let mut ev = ev
            .with_user(actor)
            .with_action("api_key")
            .with_outcome("success")
            .with_metadata("key_id", serde_json::json!(rec.id))
            .with_metadata("label", serde_json::json!(rec.label))
            .with_metadata("role", serde_json::json!(rec.role))
            .with_metadata("tenant_id", serde_json::json!(rec.tenant_id));
        for (k, v) in extra {
            ev = ev.with_metadata(k, v.clone());
        }
        emit_audit(ev);
    }
}

pub async fn issue_key(
    _: RequireAdminAction,
    AuthContextExt(ctx): AuthContextExt,
    State(state): State<Arc<AppState>>,
    Json(body): Json<IssueBody>,
) -> Reply<IssuedView> {
    let store = store(&state)?;
    let req =
        validate(body, &ctx.actor, Utc::now()).map_err(|why| err(StatusCode::BAD_REQUEST, why))?;
    if req.role == Role::Admin.label() {
        // Allowed — an admin may need a machine with full rights — but never
        // quietly. The console warns too.
        tracing::warn!(actor = %ctx.actor, "issuing an ADMIN api key");
    }
    let issued = store.issue(req).await.map_err(map_err)?;
    audit(
        "KEY_ISSUE",
        &ctx.actor,
        &issued.record,
        &[("expires_at", serde_json::json!(issued.record.expires_at))],
    );
    tracing::info!(actor = %ctx.actor, key_id = %issued.record.id, role = %issued.record.role, "api key issued");
    Ok((
        StatusCode::CREATED,
        Json(IssuedView {
            key: issued.record.into(),
            secret: issued.secret,
        }),
    ))
}

pub async fn list_keys(
    _: RequireAdminAction,
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Reply<KeyList> {
    let store = store(&state)?;
    let keys: Vec<KeyView> = store
        .list(q.include_revoked)
        .into_iter()
        .map(KeyView::from)
        .collect();
    let total = keys.len();
    Ok((StatusCode::OK, Json(KeyList { keys, total })))
}

pub async fn get_key(
    _: RequireAdminAction,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Reply<KeyView> {
    let store = store(&state)?;
    let rec = store
        .get(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such key"))?;
    Ok((StatusCode::OK, Json(rec.into())))
}

pub async fn revoke_key(
    _: RequireAdminAction,
    AuthContextExt(ctx): AuthContextExt,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let store = store(&state)?;
    let was_live = store.revoke(&id, &ctx.actor).await.map_err(map_err)?;
    if was_live {
        if let Some(rec) = store.get(&id) {
            audit("KEY_REVOKE", &ctx.actor, &rec, &[]);
        }
        tracing::info!(actor = %ctx.actor, key_id = %id, "api key revoked");
    }
    // Idempotent: revoking a revoked key is not an error, and says nothing
    // about whether the id existed a moment ago.
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_key(
    _: RequireAdminAction,
    AuthContextExt(ctx): AuthContextExt,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<RotateBody>>,
) -> Reply<IssuedView> {
    let store = store(&state)?;
    let grace = body
        .and_then(|Json(b)| b.grace_seconds)
        .unwrap_or(DEFAULT_ROTATE_GRACE_SECS);
    if !(0..=MAX_ROTATE_GRACE_SECS).contains(&grace) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("grace_seconds must be between 0 and {MAX_ROTATE_GRACE_SECS}"),
        ));
    }
    let issued = store
        .rotate(&id, &ctx.actor, Duration::seconds(grace))
        .await
        .map_err(map_err)?;
    audit(
        "KEY_ROTATE",
        &ctx.actor,
        &issued.record,
        &[(
            "previous_valid_until",
            serde_json::json!(issued.record.previous_valid_until),
        )],
    );
    tracing::info!(actor = %ctx.actor, key_id = %id, grace_seconds = grace, "api key rotated");
    Ok((
        StatusCode::OK,
        Json(IssuedView {
            key: issued.record.into(),
            secret: issued.secret,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(label: &str, role: &str) -> IssueBody {
        IssueBody {
            label: label.into(),
            role: role.into(),
            tenant_id: None,
            expires_in_days: None,
            never_expires: false,
        }
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn defaults_to_a_year_and_a_wire_role_label() {
        let r = validate(body("payments prod", "operator"), "alice", now()).unwrap();
        assert_eq!(r.role, "operator");
        let days = (r.expires_at.unwrap() - now()).num_days();
        assert!((364..=365).contains(&days), "{days}");
        assert_eq!(r.created_by, "alice");
    }

    #[test]
    fn idp_spellings_are_not_roles() {
        // `admins` is an IdP group name; a key's role is the wire label only.
        let e = validate(body("x", "admins"), "a", now()).unwrap_err();
        assert!(e.contains("unknown role"), "{e}");
        assert!(
            e.contains("responder-readonly"),
            "the error lists what would work: {e}"
        );
    }

    #[test]
    fn an_admin_key_cannot_be_tenant_bound() {
        let mut b = body("x", "admin");
        b.tenant_id = Some("payments".into());
        let e = validate(b, "a", now()).unwrap_err();
        assert!(e.contains("unscoped"), "{e}");
    }

    #[test]
    fn tenant_is_sanitised_like_the_header() {
        let mut b = body("x", "operator");
        b.tenant_id = Some("pay ments".into());
        assert!(validate(b, "a", now()).is_err());
        let mut b = body("x", "operator");
        b.tenant_id = Some(" payments-app ".into());
        assert_eq!(
            validate(b, "a", now()).unwrap().tenant_id.as_deref(),
            Some("payments-app")
        );
    }

    #[test]
    fn expiry_is_explicit() {
        let mut b = body("x", "operator");
        b.expires_in_days = Some(0);
        assert!(validate(b, "a", now())
            .unwrap_err()
            .contains("never_expires"));

        let mut b = body("x", "operator");
        b.never_expires = true;
        assert_eq!(validate(b, "a", now()).unwrap().expires_at, None);

        let mut b = body("x", "operator");
        b.never_expires = true;
        b.expires_in_days = Some(30);
        assert!(
            validate(b, "a", now()).is_err(),
            "contradiction is refused, not resolved"
        );
    }

    #[test]
    fn labels_are_bounded_and_printable() {
        assert!(validate(body("   ", "operator"), "a", now()).is_err());
        assert!(validate(body(&"x".repeat(65), "operator"), "a", now()).is_err());
        assert!(validate(body("evil\nlabel", "operator"), "a", now()).is_err());
    }

    #[test]
    fn every_role_the_binary_knows_is_in_the_check_constraint() {
        // The enum and the CHECK live in different crates. This is the one
        // place both are visible.
        let sql = siphon_auth::keys::MIGRATION_SQL;
        for r in Role::ALL {
            let quoted = format!("'{}'", r.label());
            assert!(
                sql.contains(&quoted),
                "api_keys.role CHECK is missing {quoted}"
            );
        }
    }
}
