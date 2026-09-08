//! Per-caller API keys: the store, the cache and the token format.
//!
//! One implementation, because siphon-api and siphon-fs must resolve a
//! bearer token identically — see `docs/architecture/api-keys.md`.
//!
//! # The token
//!
//! `sk_<id>_<secret>`: a 12-character public id and a 64-hex-character
//! random secret. The whole token is hashed with SHA-256 and only the hash
//! is stored; the secret is a 256-bit random value, so a slow password hash
//! would defend nothing. The id is what appears in audit rows, scan
//! attribution and the console, and a leaked token can be matched to its
//! row from the prefix without knowing the secret.
//!
//! # The cache
//!
//! A request costs one SHA-256 and one map read. The map is loaded from
//! Postgres at startup and refreshed on an interval by the owning service;
//! every write through this store updates it immediately, so a revocation
//! takes effect on the next request from *this* pod and within one refresh
//! interval on every other.
//!
//! If Postgres is unreachable the cache keeps serving what it last loaded
//! and the refresh logs once. That is a deliberate trade: scans keep flowing
//! through a database outage — persistence is already fire-and-forget — and
//! a revocation is at most one interval plus the outage late. Failing closed
//! would turn every Postgres blip into a scanning outage across every
//! integration, which is the wrong failure for a control in front of mail
//! and web traffic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};

/// This crate's schema, exported so siphon-api's migration runner can
/// register it without a cross-crate `include_str!` path.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0013_api_keys.sql");

/// A key as the store knows it. Never carries the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: String,
    pub label: String,
    /// `siphon::rbac::Role::label()`. A string here because this crate does
    /// not link the RBAC model; the caller maps it and fails closed on a
    /// label it does not know.
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
}

impl KeyRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }
}

/// What a presented token resolved to.
#[derive(Debug)]
pub enum Resolution {
    Ok(Arc<KeyRecord>),
    /// No live key hashes to this. Also the answer for a rotated-out secret
    /// past its grace window — deliberately indistinguishable from a wrong
    /// token, since the old secret is no longer a credential.
    Unknown,
    Revoked(Arc<KeyRecord>),
    Expired(Arc<KeyRecord>),
}

#[derive(Debug)]
pub enum KeyError {
    /// The store has no database — keys cannot be issued or listed.
    NoDatabase,
    NotFound,
    Revoked,
    Invalid(String),
    Db(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDatabase => write!(f, "key store unavailable: no database configured"),
            Self::NotFound => write!(f, "no such key"),
            Self::Revoked => write!(f, "key is revoked"),
            Self::Invalid(why) => write!(f, "{why}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<tokio_postgres::Error> for KeyError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Db(e.to_string())
    }
}

impl From<deadpool_postgres::PoolError> for KeyError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        Self::Db(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub label: String,
    pub role: String,
    pub tenant_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: String,
}

/// A freshly issued or rotated key. `secret` exists in memory exactly here
/// and in the one response that carries it; the store cannot show it again.
pub struct Issued {
    pub record: KeyRecord,
    pub secret: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Current,
    Previous,
}

#[derive(Default)]
struct Cache {
    by_hash: HashMap<[u8; 32], (Arc<KeyRecord>, Which)>,
    /// Every row, revoked included — for `get` without a round trip.
    by_id: HashMap<String, Arc<KeyRecord>>,
}

pub struct KeyStore {
    pool: Option<Pool>,
    cache: RwLock<Cache>,
    /// `last_used_at` writes waiting for the next flush.
    pending_touch: Mutex<HashMap<String, DateTime<Utc>>>,
    refresh_warned: std::sync::atomic::AtomicBool,
}

const TOKEN_PREFIX: &str = "sk_";
const ID_LEN: usize = 12;
/// Lowercase base32 without vowels-that-look-like-digits: unambiguous when
/// read aloud, safe in a URL, and never a substring an English word makes.
const ID_ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstvwxyz0123456789";

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system randomness is unavailable");
    buf
}

fn new_id() -> String {
    // 256 % 32 == 0, so a byte modulo 32 is unbiased.
    random_bytes::<ID_LEN>()
        .iter()
        .map(|b| ID_ALPHABET[(*b % 32) as usize] as char)
        .collect()
}

fn new_token(id: &str) -> String {
    let secret: String = random_bytes::<32>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{TOKEN_PREFIX}{id}_{secret}")
}

/// The public id inside a presented token, if it has the shape of one.
/// For logs and incident response — resolution never trusts it, and hashes
/// the whole token instead.
pub fn id_of(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (id, _) = rest.split_once('_')?;
    (id.len() == ID_LEN && id.bytes().all(|b| ID_ALPHABET.contains(&b))).then_some(id)
}

impl KeyStore {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool: Some(pool),
            cache: RwLock::new(Cache::default()),
            pending_touch: Mutex::new(HashMap::new()),
            refresh_warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A store with no database, serving only what it is given. For tests
    /// and for a service that receives its key set some other way.
    pub fn in_memory(records: Vec<(String, KeyRecord)>) -> Self {
        let store = Self {
            pool: None,
            cache: RwLock::new(Cache::default()),
            pending_touch: Mutex::new(HashMap::new()),
            refresh_warned: std::sync::atomic::AtomicBool::new(false),
        };
        let mut cache = store.cache.write().unwrap_or_else(|e| e.into_inner());
        for (token, rec) in records {
            let rec = Arc::new(rec);
            cache.by_id.insert(rec.id.clone(), rec.clone());
            if !rec.is_revoked() {
                cache
                    .by_hash
                    .insert(hash_token(&token), (rec, Which::Current));
            }
        }
        drop(cache);
        store
    }

    pub fn has_database(&self) -> bool {
        self.pool.is_some()
    }

    fn pool(&self) -> Result<&Pool, KeyError> {
        self.pool.as_ref().ok_or(KeyError::NoDatabase)
    }

    /// Number of live keys in the cache.
    pub fn live_count(&self) -> usize {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        cache.by_id.values().filter(|r| !r.is_revoked()).count()
    }

    /// Resolve a presented bearer token. Constant work regardless of outcome:
    /// one hash, one lookup.
    pub fn resolve(&self, token: &str) -> Resolution {
        let hash = hash_token(token);
        let now = Utc::now();
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let Some((rec, which)) = cache.by_hash.get(&hash) else {
            return Resolution::Unknown;
        };
        if rec.is_revoked() {
            return Resolution::Revoked(rec.clone());
        }
        if rec.is_expired_at(now) {
            return Resolution::Expired(rec.clone());
        }
        if *which == Which::Previous && !rec.previous_valid_until.is_some_and(|t| t > now) {
            return Resolution::Unknown;
        }
        Resolution::Ok(rec.clone())
    }

    /// Note a use. Written to the database by [`flush_touches`], not here.
    pub fn touch(&self, id: &str) {
        let mut pending = self.pending_touch.lock().unwrap_or_else(|e| e.into_inner());
        pending.insert(id.to_string(), Utc::now());
    }

    /// Reload every row from Postgres. Returns the live count.
    pub async fn refresh(&self) -> Result<usize, KeyError> {
        let pool = self.pool()?;
        let client = pool.get().await?;
        let rows = client
            .query(
                "SELECT id, secret_hash, previous_secret_hash, previous_valid_until, label, role, \
                 tenant_id, created_at, created_by, expires_at, revoked_at, revoked_by, last_used_at \
                 FROM api_keys",
                &[],
            )
            .await?;

        let mut fresh = Cache::default();
        for row in rows {
            let rec = Arc::new(KeyRecord {
                id: row.get("id"),
                label: row.get("label"),
                role: row.get("role"),
                tenant_id: row.get("tenant_id"),
                created_at: row.get("created_at"),
                created_by: row.get("created_by"),
                expires_at: row.get("expires_at"),
                revoked_at: row.get("revoked_at"),
                revoked_by: row.get("revoked_by"),
                last_used_at: row.get("last_used_at"),
                previous_valid_until: row.get("previous_valid_until"),
            });
            fresh.by_id.insert(rec.id.clone(), rec.clone());
            if rec.is_revoked() {
                continue;
            }
            let current: Vec<u8> = row.get("secret_hash");
            if let Ok(h) = <[u8; 32]>::try_from(current.as_slice()) {
                fresh.by_hash.insert(h, (rec.clone(), Which::Current));
            }
            let previous: Option<Vec<u8>> = row.get("previous_secret_hash");
            if let Some(p) = previous {
                if let Ok(h) = <[u8; 32]>::try_from(p.as_slice()) {
                    fresh.by_hash.insert(h, (rec.clone(), Which::Previous));
                }
            }
        }
        let live = fresh.by_id.values().filter(|r| !r.is_revoked()).count();
        *self.cache.write().unwrap_or_else(|e| e.into_inner()) = fresh;
        self.refresh_warned
            .store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(live)
    }

    /// `refresh`, logging a failure once per outage rather than every
    /// interval. The cache keeps serving either way.
    pub async fn refresh_logged(&self) {
        match self.refresh().await {
            Ok(_) => {}
            Err(e) => {
                if !self
                    .refresh_warned
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::warn!(
                        error = %e,
                        "API key refresh failed — serving the last loaded set; a key issued or \
                         revoked elsewhere is not seen until the database returns"
                    );
                }
            }
        }
    }

    /// Persist pending `last_used_at` updates.
    pub async fn flush_touches(&self) -> Result<usize, KeyError> {
        let pending: Vec<(String, DateTime<Utc>)> = {
            let mut p = self.pending_touch.lock().unwrap_or_else(|e| e.into_inner());
            p.drain().collect()
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let pool = self.pool()?;
        let client = pool.get().await?;
        for (id, at) in &pending {
            client
                .execute(
                    "UPDATE api_keys SET last_used_at = GREATEST(COALESCE(last_used_at, $2), $2) \
                     WHERE id = $1",
                    &[id, at],
                )
                .await?;
        }
        Ok(pending.len())
    }

    pub async fn issue(&self, req: IssueRequest) -> Result<Issued, KeyError> {
        let pool = self.pool()?;
        let id = new_id();
        let token = new_token(&id);
        let hash = hash_token(&token).to_vec();
        let client = pool.get().await?;
        let row = client
            .query_one(
                "INSERT INTO api_keys (id, secret_hash, label, role, tenant_id, created_by, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 RETURNING created_at",
                &[
                    &id,
                    &hash,
                    &req.label,
                    &req.role,
                    &req.tenant_id,
                    &req.created_by,
                    &req.expires_at,
                ],
            )
            .await?;
        let record = KeyRecord {
            id,
            label: req.label,
            role: req.role,
            tenant_id: req.tenant_id,
            created_at: row.get("created_at"),
            created_by: req.created_by,
            expires_at: req.expires_at,
            revoked_at: None,
            revoked_by: None,
            last_used_at: None,
            previous_valid_until: None,
        };
        let rec = Arc::new(record.clone());
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        cache.by_id.insert(rec.id.clone(), rec.clone());
        cache
            .by_hash
            .insert(hash_token(&token), (rec, Which::Current));
        drop(cache);
        Ok(Issued {
            record,
            secret: token,
        })
    }

    /// Soft-revoke. `Ok(true)` if the key was live, `Ok(false)` if it was
    /// already revoked (idempotent), `NotFound` if there is no such id.
    pub async fn revoke(&self, id: &str, by: &str) -> Result<bool, KeyError> {
        let pool = self.pool()?;
        let client = pool.get().await?;
        let updated = client
            .execute(
                "UPDATE api_keys SET revoked_at = now(), revoked_by = $2 \
                 WHERE id = $1 AND revoked_at IS NULL",
                &[&id, &by],
            )
            .await?;
        if updated == 0 {
            let exists: i64 = client
                .query_one("SELECT count(*) FROM api_keys WHERE id = $1", &[&id])
                .await?
                .get(0);
            return if exists == 0 {
                Err(KeyError::NotFound)
            } else {
                Ok(false)
            };
        }
        // Take effect on this pod now, not at the next refresh.
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        cache.by_hash.retain(|_, (rec, _)| rec.id != id);
        if let Some(rec) = cache.by_id.get_mut(id) {
            let mut updated = (**rec).clone();
            updated.revoked_at = Some(Utc::now());
            updated.revoked_by = Some(by.to_string());
            *rec = Arc::new(updated);
        }
        Ok(true)
    }

    /// New secret, same id. The old secret stays valid for `grace`.
    pub async fn rotate(&self, id: &str, by: &str, grace: Duration) -> Result<Issued, KeyError> {
        let pool = self.pool()?;
        let token = new_token(id);
        let hash = hash_token(&token).to_vec();
        let until = Utc::now() + grace;
        let client = pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE api_keys SET previous_secret_hash = secret_hash, previous_valid_until = $3, \
                 secret_hash = $2 \
                 WHERE id = $1 AND revoked_at IS NULL \
                 RETURNING label, role, tenant_id, created_at, created_by, expires_at, last_used_at",
                &[&id, &hash, &until],
            )
            .await?;
        let Some(row) = row else {
            let exists: i64 = client
                .query_one("SELECT count(*) FROM api_keys WHERE id = $1", &[&id])
                .await?
                .get(0);
            return Err(if exists == 0 {
                KeyError::NotFound
            } else {
                KeyError::Revoked
            });
        };
        let _ = by; // recorded by the caller's audit event; the row keeps its issuer
        let record = KeyRecord {
            id: id.to_string(),
            label: row.get("label"),
            role: row.get("role"),
            tenant_id: row.get("tenant_id"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            expires_at: row.get("expires_at"),
            revoked_at: None,
            revoked_by: None,
            last_used_at: row.get("last_used_at"),
            previous_valid_until: Some(until),
        };
        let rec = Arc::new(record.clone());
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        // The old current becomes previous; anything older than that is gone.
        for (r, which) in cache.by_hash.values_mut() {
            if r.id == id {
                *which = Which::Previous;
                *r = rec.clone();
            }
        }
        cache.by_hash.retain(|_, (r, which)| {
            !(r.id == id && *which == Which::Previous && r.previous_valid_until.is_none())
        });
        cache
            .by_hash
            .insert(hash_token(&token), (rec.clone(), Which::Current));
        cache.by_id.insert(id.to_string(), rec);
        drop(cache);
        Ok(Issued {
            record,
            secret: token,
        })
    }

    /// Every key, from the cache. Revoked ones included when asked.
    pub fn list(&self, include_revoked: bool) -> Vec<KeyRecord> {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<KeyRecord> = cache
            .by_id
            .values()
            .filter(|r| include_revoked || !r.is_revoked())
            .map(|r| (**r).clone())
            .collect();
        out.sort_by_key(|k| std::cmp::Reverse(k.created_at));
        out
    }

    pub fn get(&self, id: &str) -> Option<KeyRecord> {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        cache.by_id.get(id).map(|r| (**r).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str) -> KeyRecord {
        KeyRecord {
            id: id.to_string(),
            label: "test".into(),
            role: "operator".into(),
            tenant_id: None,
            created_at: Utc::now(),
            created_by: "tester".into(),
            expires_at: None,
            revoked_at: None,
            revoked_by: None,
            last_used_at: None,
            previous_valid_until: None,
        }
    }

    #[test]
    fn token_shape_and_id_extraction() {
        let id = new_id();
        assert_eq!(id.len(), ID_LEN);
        let token = new_token(&id);
        assert!(token.starts_with("sk_"));
        assert_eq!(id_of(&token), Some(id.as_str()));
        assert_eq!(token.len(), 3 + ID_LEN + 1 + 64);
        // Anything else is not a key-shaped token.
        assert_eq!(id_of("bootstrap-secret"), None);
        assert_eq!(id_of("sk_short_abc"), None);
    }

    #[test]
    fn two_tokens_never_collide() {
        let a = new_token(&new_id());
        let b = new_token(&new_id());
        assert_ne!(a, b);
        assert_ne!(hash_token(&a), hash_token(&b));
    }

    #[test]
    fn resolves_a_live_key_and_nothing_else() {
        let store = KeyStore::in_memory(vec![("sk_live".into(), rec("live"))]);
        assert!(matches!(store.resolve("sk_live"), Resolution::Ok(r) if r.id == "live"));
        assert!(matches!(store.resolve("sk_liv"), Resolution::Unknown));
        assert!(matches!(store.resolve(""), Resolution::Unknown));
    }

    #[test]
    fn an_expired_key_is_expired_not_unknown() {
        // The distinction is for the audit row: "someone used a key that
        // ran out" is a different fact from "someone guessed".
        let mut r = rec("old");
        r.expires_at = Some(Utc::now() - Duration::seconds(1));
        let store = KeyStore::in_memory(vec![("sk_old".into(), r)]);
        assert!(matches!(store.resolve("sk_old"), Resolution::Expired(_)));
    }

    #[test]
    fn a_revoked_key_does_not_resolve() {
        let mut r = rec("gone");
        r.revoked_at = Some(Utc::now());
        let store = KeyStore::in_memory(vec![("sk_gone".into(), r)]);
        // Not even as Revoked: in_memory never indexes a revoked hash, and
        // refresh() skips them the same way, so a revoked secret is a
        // stranger's secret as far as the auth path can tell.
        assert!(matches!(store.resolve("sk_gone"), Resolution::Unknown));
        assert!(store.get("gone").is_some(), "the row is still history");
        assert_eq!(store.list(false).len(), 0);
        assert_eq!(store.list(true).len(), 1);
    }

    #[test]
    fn a_store_without_a_database_cannot_issue() {
        let store = KeyStore::in_memory(vec![]);
        assert!(!store.has_database());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt
            .block_on(store.issue(IssueRequest {
                label: "x".into(),
                role: "operator".into(),
                tenant_id: None,
                expires_at: None,
                created_by: "t".into(),
            }))
            .err()
            .unwrap();
        assert!(matches!(err, KeyError::NoDatabase));
    }

    #[test]
    fn touch_is_write_behind() {
        let store = KeyStore::in_memory(vec![("sk_live".into(), rec("live"))]);
        store.touch("live");
        store.touch("live");
        let pending = store.pending_touch.lock().unwrap();
        assert_eq!(pending.len(), 1, "one pending write per key, not per use");
    }
}
