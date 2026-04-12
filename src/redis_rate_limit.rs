//! Redis-backed distributed rate limiter.
//!
//! Enables rate limits to be enforced across multiple dlpscan API
//! instances sharing a Redis cluster. Without this backend, each
//! instance tracks its own per-client counters in memory, so a client
//! round-robining across N replicas gets N × the configured limit.
//!
//! ## Algorithm
//!
//! Fixed-window counter implemented via `INCR` + `EXPIRE` on a key of
//! the form `dlpscan:rl:<bucket>:<client_id>`, where `<bucket>` is the
//! current window rounded down to `window_secs`. Each call:
//!
//! 1. Computes the current window bucket (`epoch_secs / window_secs`).
//! 2. `INCR` the key. If the returned value is 1, set `EXPIRE` on the
//!    key so it self-cleans after the window passes.
//! 3. If the returned value exceeds `max_requests`, the request is
//!    rejected.
//!
//! Fixed-window has a 2x burst edge case (a client can burn through
//! `max_requests` at the end of one window and immediately again at
//! the start of the next). This is acceptable for DLP API rate
//! limiting where short-duration bursts are not a DoS vector.
//!
//! ## Failure handling
//!
//! Any Redis error (connection failure, timeout, reply parsing) returns
//! `Err`. Callers should treat this as "Redis unavailable" and fall
//! back to the in-memory limiter rather than fail open or closed
//! arbitrarily. This matches the semantics used by the API layer.
//!
//! ## Feature gating
//!
//! Compiled only when the `redis-rate-limit` feature is enabled. Without
//! the feature, this module is empty and `AppState` uses only the
//! in-memory limiter.

#![cfg(feature = "redis-rate-limit")]

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use redis::{Client, Commands, Connection};

/// Distributed rate limiter backed by a Redis server.
pub struct RedisRateLimiter {
    /// Synchronous Redis connection. Wrapped in a Mutex because the
    /// connection is not `Sync` and the limiter is called from an
    /// async handler via `tokio::task::block_in_place`.
    conn: Mutex<Connection>,
    /// Maximum requests allowed per window.
    max_requests: u64,
    /// Window size in seconds.
    window_secs: u64,
    /// Key prefix (default: "dlpscan:rl:").
    prefix: String,
}

impl RedisRateLimiter {
    /// Connect to a Redis server and build a new rate limiter.
    ///
    /// `url` is any URL accepted by `redis::Client::open`, e.g.
    /// `redis://127.0.0.1:6379` or `redis://user:pass@host:6379/0`.
    pub fn new(url: &str, max_requests: usize, window_secs: u64) -> Result<Self, String> {
        let client = Client::open(url).map_err(|e| format!("redis open: {e}"))?;
        let conn = client
            .get_connection()
            .map_err(|e| format!("redis connect: {e}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_requests: max_requests as u64,
            window_secs,
            prefix: "dlpscan:rl:".to_string(),
        })
    }

    /// Check whether a request from `client_id` is allowed in the
    /// current window. Returns `Ok(true)` if allowed, `Ok(false)` if
    /// the client has exceeded `max_requests`, or `Err` if Redis
    /// communication failed.
    pub fn check_client(&self, client_id: &str) -> Result<bool, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let bucket = now / self.window_secs;
        let key = format!("{}{}:{}", self.prefix, bucket, sanitize_client_id(client_id));

        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "redis mutex poisoned".to_string())?;

        // INCR is atomic and returns the new counter value.
        let count: i64 = conn.incr(&key, 1).map_err(|e| format!("redis INCR: {e}"))?;

        // Set TTL on the first increment so the key self-expires.
        if count == 1 {
            // 1.5× window so slow clients whose clocks are slightly
            // skewed still see consistent counters.
            let ttl = (self.window_secs as i64) * 3 / 2;
            let _: () = conn
                .expire(&key, ttl)
                .map_err(|e| format!("redis EXPIRE: {e}"))?;
        }

        Ok((count as u64) <= self.max_requests)
    }

    /// Configured max requests per window.
    pub fn max_requests(&self) -> u64 {
        self.max_requests
    }

    /// Configured window size in seconds.
    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
}

/// Sanitize a client ID so it cannot inject Redis key separators or
/// wildcard characters. Keeps ASCII alphanumerics, `.`, `:`, `_`, `-`;
/// replaces everything else with `_`.
fn sanitize_client_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for c in id.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    // Cap length to avoid unbounded key growth if a client sends long headers.
    if out.len() > 128 {
        out.truncate(128);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_alphanumerics() {
        assert_eq!(sanitize_client_id("alice"), "alice");
        assert_eq!(sanitize_client_id("key:abcd1234"), "key:abcd1234");
        assert_eq!(sanitize_client_id("ip:192.168.1.1"), "ip:192.168.1.1");
    }

    #[test]
    fn test_sanitize_strips_wildcards() {
        assert_eq!(sanitize_client_id("key:*"), "key:_");
        assert_eq!(sanitize_client_id("a b\nc"), "a_b_c");
    }

    #[test]
    fn test_sanitize_caps_length() {
        let long = "a".repeat(500);
        assert_eq!(sanitize_client_id(&long).len(), 128);
    }
}
