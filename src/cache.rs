//! LRU Scan Result Cache with TTL eviction.
//!
//! Thread-safe cache keyed by SHA-256 hash of input text.
//! Supports configurable max size and time-to-live.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::guard::ScanResult;

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

struct CacheEntry {
    result: ScanResult,
    inserted_at: Instant,
}

// ---------------------------------------------------------------------------
// ScanCache
// ---------------------------------------------------------------------------

/// Thread-safe LRU cache for scan results with TTL eviction.
pub struct ScanCache {
    max_size: usize,
    ttl: Duration,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<String, CacheEntry>,
    order: VecDeque<String>, // front = oldest
    hits: u64,
    misses: u64,
}

/// Cache statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub size: usize,
}

impl ScanCache {
    /// Create a new cache with given capacity and TTL in seconds.
    pub fn new(max_size: usize, ttl_seconds: f64) -> Self {
        Self {
            max_size,
            ttl: Duration::from_secs_f64(ttl_seconds),
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                hits: 0,
                misses: 0,
            }),
        }
    }

    /// Compute SHA-256 key for text.
    fn key(text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get a cached result, if present and not expired.
    pub fn get(&self, text: &str) -> Option<ScanResult> {
        let k = Self::key(text);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Check if entry exists and is valid
        let entry_state = inner.map.get(&k).map(|entry| {
            if entry.inserted_at.elapsed() < self.ttl {
                Some(entry.result.clone())
            } else {
                None
            }
        });

        match entry_state {
            Some(Some(result)) => {
                inner.hits += 1;
                inner.order.retain(|x| x != &k);
                inner.order.push_back(k);
                return Some(result);
            }
            Some(None) => {
                // Expired
                inner.map.remove(&k);
                inner.order.retain(|x| x != &k);
            }
            None => {}
        }

        inner.misses += 1;
        None
    }

    /// Store a scan result in the cache.
    pub fn put(&self, text: &str, result: ScanResult) {
        let k = Self::key(text);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // If key already exists, update it
        if inner.map.contains_key(&k) {
            inner.order.retain(|x| x != &k);
        }

        // Evict LRU if at capacity
        while inner.map.len() >= self.max_size && !inner.order.is_empty() {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }

        // Don't retain sensitive text in cache — clear the original input
        let mut result = result;
        result.text = String::new();

        inner.map.insert(
            k.clone(),
            CacheEntry {
                result,
                inserted_at: Instant::now(),
            },
        );
        inner.order.push_back(k);
    }

    /// Remove a specific entry.
    pub fn invalidate(&self, text: &str) {
        let k = Self::key(text);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.map.remove(&k);
        inner.order.retain(|x| x != &k);
    }

    /// Clear all entries and reset stats.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.map.clear();
        inner.order.clear();
        inner.hits = 0;
        inner.misses = 0;
    }

    /// Return cache statistics.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        CacheStats {
            hits: inner.hits,
            misses: inner.misses,
            size: inner.map.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Global default cache
// ---------------------------------------------------------------------------

static DEFAULT_CACHE: Mutex<Option<ScanCache>> = Mutex::new(None);

/// Get the global default cache (if set).
pub fn get_default_cache() -> &'static Mutex<Option<ScanCache>> {
    &DEFAULT_CACHE
}

/// Set or clear the global default cache.
pub fn set_default_cache(cache: Option<ScanCache>) {
    let mut global = DEFAULT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *global = cache;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn make_result(text: &str) -> ScanResult {
        ScanResult {
            text: text.to_string(),
            is_clean: true,
            findings: vec![],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
        }
    }

    #[test]
    fn test_put_and_get() {
        let cache = ScanCache::new(10, 60.0);
        let result = make_result("hello");
        cache.put("hello", result.clone());
        let got = cache.get("hello");
        assert!(got.is_some());
        assert_eq!(got.unwrap().text, ""); // text is cleared to avoid caching sensitive data
    }

    #[test]
    fn test_miss() {
        let cache = ScanCache::new(10, 60.0);
        assert!(cache.get("nope").is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let cache = ScanCache::new(2, 60.0);
        cache.put("a", make_result("a"));
        cache.put("b", make_result("b"));
        cache.put("c", make_result("c")); // should evict "a"
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn test_invalidate() {
        let cache = ScanCache::new(10, 60.0);
        cache.put("x", make_result("x"));
        cache.invalidate("x");
        assert!(cache.get("x").is_none());
    }

    #[test]
    fn test_clear() {
        let cache = ScanCache::new(10, 60.0);
        cache.put("a", make_result("a"));
        cache.put("b", make_result("b"));
        cache.clear();
        assert_eq!(cache.stats().size, 0);
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn test_ttl_expiry() {
        let cache = ScanCache::new(10, 0.0); // 0 second TTL
        cache.put("x", make_result("x"));
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.get("x").is_none());
    }
}
