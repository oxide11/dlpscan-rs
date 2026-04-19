//! Shared finding record + in-memory ring buffer.
//!
//! Both siphon-api (text `/scan`) and siphon-fs (file `/scan`) keep
//! their own independent ring of recently emitted findings and serve
//! `/v1/findings` from it. That keeps each pod functional in
//! isolation — if you only run siphon-fs, you can still browse its
//! findings through the admin console. The console fans out to both
//! pods and unions the results client-side (Phase 2c.3).
//!
//! Rings are bounded and in-memory. A durable store (Redis / Postgres
//! / ConfigMap) for multi-replica deployments lives beyond Phase 0.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// One emitted finding, enriched with routing metadata so it's
/// directly renderable in the admin console without extra joins.
/// `source_pod` tells the console which pod produced it so the union
/// view can label rows ("api" vs "fs") and filter by origin.
#[derive(Clone, Debug, Serialize)]
pub struct FindingRecord {
    pub id: String,
    pub ts: String,
    pub request_id: String,
    pub source_ip: String,
    /// Which pod recorded this finding — "siphon-api" or "siphon-fs".
    pub source_pod: String,
    pub category: String,
    pub sub_category: String,
    pub text: String,
    pub confidence: f64,
    pub has_context: bool,
    pub span: (usize, usize),
    pub metadata: HashMap<String, String>,
    pub severity: &'static str,
}

/// Coarse severity bucket. Keeping derivation on the server means
/// every client sees the same classification for the same (category,
/// confidence) pair. Both pods call into this so the buckets stay
/// identical across the two rings.
pub fn severity_for(category: &str, confidence: f64) -> &'static str {
    let c = category.to_ascii_lowercase();
    let critical = c.contains("credit card")
        || c.contains("primary account")
        || c.contains("secret")
        || c.contains("medical identifier");
    if critical && confidence >= 0.80 {
        return "red";
    }
    if confidence >= 0.90 {
        return "red";
    }
    if confidence >= 0.70 {
        return "warn";
    }
    "safe"
}

/// Bounded in-memory ring of `FindingRecord`s. Thread-safe via Mutex
/// — writes are per-scan (low rate) and reads are per `/v1/findings`
/// poll (also low rate), so lock contention is not a concern at lab
/// scale. `snapshot()` clones for caller safety.
pub struct FindingsRing {
    buf: Mutex<VecDeque<FindingRecord>>,
    cap: usize,
}

impl FindingsRing {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn push(&self, rec: FindingRecord) {
        let mut guard = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= self.cap {
            guard.pop_front();
        }
        guard.push_back(rec);
    }

    /// Newest-first copy of the ring for read handlers.
    pub fn snapshot(&self) -> Vec<FindingRecord> {
        let guard = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().rev().cloned().collect()
    }
}

/// Shared filter logic for `/v1/findings` queries. Both pods call
/// this so filter semantics stay identical — the admin console's
/// union view relies on every pod treating `category`, `severity`,
/// `contains`, and `since` the same way.
pub fn filter_findings<'a>(
    snapshot: &'a [FindingRecord],
    category: Option<&str>,
    severity: Option<&str>,
    contains: Option<&str>,
    since: Option<&str>,
) -> Vec<&'a FindingRecord> {
    let needle = contains.map(|s| s.to_ascii_lowercase());
    snapshot
        .iter()
        .filter(|f| category.is_none_or(|c| f.category == c))
        .filter(|f| severity.is_none_or(|s| f.severity == s))
        .filter(|f| {
            needle.as_deref().is_none_or(|n| {
                f.text.to_ascii_lowercase().contains(n)
                    || f.category.to_ascii_lowercase().contains(n)
                    || f.sub_category.to_ascii_lowercase().contains(n)
            })
        })
        .filter(|f| since.is_none_or(|s| f.ts.as_str() > s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, cat: &str, conf: f64) -> FindingRecord {
        FindingRecord {
            id: id.into(),
            ts: "2026-04-19T00:00:00Z".into(),
            request_id: "req".into(),
            source_ip: "127.0.0.1".into(),
            source_pod: "siphon-test".into(),
            category: cat.into(),
            sub_category: "x".into(),
            text: "hello".into(),
            confidence: conf,
            has_context: false,
            span: (0, 0),
            metadata: HashMap::new(),
            severity: severity_for(cat, conf),
        }
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let r = FindingsRing::new(2);
        r.push(rec("a", "Email Address", 0.5));
        r.push(rec("b", "Email Address", 0.5));
        r.push(rec("c", "Email Address", 0.5));
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, "c"); // newest first
        assert_eq!(snap[1].id, "b");
    }

    #[test]
    fn severity_reflects_category_and_confidence() {
        assert_eq!(severity_for("Credit Card Numbers", 0.85), "red");
        assert_eq!(severity_for("Credit Card Numbers", 0.70), "warn");
        assert_eq!(severity_for("Other", 0.95), "red");
        assert_eq!(severity_for("Other", 0.50), "safe");
    }

    #[test]
    fn filter_by_category_and_contains() {
        let snap = vec![
            rec("a", "Email Address", 0.9),
            rec("b", "Credit Card Numbers", 0.95),
        ];
        let only_email = filter_findings(&snap, Some("Email Address"), None, None, None);
        assert_eq!(only_email.len(), 1);
        assert_eq!(only_email[0].id, "a");

        let contains_hit = filter_findings(&snap, None, None, Some("hello"), None);
        assert_eq!(contains_hit.len(), 2);
    }
}
