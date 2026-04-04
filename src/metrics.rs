use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Scan metrics collected during a scan operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanMetrics {
    pub duration_ms: f64,
    pub match_count: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub bytes_scanned: usize,
    pub patterns_timed_out: usize,
    pub scan_truncated: bool,
    pub categories_scanned: Vec<String>,
    pub error: Option<String>,
}

/// Collects metrics for a scan operation.
///
/// Create a collector at the start of a scan, update its `metrics` field
/// during the scan, then call `finish()` to record the duration and
/// invoke the global callback (if one is registered).
pub struct MetricsCollector {
    start: Instant,
    pub metrics: ScanMetrics,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            metrics: ScanMetrics::default(),
        }
    }

    /// Finish collection: record elapsed time, invoke global callback, return metrics.
    pub fn finish(mut self) -> ScanMetrics {
        self.metrics.duration_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        if let Some(cb) = get_metrics_callback() {
            cb(&self.metrics);
        }
        self.metrics
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global callback
// ---------------------------------------------------------------------------

type MetricsCallback = Arc<dyn Fn(&ScanMetrics) + Send + Sync>;

fn global_callback() -> &'static Mutex<Option<MetricsCallback>> {
    use std::sync::OnceLock;
    static INSTANCE: OnceLock<Mutex<Option<MetricsCallback>>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new(None))
}

/// Register a global callback that is invoked every time a `MetricsCollector`
/// finishes.
pub fn set_metrics_callback<F>(callback: F)
where
    F: Fn(&ScanMetrics) + Send + Sync + 'static,
{
    *global_callback().lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(callback));
}

/// Remove the global metrics callback.
pub fn clear_metrics_callback() {
    *global_callback().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn get_metrics_callback() -> Option<MetricsCallback> {
    global_callback().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Tests that touch the global callback must not run in parallel.
    static CALLBACK_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn default_metrics_are_zeroed() {
        let m = ScanMetrics::default();
        assert_eq!(m.match_count, 0);
        assert_eq!(m.files_scanned, 0);
        assert_eq!(m.bytes_scanned, 0);
        assert!(!m.scan_truncated);
        assert!(m.error.is_none());
        assert!(m.categories_scanned.is_empty());
    }

    #[test]
    fn collector_records_duration() {
        let _guard = CALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_metrics_callback();

        let collector = MetricsCollector::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let metrics = collector.finish();
        assert!(metrics.duration_ms >= 5.0, "expected >=5ms, got {}", metrics.duration_ms);
    }

    #[test]
    fn collector_accumulates_fields() {
        clear_metrics_callback();

        let mut collector = MetricsCollector::new();
        collector.metrics.files_scanned = 42;
        collector.metrics.bytes_scanned = 1024;
        collector.metrics.match_count = 3;
        collector.metrics.categories_scanned = vec!["pii".into(), "secrets".into()];

        let metrics = collector.finish();
        assert_eq!(metrics.files_scanned, 42);
        assert_eq!(metrics.bytes_scanned, 1024);
        assert_eq!(metrics.match_count, 3);
        assert_eq!(metrics.categories_scanned, vec!["pii", "secrets"]);
    }

    #[test]
    fn callback_is_invoked_on_finish() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        set_metrics_callback(move |m: &ScanMetrics| {
            assert_eq!(m.files_scanned, 7);
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let mut collector = MetricsCollector::new();
        collector.metrics.files_scanned = 7;
        let _ = collector.finish();

        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Clean up so other tests are not affected.
        clear_metrics_callback();
    }

    #[test]
    fn clear_callback_prevents_invocation() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        set_metrics_callback(move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
        clear_metrics_callback();

        let collector = MetricsCollector::new();
        let _ = collector.finish();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn metrics_serializes_to_json() {
        let mut m = ScanMetrics::default();
        m.files_scanned = 5;
        m.error = Some("timeout".into());

        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"files_scanned\":5"));
        assert!(json.contains("\"error\":\"timeout\""));

        let deserialized: ScanMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.files_scanned, 5);
        assert_eq!(deserialized.error.as_deref(), Some("timeout"));
    }
}
