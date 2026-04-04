//! Structured audit event logging with multiple handler backends.
//!
//! Provides [`AuditEvent`] for recording DLP scan actions, pluggable
//! [`AuditHandler`] backends (stderr, file, callback, null), and a global
//! singleton [`AuditLogger`] for application-wide audit trails.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The set of recognised audit event types.
pub const VALID_EVENT_TYPES: &[&str] = &[
    "SCAN",
    "TOKENIZE",
    "DETOKENIZE",
    "OBFUSCATE",
    "REDACT",
    "REJECT",
    "FLAG",
];

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// A single structured audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub timestamp: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub categories_scanned: Vec<String>,
    #[serde(default)]
    pub categories_found: Vec<String>,
    #[serde(default)]
    pub finding_count: usize,
    #[serde(default)]
    pub is_clean: bool,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<f64>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuditEvent {
    /// Create a new [`AuditEvent`] with the given `event_type`.
    ///
    /// Returns an error if `event_type` is not one of [`VALID_EVENT_TYPES`].
    pub fn new(event_type: &str) -> Result<Self, String> {
        if !VALID_EVENT_TYPES.contains(&event_type) {
            return Err(format!("Invalid event type: {}", event_type));
        }

        Ok(Self {
            event_type: event_type.to_string(),
            timestamp: iso8601_now(),
            user: None,
            action: None,
            categories_scanned: Vec::new(),
            categories_found: Vec::new(),
            finding_count: 0,
            is_clean: false,
            source: None,
            duration_ms: None,
            metadata: HashMap::new(),
        })
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source = Some(source.to_string());
        self
    }

    pub fn with_duration_ms(mut self, ms: f64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    pub fn with_finding_count(mut self, count: usize) -> Self {
        self.finding_count = count;
        self
    }

    pub fn with_is_clean(mut self, clean: bool) -> Self {
        self.is_clean = clean;
        self
    }

    pub fn with_categories_found(mut self, cats: Vec<String>) -> Self {
        self.categories_found = cats;
        self
    }

    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Return the current UTC time formatted as ISO 8601 (`2024-01-15T12:00:00Z`).
fn iso8601_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let total_secs = dur.as_secs();
    // Algorithm: convert Unix epoch seconds to calendar date/time.
    let secs_per_day: u64 = 86400;
    let days = total_secs / secs_per_day;
    let day_secs = total_secs % secs_per_day;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since 1970-01-01 to calendar date (Gregorian).
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since 1970-01-01 to (year, month, day).
fn days_to_ymd(days: u64) -> (i64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe =
        (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// AuditHandler trait
// ---------------------------------------------------------------------------

/// Trait for audit event backends.
pub trait AuditHandler: Send + Sync {
    /// Process an audit event.
    fn handle(&self, event: &AuditEvent);
}

// ---------------------------------------------------------------------------
// Handler implementations
// ---------------------------------------------------------------------------

/// Writes JSON lines to stderr.
pub struct StderrAuditHandler;

impl AuditHandler for StderrAuditHandler {
    fn handle(&self, event: &AuditEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            let _ = writeln!(std::io::stderr(), "{json}");
        }
    }
}

/// Writes JSON lines to a file (thread-safe, append mode, file mode 0o600).
pub struct FileAuditHandler {
    path: String,
    lock: Mutex<()>,
}

impl FileAuditHandler {
    /// Create a new [`FileAuditHandler`] that appends to `path`.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            lock: Mutex::new(()),
        }
    }
}

impl AuditHandler for FileAuditHandler {
    fn handle(&self, event: &AuditEvent) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(path = %self.path, error = %e, "Failed to serialize audit event");
                return;
            }
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path);

        match file {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{json}") {
                    tracing::error!(path = %self.path, error = %e, "Failed to write audit log");
                }
            }
            Err(e) => {
                tracing::error!(path = %self.path, error = %e, "Failed to open audit log file");
            }
        }
    }
}

// Unix-specific: OpenOptions::mode
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Calls a user-provided closure for each event.
pub struct CallbackAuditHandler {
    callback: Box<dyn Fn(&AuditEvent) + Send + Sync>,
}

impl CallbackAuditHandler {
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&AuditEvent) + Send + Sync + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl AuditHandler for CallbackAuditHandler {
    fn handle(&self, event: &AuditEvent) {
        (self.callback)(event);
    }
}

/// No-op handler — silently discards events.
pub struct NullAuditHandler;

impl AuditHandler for NullAuditHandler {
    fn handle(&self, _event: &AuditEvent) {}
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Central audit logger that dispatches events to registered handlers.
pub struct AuditLogger {
    handlers: Vec<Box<dyn AuditHandler>>,
    default_user: Option<String>,
}

impl AuditLogger {
    /// Create an empty logger with no handlers.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            default_user: None,
        }
    }

    /// Builder: add a handler.
    pub fn with_handler(mut self, handler: Box<dyn AuditHandler>) -> Self {
        self.handlers.push(handler);
        self
    }

    /// Builder: set the default user attached to events that lack one.
    pub fn with_user(mut self, user: &str) -> Self {
        self.default_user = Some(user.to_string());
        self
    }

    /// Add a handler after construction.
    pub fn add_handler(&mut self, handler: Box<dyn AuditHandler>) {
        self.handlers.push(handler);
    }

    /// Dispatch `event` to all registered handlers.
    ///
    /// If the event has no user set and a `default_user` is configured, the
    /// default user is applied to a clone of the event before dispatching.
    pub fn log(&self, event: &AuditEvent) {
        let event = if event.user.is_none() && self.default_user.is_some() {
            let mut patched = event.clone();
            patched.user = self.default_user.clone();
            patched
        } else {
            event.clone()
        };

        for handler in &self.handlers {
            handler.handle(&event);
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static GLOBAL_AUDIT: OnceLock<Mutex<Option<AuditLogger>>> = OnceLock::new();

fn global_cell() -> &'static Mutex<Option<AuditLogger>> {
    GLOBAL_AUDIT.get_or_init(|| Mutex::new(None))
}

/// Install a global [`AuditLogger`].
pub fn set_audit_logger(logger: AuditLogger) {
    let mut guard = global_cell().lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(logger);
}

/// Run a closure with a reference to the global [`AuditLogger`], if one is set.
///
/// Returns `None` when no logger has been installed.
pub fn with_audit_logger<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&AuditLogger) -> R,
{
    let guard = global_cell().lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// Convenience: log an event via the global logger (no-op if none is set).
pub fn audit_event(event: &AuditEvent) {
    with_audit_logger(|logger| logger.log(event));
}

// ---------------------------------------------------------------------------
// Factory helpers
// ---------------------------------------------------------------------------

/// Create an [`AuditEvent`] from a [`crate::guard::ScanResult`].
pub fn event_from_scan(
    result: &crate::guard::ScanResult,
    action: &str,
    source: Option<&str>,
    duration_ms: Option<f64>,
    user: Option<&str>,
) -> AuditEvent {
    let event_type = match action.to_uppercase().as_str() {
        "REJECT" => "REJECT",
        "REDACT" => "REDACT",
        "FLAG" => "FLAG",
        "TOKENIZE" => "TOKENIZE",
        "OBFUSCATE" => "OBFUSCATE",
        "DETOKENIZE" => "DETOKENIZE",
        _ => "SCAN",
    };

    let mut event = match AuditEvent::new(event_type) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!("Failed to create audit event: {}", err);
            return AuditEvent::new("SCAN").unwrap_or_else(|_| AuditEvent {
                event_type: "SCAN".to_string(),
                timestamp: iso8601_now(),
                user: None,
                action: None,
                categories_scanned: Vec::new(),
                categories_found: Vec::new(),
                finding_count: 0,
                is_clean: false,
                source: None,
                duration_ms: None,
                metadata: HashMap::new(),
            });
        }
    };

    event = event
        .with_action(action)
        .with_is_clean(result.is_clean)
        .with_finding_count(result.finding_count())
        .with_categories_found(
            result
                .categories_found
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );

    if let Some(src) = source {
        event = event.with_source(src);
    }
    if let Some(ms) = duration_ms {
        event = event.with_duration_ms(ms);
    }
    if let Some(u) = user {
        event = event.with_user(u);
    }

    event
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    #[test]
    fn test_valid_event_types() {
        for &et in VALID_EVENT_TYPES {
            let event = AuditEvent::new(et).unwrap();
            assert_eq!(event.event_type, et);
        }
    }

    #[test]
    fn test_invalid_event_type_returns_error() {
        let result = AuditEvent::new("INVALID");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid event type"));
    }

    #[test]
    fn test_builder_methods() {
        let event = AuditEvent::new("SCAN")
            .unwrap()
            .with_user("alice")
            .with_action("scan")
            .with_source("api")
            .with_duration_ms(42.5)
            .with_finding_count(3)
            .with_is_clean(false)
            .with_categories_found(vec!["PII".into(), "SSN".into()])
            .with_metadata("key", serde_json::json!("value"));

        assert_eq!(event.user.as_deref(), Some("alice"));
        assert_eq!(event.action.as_deref(), Some("scan"));
        assert_eq!(event.source.as_deref(), Some("api"));
        assert_eq!(event.duration_ms, Some(42.5));
        assert_eq!(event.finding_count, 3);
        assert!(!event.is_clean);
        assert_eq!(event.categories_found, vec!["PII", "SSN"]);
        assert_eq!(
            event.metadata.get("key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn test_timestamp_format() {
        let event = AuditEvent::new("SCAN").unwrap();
        // Should match ISO 8601 pattern: YYYY-MM-DDTHH:MM:SSZ
        assert!(event.timestamp.ends_with('Z'));
        assert_eq!(event.timestamp.len(), 20);
        assert_eq!(&event.timestamp[4..5], "-");
        assert_eq!(&event.timestamp[7..8], "-");
        assert_eq!(&event.timestamp[10..11], "T");
        assert_eq!(&event.timestamp[13..14], ":");
        assert_eq!(&event.timestamp[16..17], ":");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event = AuditEvent::new("REDACT")
            .unwrap()
            .with_user("bob")
            .with_finding_count(2)
            .with_is_clean(false);

        let json = serde_json::to_string(&event).unwrap();
        let deser: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deser.event_type, "REDACT");
        assert_eq!(deser.user.as_deref(), Some("bob"));
        assert_eq!(deser.finding_count, 2);
        assert!(!deser.is_clean);
    }

    #[test]
    fn test_null_handler() {
        // Should not panic.
        let handler = NullAuditHandler;
        handler.handle(&AuditEvent::new("SCAN").unwrap());
    }

    #[test]
    fn test_callback_handler() {
        let captured: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);

        let handler = CallbackAuditHandler::new(move |event: &AuditEvent| {
            captured_clone
                .lock()
                .unwrap()
                .push(event.event_type.clone());
        });

        handler.handle(&AuditEvent::new("SCAN").unwrap());
        handler.handle(&AuditEvent::new("REJECT").unwrap());

        let events = captured.lock().unwrap();
        assert_eq!(*events, vec!["SCAN", "REJECT"]);
    }

    #[test]
    fn test_file_handler() {
        let dir = std::env::temp_dir().join("dlpscan_audit_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let path_str = path.to_string_lossy().to_string();

        // Clean up from prior runs.
        let _ = std::fs::remove_file(&path);

        let handler = FileAuditHandler::new(&path_str);
        handler.handle(&AuditEvent::new("SCAN").unwrap().with_user("test"));
        handler.handle(&AuditEvent::new("REDACT").unwrap());

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.event_type, "SCAN");
        assert_eq!(first.user.as_deref(), Some("test"));

        // Cleanup.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_audit_logger_dispatches() {
        let captured: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let c = Arc::clone(&captured);

        let logger = AuditLogger::new()
            .with_handler(Box::new(CallbackAuditHandler::new(move |e| {
                c.lock().unwrap().push(e.event_type.clone());
            })));

        logger.log(&AuditEvent::new("SCAN").unwrap());
        logger.log(&AuditEvent::new("FLAG").unwrap());

        let events = captured.lock().unwrap();
        assert_eq!(*events, vec!["SCAN", "FLAG"]);
    }

    #[test]
    fn test_audit_logger_default_user() {
        let captured: Arc<StdMutex<Vec<Option<String>>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let c = Arc::clone(&captured);

        let logger = AuditLogger::new()
            .with_user("default_user")
            .with_handler(Box::new(CallbackAuditHandler::new(move |e| {
                c.lock().unwrap().push(e.user.clone());
            })));

        // Event without user -> should get default.
        logger.log(&AuditEvent::new("SCAN").unwrap());
        // Event with explicit user -> should keep its own.
        logger.log(&AuditEvent::new("SCAN").unwrap().with_user("explicit"));

        let users = captured.lock().unwrap();
        assert_eq!(users[0], Some("default_user".to_string()));
        assert_eq!(users[1], Some("explicit".to_string()));
    }

    #[test]
    fn test_audit_logger_add_handler() {
        let captured: Arc<StdMutex<usize>> = Arc::new(StdMutex::new(0));
        let c = Arc::clone(&captured);

        let mut logger = AuditLogger::new();
        logger.add_handler(Box::new(CallbackAuditHandler::new(move |_| {
            *c.lock().unwrap() += 1;
        })));

        logger.log(&AuditEvent::new("SCAN").unwrap());
        assert_eq!(*captured.lock().unwrap(), 1);
    }

    #[test]
    fn test_global_audit_event_no_logger() {
        // Should be a no-op, not panic.
        audit_event(&AuditEvent::new("SCAN").unwrap());
    }

    #[test]
    fn test_event_from_scan() {
        use std::collections::HashSet;

        let scan_result = crate::guard::ScanResult {
            text: "hello".to_string(),
            is_clean: false,
            findings: vec![],
            redacted_text: None,
            categories_found: {
                let mut s = HashSet::new();
                s.insert("SSN".to_string());
                s
            },
            scan_truncated: false,
        };

        let event = event_from_scan(
            &scan_result,
            "redact",
            Some("cli"),
            Some(12.3),
            Some("alice"),
        );

        assert_eq!(event.event_type, "REDACT");
        assert_eq!(event.action.as_deref(), Some("redact"));
        assert_eq!(event.source.as_deref(), Some("cli"));
        assert_eq!(event.duration_ms, Some(12.3));
        assert_eq!(event.user.as_deref(), Some("alice"));
        assert!(!event.is_clean);
        assert!(event.categories_found.contains(&"SSN".to_string()));
    }

    #[test]
    fn test_event_from_scan_unknown_action_defaults_to_scan() {
        use std::collections::HashSet;

        let scan_result = crate::guard::ScanResult {
            text: String::new(),
            is_clean: true,
            findings: vec![],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
        };

        let event = event_from_scan(&scan_result, "unknown_action", None, None, None);
        assert_eq!(event.event_type, "SCAN");
    }
}
