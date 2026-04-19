//! Pattern overrides — deployable layer on top of the compile-time
//! pattern set without rebuilding any crate.
//!
//! Both siphon-api and siphon-fs read the same JSON file (mounted from
//! a Kubernetes ConfigMap in the lab; supplied via `SIPHON_OVERRIDES_PATH`
//! environment variable in dev) at startup and consult it during scans.
//! When the admin console commits an edit (Phase 4), the apply endpoint
//! writes the file and triggers a rolling restart of both Deployments
//! (Phase 6) so every detection pod converges on the new ruleset
//! together.
//!
//! Phase 3a (this file) defines the on-disk shape, the loader, and the
//! lookup helpers. Phase 3b wires the scanner to actually skip
//! `disabled_patterns`. Phases 3c and 3d add field overrides and
//! custom categories respectively.
//!
//! The overrides file is *additive* — base patterns always remain
//! restorable by deleting the relevant entry. Removing the file
//! entirely returns the engine to its compile-time defaults.

// Re-exported so siphon-api and siphon-fs can store the compiled
// override map in their AppState without taking a direct dep on
// `regex` themselves.
pub use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Current schema version. Bumped on incompatible shape changes; the
/// loader rejects unknown versions instead of silently ignoring fields
/// it doesn't understand.
pub const CURRENT_VERSION: u32 = 0;

/// Composite key for a pattern in the registry. Used as the lookup key
/// for `disabled_patterns` and `pattern_overrides` so the same shape is
/// reused throughout. Two-string newtype rather than a tuple for clarity
/// at call sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternKey {
    pub category: String,
    pub sub_category: String,
}

impl PatternKey {
    pub fn new(category: impl Into<String>, sub_category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            sub_category: sub_category.into(),
        }
    }

    /// Wire format used for `pattern_overrides` map keys —
    /// "<category>/<sub_category>" — chosen so the JSON file stays
    /// readable in version control diffs.
    pub fn to_wire(&self) -> String {
        format!("{}/{}", self.category, self.sub_category)
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        let (cat, sub) = s.split_once('/')?;
        Some(Self::new(cat, sub))
    }
}

/// Per-pattern field overrides. Every field is Optional so a partial
/// override (e.g. just bumping `specificity`) can sit alongside the
/// compile-time defaults for everything else.
///
/// Honoured by the scanner today (Phase 3c):
///   · specificity        — replaces pattern_specificity() at scoring time
///   · context_required   — replaces is_context_required() at gating time
///
/// Loaded but not yet applied (lands in Phase 3d alongside custom
/// categories, since they share the runtime regex/AC compilation
/// machinery):
///   · regex              — runtime regex recompilation
///   · case_insensitive   — same compilation path
///   · context_keywords   — runtime AC matcher rebuild
///   · proximity_chars    — context distance lookup
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternOverride {
    pub regex: Option<String>,
    pub specificity: Option<f64>,
    pub context_required: Option<bool>,
    pub case_insensitive: Option<bool>,
    pub context_keywords: Option<Vec<String>>,
    pub proximity_chars: Option<u32>,
}

/// One pattern inside a custom category. Mirrors the shape the admin
/// console's NewPatternModal already writes to localStorage so the
/// Phase 4 apply path can serialise localStorage entries straight into
/// this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub sub_category: String,
    pub regex: String,
    pub specificity: f64,
    pub context_required: bool,
    pub case_insensitive: bool,
    pub context_keywords: Vec<String>,
    pub proximity_chars: u32,
}

impl Default for CustomPattern {
    fn default() -> Self {
        Self {
            sub_category: String::new(),
            regex: String::new(),
            specificity: 0.5,
            context_required: false,
            case_insensitive: true,
            context_keywords: Vec::new(),
            proximity_chars: 50,
        }
    }
}

/// A custom category authored by an analyst. Phase 3d wires the
/// scanner to register these as additional patterns at startup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomCategory {
    pub name: String,
    pub group: String,
    pub description: String,
    pub patterns: Vec<CustomPattern>,
}

// ─── Reusable match lists (Phase 4.7) ────────────────────────────
//
// Lists are analyst-authored collections that policies reference
// with an action (allow, block, mask). Examples: an allow-list of
// partner domains that suppress email-address findings, a block-list
// of leaked hashes that force a red severity, a path-based exception
// list for a finance-team inbound flow.
//
// Lists themselves are purely data. Policies (loaded separately)
// attach them with an action; the scanner / router consults the
// combined (list, action) set at emit time (Phase 4.7c).

/// Discriminator for how entries in a list should be interpreted.
/// The scanner picks the right matcher per kind — exact for hashes,
/// case-insensitive substring for keywords, suffix match for domains,
/// etc. Serialises as lowercase ("keyword", "domain", …) so the wire
/// file stays readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListKind {
    /// Free-text words/phrases. Case-insensitive substring match.
    Keyword,
    /// Fully-qualified domains. Suffix match so `example.com` in the
    /// list also matches `foo.example.com`. Case-insensitive.
    Domain,
    /// Email addresses. Exact match case-insensitive, with an
    /// optional domain fallback when the entry begins with '@'.
    Email,
    /// Content hashes — MD5 / SHA-1 / SHA-256, hex-encoded lowercase.
    /// Exact match.
    Hash,
    /// IP addresses or CIDR blocks (`10.0.0.0/8`). Matches by
    /// containment.
    Ip,
    /// URLs or URL prefixes. Prefix match with trailing-slash
    /// normalisation.
    Url,
    /// Filesystem paths or glob patterns (`**/payroll/*`). Useful for
    /// destination-aware exceptions ("files going to /mnt/audit/**").
    Path,
    /// Generic fallback for kinds not yet modelled; matcher treats
    /// entries as case-insensitive exact strings.
    Other,
}

impl Default for ListKind {
    fn default() -> Self {
        ListKind::Keyword
    }
}

/// An attachment of a match list to an action, scoped globally —
/// the scanner honours every entry in `active_list_bindings` at
/// emit time regardless of which policy originally declared it.
///
/// Policies author their own bindings (see `siphon::policy::ListBinding`)
/// for documentation and audit; the admin-console Apply flow can
/// optionally merge policy bindings into `active_list_bindings` so
/// they actually influence scans. Keeping the scanner-active set
/// explicit + separate from policies means:
///   · pods don't need to load policies to enforce lists
///   · the operator sees a single "what's actually being enforced"
///     surface (the overrides file) without chasing per-policy TOML
///   · conflicting bindings from overlapping policies are resolved
///     once, at Apply time, instead of per-scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ListAttachment {
    pub list_id: String,
    /// "allow" | "block" | "mask" | "tag"
    pub action: String,
    pub note: String,
}

/// An analyst-authored list. `id` is stable across edits so policies
/// can reference it without risking rename drift. Timestamps are
/// strings (ISO8601) for wire-file readability; the scanner doesn't
/// read them today.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MatchList {
    /// Stable opaque id (e.g. `ml_<slug>`). Policies reference this.
    pub id: String,
    /// Human-facing label.
    pub name: String,
    /// Free-text description — why the list exists, who owns it.
    pub description: String,
    pub kind: ListKind,
    /// Raw entries. Interpretation depends on `kind`. Order doesn't
    /// matter for matching but is preserved for the UI.
    pub entries: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Top-level overrides document. Designed for human edits in git as
/// well as machine writes from the admin console — every collection is
/// optional + defaults to empty so a partially-filled document still
/// loads cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternOverrides {
    /// Schema version. Loader rejects values it doesn't recognise.
    pub version: u32,
    /// Patterns to skip at scan time, by composite key.
    pub disabled_patterns: Vec<PatternKey>,
    /// Field-level overrides keyed by "<category>/<sub_category>".
    pub pattern_overrides: HashMap<String, PatternOverride>,
    /// Analyst-authored categories with their own patterns.
    pub custom_categories: Vec<CustomCategory>,
    /// Reusable match lists (Phase 4.7). Policies reference these by
    /// id; the scanner consults them at emit time via
    /// `active_list_bindings` (Phase 4.7c).
    pub lists: Vec<MatchList>,
    /// Scanner-active list bindings. Each entry is a (list_id, action,
    /// note) attachment that the scanner honours at emit time. Empty
    /// by default so policies' declarative list_bindings don't
    /// silently take effect — operators opt in by merging the ones
    /// they actually want enforced into this field.
    pub active_list_bindings: Vec<ListAttachment>,
    /// Per-(category, sub_category) distinct-value thresholds.
    /// Keys are wire-formatted as "<category>/<sub_category>" — same
    /// convention as `pattern_overrides`. Value is the maximum number
    /// of distinct match strings the scanner will tolerate for that
    /// tuple in a single scan. Over the limit, every affected match
    /// gets metadata["unique_count_breach"] = "true" and
    /// metadata["action"] = "block" so downstream forwarders can
    /// escalate. Scanner doesn't drop breached matches — the analyst
    /// still sees everything, the router decides what to do. Empty
    /// map means no thresholds (Phase 9 default).
    pub max_unique_per_subcategory: HashMap<String, usize>,
}

/// Errors surfaced by the loader. Kept simple — the caller logs and
/// either falls back to defaults or refuses to start, depending on
/// readiness-probe semantics chosen per pod.
#[derive(Debug)]
pub enum LoadError {
    /// File could not be opened. The caller decides whether 'no file'
    /// means 'use defaults' or 'fail readiness' — Phase 3b lets it
    /// be the former so dev-mode doesn't need a file at all.
    Io(std::io::Error),
    /// File parsed as JSON but failed schema validation.
    Parse(String),
    /// Schema version doesn't match what this build understands.
    Version { found: u32, expected: u32 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "io: {e}"),
            LoadError::Parse(e) => write!(f, "parse: {e}"),
            LoadError::Version { found, expected } => {
                write!(f, "schema version {found} not supported (expected {expected})")
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl PatternOverrides {
    /// Empty overrides — the scanner behaves exactly as it did before
    /// Phase 3 when this is the active set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load + validate from a JSON file. Caller decides how to react
    /// to errors.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let bytes = std::fs::read(path.as_ref()).map_err(LoadError::Io)?;
        Self::from_bytes(&bytes)
    }

    /// Convenience: try the file, fall back to empty + log a warning
    /// when it's not present. Useful in dev where the file may not
    /// exist; the lab always has it via the ConfigMap mount.
    pub fn from_file_or_empty(path: impl AsRef<Path>) -> Self {
        match Self::from_file(path.as_ref()) {
            Ok(o) => o,
            Err(LoadError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Self::empty(),
            Err(e) => {
                eprintln!(
                    "siphon overrides: failed to load {} — {} · falling back to compile-time defaults",
                    path.as_ref().display(),
                    e
                );
                Self::empty()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LoadError> {
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|e| LoadError::Parse(e.to_string()))?;
        if parsed.version != CURRENT_VERSION {
            return Err(LoadError::Version {
                found: parsed.version,
                expected: CURRENT_VERSION,
            });
        }
        Ok(parsed)
    }

    /// O(1) check used by the scanner emit path. Build the underlying
    /// HashSet once at construction time when overrides are loaded.
    pub fn is_disabled(&self, category: &str, sub_category: &str) -> bool {
        // Linear scan is fine for a handful of disabled entries;
        // callers that need O(1) should call `disabled_set()` once and
        // keep the HashSet around. Phase 3b's scanner integration
        // builds the set up-front.
        self.disabled_patterns
            .iter()
            .any(|k| k.category == category && k.sub_category == sub_category)
    }

    /// Pre-compute a HashSet for repeated lookups.
    pub fn disabled_set(&self) -> HashSet<(String, String)> {
        self.disabled_patterns
            .iter()
            .map(|k| (k.category.clone(), k.sub_category.clone()))
            .collect()
    }

    pub fn override_for(&self, category: &str, sub_category: &str) -> Option<&PatternOverride> {
        let key = format!("{category}/{sub_category}");
        self.pattern_overrides.get(&key)
    }

    /// Pre-compute a `(category, sub_category) → PatternOverride` map
    /// that the scanner consults on every match. Built once at startup
    /// when overrides are loaded; cloned via Arc on each scan.
    pub fn override_lookup(&self) -> HashMap<(String, String), PatternOverride> {
        self.pattern_overrides
            .iter()
            .filter_map(|(k, v)| {
                let (cat, sub) = k.split_once('/')?;
                Some(((cat.to_string(), sub.to_string()), v.clone()))
            })
            .collect()
    }

    /// Counts surfaced via /v1/version + the admin console for an
    /// at-a-glance "what's actually applied" indicator.
    pub fn summary(&self) -> OverridesSummary {
        OverridesSummary {
            disabled_patterns: self.disabled_patterns.len(),
            pattern_overrides: self.pattern_overrides.len(),
            custom_categories: self.custom_categories.len(),
            custom_patterns: self
                .custom_categories
                .iter()
                .map(|c| c.patterns.len())
                .sum(),
            lists: self.lists.len(),
            list_entries: self.lists.iter().map(|l| l.entries.len()).sum(),
            unique_thresholds: self.max_unique_per_subcategory.len(),
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OverridesSummary {
    pub disabled_patterns: usize,
    pub pattern_overrides: usize,
    pub custom_categories: usize,
    pub custom_patterns: usize,
    /// Count of match lists (Phase 4.7). Sum of entries across all
    /// lists.
    pub lists: usize,
    pub list_entries: usize,
    /// Count of per-(cat,sub) thresholds declared (Phase 9).
    pub unique_thresholds: usize,
    pub version: u32,
}

// ─── Runtime patterns (compiled at startup from custom_categories) ──
//
// The compile-time PATTERNS slice is the source of truth for the
// vendored detection library. Custom categories declared in the
// overrides file get compiled into RuntimePattern entries at startup
// and run AFTER the static loop on every scan. This keeps the static
// path lock-free and zero-allocation while still letting analysts
// add org-specific rules without rebuilding any crate.
//
// Validation hooks (Luhn / IBAN / etc.) don't apply to runtime
// patterns yet — those are dispatched by category name in the
// validation module which only knows about compile-time categories.
// Custom patterns rely on regex + optional keyword context for now.

/// One compiled custom pattern, ready to be evaluated against a scan
/// input. The `Regex` is compiled with the right (?i) prefix when
/// `case_insensitive` is true, mirroring the static path.
pub struct RuntimePattern {
    pub category: String,
    pub sub_category: String,
    pub regex: Regex,
    pub specificity: f64,
    pub context_required: bool,
    pub context_keywords: Vec<String>,
    /// Char window either side of the match for keyword proximity
    /// checks. Stored as `usize` ready for `saturating_sub` / `min`.
    pub proximity_chars: usize,
}

impl PatternOverrides {
    /// Compile any `pattern_overrides.<key>.regex` entries into a
    /// per-pattern `Regex` keyed by `(category, sub_category)`. The
    /// scanner swaps the static compiled regex for an entry from this
    /// map whenever one exists — letting analysts tighten or loosen a
    /// baked-in pattern's regex without touching siphon-core. Same
    /// case_insensitive handling as the static path (prepends `(?i)`
    /// when the override sets it true; falls back to the static
    /// pattern's own case_insensitive when the override leaves it
    /// unset). Bad regexes are skipped with a stderr warning rather
    /// than failing the pod — operational continuity beats strictness.
    ///
    /// Note: `pattern_overrides.<key>.context_keywords` and
    /// `proximity_chars` for compile-time patterns are NOT yet
    /// honoured — those would require rebuilding the static
    /// Aho-Corasick context matcher in `crate::context`. Disable +
    /// custom-category-clone is the workaround today.
    pub fn compile_pattern_regex_overrides(
        &self,
    ) -> HashMap<(String, String), Regex> {
        let mut out = HashMap::new();
        for (wire_key, po) in &self.pattern_overrides {
            let Some((cat, sub)) = wire_key.split_once('/') else {
                eprintln!(
                    "siphon overrides: pattern_overrides key '{wire_key}' is not '<cat>/<sub>', skipping"
                );
                continue;
            };
            let Some(regex_str) = po.regex.as_ref() else {
                continue; // override exists but no regex change
            };
            // Apply case_insensitive override if set; otherwise the
            // static path's flag will continue to apply because the
            // scanner only swaps the regex, not other fields.
            let prepared = if po.case_insensitive.unwrap_or(false) {
                format!("(?i){regex_str}")
            } else {
                regex_str.clone()
            };
            match Regex::new(&prepared) {
                Ok(re) => {
                    out.insert((cat.to_string(), sub.to_string()), re);
                }
                Err(e) => {
                    eprintln!(
                        "siphon overrides: regex for '{wire_key}' failed to compile — {e} · skipping override (static pattern still applies)"
                    );
                }
            }
        }
        out
    }

    /// Compile every `custom_categories[*].patterns[*]` entry into a
    /// `RuntimePattern`. Patterns whose regex fails to compile are
    /// skipped with a stderr warning — operational continuity beats
    /// hard-fail (a single bad regex shouldn't take the pod offline).
    /// Cost is paid once per pod startup; subsequent scans just clone
    /// the resulting `Arc<Vec<RuntimePattern>>` into ScanConfig.
    pub fn compile_runtime_patterns(&self) -> Vec<RuntimePattern> {
        let mut out = Vec::new();
        for cat in &self.custom_categories {
            for cp in &cat.patterns {
                if cp.sub_category.is_empty() || cp.regex.is_empty() {
                    eprintln!(
                        "siphon overrides: custom pattern in '{}' has empty regex or sub_category, skipping",
                        cat.name
                    );
                    continue;
                }
                let regex_str = if cp.case_insensitive {
                    format!("(?i){}", cp.regex)
                } else {
                    cp.regex.clone()
                };
                match Regex::new(&regex_str) {
                    Ok(re) => out.push(RuntimePattern {
                        category: cat.name.clone(),
                        sub_category: cp.sub_category.clone(),
                        regex: re,
                        specificity: cp.specificity,
                        context_required: cp.context_required,
                        context_keywords: cp.context_keywords.clone(),
                        proximity_chars: cp.proximity_chars as usize,
                    }),
                    Err(e) => {
                        eprintln!(
                            "siphon overrides: custom pattern '{}/{}' regex failed to compile — {} · skipping",
                            cat.name, cp.sub_category, e
                        );
                    }
                }
            }
        }
        out
    }
}

// ─── Compiled list matcher (Phase 4.7c.1) ───────────────────────
//
// MatchList is declarative data — `CompiledList` is what the scanner
// actually consults at emit time. Per-kind matcher semantics live
// here so the scanner stays oblivious to list interpretation.
//
// Matchers are intentionally naive (linear scans, simple string ops)
// because lists are expected to be short — a handful of partner
// domains, a curated block-list of hashes, etc. If a list grows to
// thousands of entries, swap the matcher for an Aho-Corasick / hash
// set / IP tree without changing the caller surface.

/// Compiled form of a MatchList. Keeps entries lowercased where
/// appropriate so matching is allocation-free at scan time.
#[derive(Debug, Clone)]
pub struct CompiledList {
    pub id: String,
    pub name: String,
    pub kind: ListKind,
    /// Entries pre-normalised for the list's kind (lowercase for
    /// string-ish kinds, whitespace-trimmed, etc.).
    entries: Vec<String>,
}

impl CompiledList {
    pub fn from_list(list: &MatchList) -> Self {
        let entries: Vec<String> = list
            .entries
            .iter()
            .map(|e| {
                let trimmed = e.trim();
                match list.kind {
                    // String-ish kinds normalise to lowercase.
                    ListKind::Keyword
                    | ListKind::Domain
                    | ListKind::Email
                    | ListKind::Url
                    | ListKind::Path
                    | ListKind::Other => trimmed.to_lowercase(),
                    // Hashes normalise to lowercase hex too — matches
                    // the usual convention and lets analysts paste
                    // hashes in any casing.
                    ListKind::Hash => trimmed.to_lowercase(),
                    // IPs/CIDRs: keep verbatim for now; proper CIDR
                    // parsing lands in a follow-up (requires the
                    // ipnetwork crate). Falls back to exact string
                    // match until then.
                    ListKind::Ip => trimmed.to_string(),
                }
            })
            .filter(|e| !e.is_empty())
            .collect();
        Self {
            id: list.id.clone(),
            name: list.name.clone(),
            kind: list.kind,
            entries,
        }
    }

    /// Returns true if `text` (the finding's matched span or the
    /// scan context it's being evaluated against) satisfies this
    /// list's matcher.
    ///
    /// Interpretations:
    ///   · Keyword: case-insensitive substring
    ///   · Domain:  case-insensitive suffix; `example.com` matches
    ///              `foo.example.com` AND a bare `example.com`
    ///   · Email:   leading `@` = domain-suffix; else exact
    ///   · Hash:    exact (lowercased)
    ///   · Url:     case-insensitive prefix
    ///   · Path:    naive — substring today; proper glob in follow-up
    ///   · Ip:      case-insensitive exact today (string); CIDR
    ///              containment in a follow-up
    ///   · Other:   case-insensitive exact
    pub fn matches(&self, text: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let lower = text.trim().to_lowercase();
        match self.kind {
            ListKind::Keyword => self.entries.iter().any(|e| lower.contains(e)),
            ListKind::Domain => self.entries.iter().any(|e| {
                // Matches bare domain, sub-domain suffix, AND emails
                // whose local@<domain> ends with the entry — that's
                // the common 'partner domains allow list' case.
                lower == *e
                    || lower.ends_with(&format!(".{e}"))
                    || lower.ends_with(&format!("@{e}"))
            }),
            ListKind::Email => self.entries.iter().any(|e| {
                if let Some(dom) = e.strip_prefix('@') {
                    lower.ends_with(&format!("@{dom}"))
                } else {
                    lower == *e
                }
            }),
            ListKind::Url => self.entries.iter().any(|e| lower.starts_with(e)),
            ListKind::Path => self.entries.iter().any(|e| lower.contains(e)),
            ListKind::Hash | ListKind::Ip | ListKind::Other => {
                self.entries.iter().any(|e| lower == *e)
            }
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl PatternOverrides {
    /// Compile every list into a `(list_id -> CompiledList)` lookup.
    /// Called once at pod startup; the lookup lives alongside the
    /// rest of the derived overrides state on the pod's AppState.
    pub fn compile_lists(&self) -> HashMap<String, CompiledList> {
        self.lists
            .iter()
            .filter(|l| !l.id.is_empty())
            .map(|l| (l.id.clone(), CompiledList::from_list(l)))
            .collect()
    }

    /// Resolve `max_unique_per_subcategory` wire-keys into the
    /// `(category, sub_category) → usize` lookup the scanner
    /// consumes. Malformed keys (not "<cat>/<sub>") are skipped with
    /// a stderr warning so one typo doesn't take the pod offline.
    pub fn compile_unique_thresholds(&self) -> HashMap<(String, String), usize> {
        self.max_unique_per_subcategory
            .iter()
            .filter_map(|(wire_key, limit)| {
                match wire_key.split_once('/') {
                    Some((cat, sub)) => Some(((cat.to_string(), sub.to_string()), *limit)),
                    None => {
                        eprintln!(
                            "siphon overrides: max_unique_per_subcategory key '{wire_key}' is not '<cat>/<sub>', skipping"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Resolve `active_list_bindings` into the scanner-ready
    /// `(action, CompiledList)` vector. Bindings pointing at
    /// missing list ids are skipped with a stderr warning — keeps a
    /// typo from taking the pod offline while making the problem
    /// visible in the logs.
    pub fn compile_active_list_bindings(&self) -> Vec<(String, CompiledList)> {
        if self.active_list_bindings.is_empty() {
            return Vec::new();
        }
        let lists = self.compile_lists();
        self.active_list_bindings
            .iter()
            .filter_map(|b| {
                if b.list_id.is_empty() || b.action.is_empty() {
                    return None;
                }
                match lists.get(&b.list_id) {
                    Some(cl) => Some((b.action.clone(), cl.clone())),
                    None => {
                        eprintln!(
                            "siphon overrides: active_list_bindings references unknown list '{}' — skipping",
                            b.list_id
                        );
                        None
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_safe() {
        let o = PatternOverrides::empty();
        assert!(!o.is_disabled("Email Address", "personal"));
        assert!(o.override_for("Email Address", "personal").is_none());
        assert_eq!(o.summary().disabled_patterns, 0);
    }

    #[test]
    fn parses_minimal_document() {
        let json = r#"{"version":0}"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(o.version, 0);
        assert!(o.disabled_patterns.is_empty());
    }

    #[test]
    fn rejects_future_versions() {
        let json = r#"{"version":99}"#;
        let err = PatternOverrides::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, LoadError::Version { found: 99, expected: 0 }));
    }

    #[test]
    fn disabled_lookup_round_trip() {
        let json = r#"{
            "version":0,
            "disabled_patterns":[
                {"category":"Email Address","sub_category":"personal"}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert!(o.is_disabled("Email Address", "personal"));
        assert!(!o.is_disabled("Email Address", "corporate"));
    }

    #[test]
    fn pattern_override_lookup_round_trip() {
        let json = r#"{
            "version":0,
            "pattern_overrides":{
                "PII/email.v1":{"specificity":0.95,"context_required":true}
            }
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let ov = o.override_for("PII", "email.v1").unwrap();
        assert_eq!(ov.specificity, Some(0.95));
        assert_eq!(ov.context_required, Some(true));
        assert_eq!(ov.regex, None);
    }

    #[test]
    fn custom_categories_summary() {
        let json = r#"{
            "version":0,
            "custom_categories":[
                {"name":"MYORG","group":"SECRET","patterns":[
                    {"sub_category":"emp.id","regex":"EMP-\\d+","specificity":0.7}
                ]}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let s = o.summary();
        assert_eq!(s.custom_categories, 1);
        assert_eq!(s.custom_patterns, 1);
    }

    #[test]
    fn pattern_key_wire_round_trip() {
        let k = PatternKey::new("PCI", "visa.v3");
        assert_eq!(k.to_wire(), "PCI/visa.v3");
        assert_eq!(PatternKey::from_wire("PCI/visa.v3"), Some(k));
        assert_eq!(PatternKey::from_wire("malformed"), None);
    }

    #[test]
    fn missing_file_falls_back_to_empty() {
        let o = PatternOverrides::from_file_or_empty("/nonexistent/path/x.json");
        assert_eq!(o.summary().disabled_patterns, 0);
    }

    #[test]
    fn compile_pattern_regex_overrides_round_trips() {
        let json = r#"{
            "version":0,
            "pattern_overrides":{
                "PCI/visa.v3":{"regex":"\\b4\\d{15}\\b"},
                "PII/email":{"regex":"[unterminated"},
                "PHI/no_regex":{"specificity":0.5},
                "malformed_key":{"regex":"."}
            }
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let map = o.compile_pattern_regex_overrides();
        // Only the well-formed override with a regex compiles in.
        assert_eq!(map.len(), 1);
        let re = map.get(&("PCI".to_string(), "visa.v3".to_string())).unwrap();
        assert!(re.is_match("4111111111111111"));
        assert!(!re.is_match("411111111"));
    }

    #[test]
    fn match_list_parses_and_summarises() {
        let json = r#"{
            "version":0,
            "lists":[
                {"id":"ml_partners","name":"Partner domains","kind":"domain",
                 "entries":["acme.com","globex.eu"]},
                {"id":"ml_leaked","name":"Known leaked hashes","kind":"hash",
                 "description":"IR triage",
                 "entries":["5d41402abc4b2a76b9719d911017c592"]},
                {"id":"ml_kws","name":"Weaponised phrases","kind":"keyword",
                 "entries":["project icarus","shell access"]}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(o.lists.len(), 3);
        assert_eq!(o.lists[0].kind, ListKind::Domain);
        assert_eq!(o.lists[1].kind, ListKind::Hash);
        assert_eq!(o.lists[2].entries.len(), 2);
        let s = o.summary();
        assert_eq!(s.lists, 3);
        assert_eq!(s.list_entries, 5);
    }

    #[test]
    fn match_list_kind_round_trips_unknown_as_other_fails() {
        // Unknown kind should fail hard — no silent downgrade to Other.
        let json = r#"{
            "version":0,
            "lists":[{"id":"x","name":"x","kind":"not-a-real-kind","entries":[]}]
        }"#;
        let err = PatternOverrides::from_bytes(json.as_bytes()).unwrap_err();
        assert!(matches!(err, LoadError::Parse(_)));
    }

    #[test]
    fn compiled_list_keyword_substring_case_insensitive() {
        let list = MatchList {
            id: "x".into(), kind: ListKind::Keyword,
            entries: vec!["Project Icarus".into(), "shell access".into()],
            ..Default::default()
        };
        let c = CompiledList::from_list(&list);
        assert!(c.matches("See PROJECT ICARUS doc"));
        assert!(c.matches("requested shell access yesterday"));
        assert!(!c.matches("no keyword here"));
    }

    #[test]
    fn compiled_list_domain_suffix_match() {
        let list = MatchList {
            id: "p".into(), kind: ListKind::Domain,
            entries: vec!["example.com".into(), "globex.eu".into()],
            ..Default::default()
        };
        let c = CompiledList::from_list(&list);
        assert!(c.matches("example.com"));
        assert!(c.matches("Foo.Example.COM"));          // case-insensitive
        assert!(c.matches("mail.globex.eu"));            // subdomain
        assert!(c.matches("alice@example.com"));         // email at domain
        assert!(c.matches("Alice@mail.example.com"));    // email at subdomain
        assert!(!c.matches("notexample.com"));            // no false suffix
        assert!(!c.matches("test@nope.com"));             // wrong domain
    }

    #[test]
    fn compiled_list_email_with_domain_fallback() {
        let list = MatchList {
            id: "e".into(), kind: ListKind::Email,
            entries: vec!["alice@corp.com".into(), "@partner.io".into()],
            ..Default::default()
        };
        let c = CompiledList::from_list(&list);
        assert!(c.matches("alice@corp.com"));
        assert!(c.matches("ALICE@CORP.com"));
        assert!(c.matches("anyone@partner.io"));         // domain fallback
        assert!(!c.matches("alice@other.com"));
    }

    #[test]
    fn compiled_list_hash_exact_lowercased() {
        let list = MatchList {
            id: "h".into(), kind: ListKind::Hash,
            entries: vec!["5d41402ABC4b2a76B9719D911017c592".into()],
            ..Default::default()
        };
        let c = CompiledList::from_list(&list);
        assert!(c.matches("5d41402abc4b2a76b9719d911017c592"));  // upper/lower round-trip
        assert!(!c.matches("deadbeef"));
    }

    #[test]
    fn compile_lists_round_trips_through_overrides() {
        let json = r#"{
            "version":0,
            "lists":[
                {"id":"ml_p","name":"Partners","kind":"domain","entries":["acme.com"]},
                {"id":"","name":"Skip empty-id","kind":"keyword","entries":["x"]}
            ]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let map = o.compile_lists();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ml_p"));
        assert!(map.get("ml_p").unwrap().matches("node.acme.com"));
    }

    #[test]
    fn match_list_default_kind_is_keyword() {
        // Missing `kind` should default to Keyword via serde(default).
        let json = r#"{
            "version":0,
            "lists":[{"id":"x","name":"x","entries":["hi"]}]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(o.lists[0].kind, ListKind::Keyword);
    }

    #[test]
    fn compile_runtime_patterns_skips_bad_regex_keeps_good() {
        let json = r#"{
            "version":0,
            "custom_categories":[{
                "name":"MYORG",
                "group":"SECRET",
                "patterns":[
                    {"sub_category":"emp.id","regex":"\\bEMP-\\d{4,}\\b","specificity":0.7,"case_insensitive":true},
                    {"sub_category":"bad","regex":"[unterminated"},
                    {"sub_category":"empty_skipped","regex":""}
                ]
            }]
        }"#;
        let o = PatternOverrides::from_bytes(json.as_bytes()).unwrap();
        let runtime = o.compile_runtime_patterns();
        assert_eq!(runtime.len(), 1);
        assert_eq!(runtime[0].category, "MYORG");
        assert_eq!(runtime[0].sub_category, "emp.id");
        assert!(runtime[0].regex.is_match("EMP-12345"));
        // case_insensitive baked into the compiled regex
        assert!(runtime[0].regex.is_match("emp-12345"));
    }
}
