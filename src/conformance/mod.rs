//! Conformance matrix — a runnable inventory of what Siphon claims to do.
//!
//! This is a library, not a test file, because the same matrix has three
//! callers: `cargo test --features conformance` in CI, the
//! `siphon-conformance` binary a developer runs against a working tree, and
//! `scripts/conformance.sh`, which does both and prints a coverage report.
//! Keeping the cases in `tests/` would have meant one of those three
//! reimplementing them.
//!
//! # The five questions
//!
//! Siphon advertises around two dozen file formats and 583 detection
//! patterns. The interesting failures are never "we cannot open a DOCX" —
//! they are the quiet ones: a format whose *second* sheet is never read, an
//! archive entry that is listed but not scanned, a corrupt file that comes
//! back `Ok("")` and therefore clean. Those do not look like bugs from
//! inside a single happy-path test, so the matrix asks the same five
//! questions of every capability:
//!
//! | Slot | Question |
//! |---|---|
//! | [`Slot::Clean`]      | Well-formed, nothing sensitive: does it read, and stay quiet? |
//! | [`Slot::Single`]     | One planted value in the obvious place: is it found? |
//! | [`Slot::Structural`] | One planted value where the format lets you hide it — a second sheet, a later archive entry, an attachment: is it found? |
//! | [`Slot::Damaged`]    | Truncated or corrupt: does the reader *say so* rather than report a faithful clean read? |
//! | [`Slot::Evasive`]    | A format-specific bypass — encoded body, nested container, split value: is it still found? |
//!
//! Slot 4 is the one that earns its keep. An extractor that returns `Ok("")`
//! for a file it could not parse makes the scanner report "clean" for content
//! nobody read, and every caller downstream — the CLI's exit code, siphon-fs's
//! response, the milter's verdict — inherits that. So [`Expect::NotSilentlyClean`]
//! asserts the *absence of a false clean*, not the presence of a finding.
//!
//! # Fixtures are built, not committed
//!
//! Every fixture is constructed in-process into a tempdir. No binary blobs
//! are checked in. A committed `.xlsx` is a file nobody can review in a diff
//! and one that rots quietly when whatever produced it is forgotten. A
//! builder is readable, and it can be parameterised — which is what makes
//! five slots per format affordable.
//!
//! # Coverage is enforced, gaps are named
//!
//! [`formats::KNOWN_GAPS`] carries a reason string per uncovered format, and
//! the coverage check fails on anything advertised by
//! [`crate::extractors::supported_extensions`] that is neither covered nor
//! listed as a gap. A format added to the dispatch without cases is a format
//! nobody has five questions about.

pub mod build;
pub mod formats;

use crate::scanner::{scan_text_with_config, ScanConfig};

// ---------------------------------------------------------------------------
// Planted values
//
// Reused across capabilities on purpose: when a format-specific case fails,
// the value is never the variable. These are the same synthetic values the
// labeled corpus in tests/corpus/ uses, checksum-valid where the pattern has
// a validator, and none of them issued.
// ---------------------------------------------------------------------------

/// Passes Luhn. The canonical Visa test number.
pub const CARD: &str = "4111111111111111";
/// Valid SSN area/group/serial; never issued.
pub const SSN: &str = "219-09-9999";
/// Shape-valid AWS access key id, from AWS's own documentation.
pub const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
/// Passes the IBAN mod-97 check.
pub const IBAN: &str = "DE89370400440532013000";

/// Prose with nothing sensitive in it, long enough that a format's own
/// boilerplate is not the only thing being scanned.
pub const INNOCUOUS: &str = "Quarterly planning notes. The team agreed to move the \
                             retrospective to Thursday and to close the remaining \
                             documentation tasks before the end of the sprint. No \
                             customer data is referenced in this document.";

// ---------------------------------------------------------------------------
// Case model
// ---------------------------------------------------------------------------

/// The five questions asked of every capability. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    Clean,
    Single,
    Structural,
    Damaged,
    Evasive,
}

impl Slot {
    pub const ALL: [Slot; 5] = [
        Slot::Clean,
        Slot::Single,
        Slot::Structural,
        Slot::Damaged,
        Slot::Evasive,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Slot::Clean => "clean",
            Slot::Single => "single",
            Slot::Structural => "structural",
            Slot::Damaged => "damaged",
            Slot::Evasive => "evasive",
        }
    }
}

/// What a case asserts.
pub enum Expect {
    /// Extraction is faithful *and* the scanner finds nothing. Both halves
    /// matter: "no findings" from a file we failed to read is not a clean
    /// result, it is an unread file.
    NoFindings,
    /// Some reported match contains this substring. A substring rather than
    /// an exact span keeps cases robust against normalisation details the
    /// matrix should not be coupled to.
    Detects(&'static str),
    /// The reader must not present this as a faithful, complete read.
    /// Satisfied by an `Err`, by any warning, or by the `unparsed` fallback
    /// format — any signal a fail-closed caller can act on.
    NotSilentlyClean,
    /// Some reported match has this `sub_category`.
    ///
    /// The right assertion whenever normalisation is in play. The scanner
    /// decodes internally but reports the span as it appeared in the source
    /// — base64 text stays base64 in `Match::text`, HTML entities stay
    /// entities — which is correct, because that span is what a redactor has
    /// to overwrite. Asserting on the decoded value there would be asserting
    /// the wrong behaviour.
    DetectsSubCategory(&'static str),
    /// Nothing may be reported except these sub_categories.
    ///
    /// For formats whose envelope inherently carries a detectable value: an
    /// email has From and To headers, so "clean" cannot mean "no findings",
    /// only "nothing beyond the addresses that make it a message".
    NoFindingsExcept(&'static [&'static str]),
}

/// One question about one capability.
pub struct Case {
    /// The capability under test — an extension for formats (`"docx"`), a
    /// sub_category for detections.
    pub capability: &'static str,
    pub slot: Slot,
    /// Filename the fixture is written under; the extension drives dispatch.
    pub filename: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expect,
    /// What this case is actually about, printed on failure. Written as the
    /// sentence you would want to read at 2am when it goes red.
    pub note: &'static str,
    /// Set when this case describes behaviour Siphon does *not* yet have.
    ///
    /// The case still runs and the expectation stays as written — what it
    /// says should happen is what should happen. It simply does not fail the
    /// build, and the reason is printed instead. Two properties make this
    /// better than deleting the case or weakening its expectation: the gap
    /// stays visible on every run rather than living in an issue tracker, and
    /// if someone fixes it, the tool reports the case as unexpectedly
    /// passing so the entry gets removed rather than quietly outliving the
    /// bug.
    pub known_gap: Option<&'static str>,
}

/// Build a case. A free function rather than a builder because a matrix of
/// 130 entries is read far more often than it is written, and positional
/// arguments keep each entry to a screenful.
pub fn case(
    capability: &'static str,
    slot: Slot,
    filename: &'static str,
    bytes: impl Into<Vec<u8>>,
    expect: Expect,
    note: &'static str,
) -> Case {
    Case {
        capability,
        slot,
        filename,
        bytes: bytes.into(),
        expect,
        note,
        known_gap: None,
    }
}

/// A case describing behaviour Siphon does not yet have. See
/// [`Case::known_gap`].
pub fn gap(mut c: Case, why: &'static str) -> Case {
    c.known_gap = Some(why);
    c
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// The outcome of a single case.
pub struct CaseResult {
    pub capability: &'static str,
    pub slot: Slot,
    /// `None` on pass; the failure explanation otherwise.
    pub failure: Option<String>,
    /// The [`Case::known_gap`] reason, carried through so a report can
    /// separate "this broke" from "this is the gap we already knew about".
    pub known_gap: Option<&'static str>,
    pub note: &'static str,
}

impl CaseResult {
    /// The expectation held.
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }

    /// A failure that is not news: a documented gap, behaving as documented.
    pub fn expected_failure(&self) -> bool {
        self.failure.is_some() && self.known_gap.is_some()
    }

    /// A documented gap that has started passing — the entry should be
    /// removed, and saying so is how the list stays honest.
    pub fn fixed_gap(&self) -> bool {
        self.failure.is_none() && self.known_gap.is_some()
    }

    /// Whether this result should fail the run.
    pub fn is_failure(&self) -> bool {
        self.failure.is_some() && self.known_gap.is_none()
    }
}

/// Run one case. Returns `Err(reason)` rather than panicking so a
/// capability's five slots all report together instead of stopping at the
/// first.
pub fn run_case(c: &Case) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = dir.path().join(c.filename);
    std::fs::write(&path, &c.bytes).map_err(|e| e.to_string())?;
    let path = path.to_string_lossy().to_string();

    let extracted = crate::extractors::extract_text(&path);

    match &c.expect {
        Expect::NotSilentlyClean => match &extracted {
            Err(_) => Ok(()),
            Ok(r) if !r.warnings.is_empty() => Ok(()),
            Ok(r) if r.format == "unparsed" => Ok(()),
            Ok(r) => Err(format!(
                "{}\n  a damaged file read as faithfully parsed \
                 (format={}, {} chars of text, no warnings)\n  \
                 a caller that fails closed has nothing to act on",
                c.note,
                r.format,
                r.text.len()
            )),
        },
        Expect::NoFindings => {
            let r = extracted.map_err(|e| format!("{}\n  extraction failed: {e}", c.note))?;
            if !r.warnings.is_empty() {
                return Err(format!(
                    "{}\n  a well-formed file produced warnings: {:?}",
                    c.note, r.warnings
                ));
            }
            let matches = scan(&r.text)?;
            if matches.is_empty() {
                return Ok(());
            }
            let found: Vec<String> = matches
                .iter()
                .map(|m| format!("{}={}", m.sub_category, m.redacted_text()))
                .collect();
            Err(format!(
                "{}\n  a document with nothing sensitive in it produced {} finding(s): {}",
                c.note,
                found.len(),
                found.join(", ")
            ))
        }
        Expect::NoFindingsExcept(allowed) => {
            let r = extracted.map_err(|e| format!("{}\n  extraction failed: {e}", c.note))?;
            if !r.warnings.is_empty() {
                return Err(format!(
                    "{}\n  a well-formed file produced warnings: {:?}",
                    c.note, r.warnings
                ));
            }
            let matches = scan(&r.text)?;
            let unexpected: Vec<String> = matches
                .iter()
                .filter(|m| !allowed.contains(&m.sub_category.as_str()))
                .map(|m| format!("{}={}", m.sub_category, m.redacted_text()))
                .collect();
            if unexpected.is_empty() {
                return Ok(());
            }
            Err(format!(
                "{}\n  expected nothing beyond {:?}, also got: {}",
                c.note,
                allowed,
                unexpected.join(", ")
            ))
        }
        Expect::DetectsSubCategory(sub) => {
            let r = extracted.map_err(|e| format!("{}\n  extraction failed: {e}", c.note))?;
            let matches = scan(&r.text)?;
            if matches.iter().any(|m| m.sub_category == *sub) {
                return Ok(());
            }
            let found: Vec<String> = matches
                .iter()
                .map(|m| format!("{}={}", m.sub_category, m.redacted_text()))
                .collect();
            Err(format!(
                "{}\n  no {sub} was reported\n  extractor: {} ({} chars)\n  \
                 findings: {}\n  text begins: {:?}",
                c.note,
                r.format,
                r.text.len(),
                if found.is_empty() {
                    "none".to_string()
                } else {
                    found.join(", ")
                },
                r.text.chars().take(180).collect::<String>(),
            ))
        }
        Expect::Detects(needle) => {
            let r = extracted.map_err(|e| format!("{}\n  extraction failed: {e}", c.note))?;
            let matches = scan(&r.text)?;
            if matches.iter().any(|m| m.text.contains(needle)) {
                return Ok(());
            }
            let found: Vec<String> = matches
                .iter()
                .map(|m| format!("{}={}", m.sub_category, m.redacted_text()))
                .collect();
            Err(format!(
                "{}\n  planted value was not reported\n  extractor: {} ({} chars)\n  \
                 findings: {}\n  text begins: {:?}",
                c.note,
                r.format,
                r.text.len(),
                if found.is_empty() {
                    "none".to_string()
                } else {
                    found.join(", ")
                },
                r.text.chars().take(180).collect::<String>(),
            ))
        }
    }
}

fn scan(text: &str) -> Result<Vec<crate::models::Match>, String> {
    if text.is_empty() {
        // The scanner rejects empty input. An extractor that faithfully read
        // a file containing no text has found nothing, which is not an error.
        return Ok(Vec::new());
    }
    scan_text_with_config(text, &ScanConfig::default()).map_err(|e| format!("scan failed: {e}"))
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// The result of a whole run, plus the coverage picture around it.
pub struct Report {
    pub results: Vec<CaseResult>,
    /// Capabilities advertised but not covered, with the reason each is not.
    pub gaps: Vec<(&'static str, &'static str)>,
    /// Capabilities advertised, covered by neither a case nor a gap entry.
    /// Any entry here is a coverage failure, not a note.
    pub uncovered: Vec<String>,
}

impl Report {
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed()).count()
    }

    /// Failures that are not documented gaps — the ones that fail a run.
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| r.is_failure()).count()
    }

    /// Documented gaps behaving as documented.
    pub fn expected_failures(&self) -> Vec<&CaseResult> {
        self.results
            .iter()
            .filter(|r| r.expected_failure())
            .collect()
    }

    /// Documented gaps that have started passing.
    pub fn fixed_gaps(&self) -> Vec<&CaseResult> {
        self.results.iter().filter(|r| r.fixed_gap()).collect()
    }

    /// True when nothing failed unexpectedly and nothing advertised is
    /// unaccounted for. A documented gap does not fail a run; a gap that has
    /// been fixed does not either, it just gets reported so the entry can go.
    pub fn ok(&self) -> bool {
        self.failed() == 0 && self.uncovered.is_empty()
    }

    /// Capabilities in run order, each with its pass/total counts.
    pub fn by_capability(&self) -> Vec<(&'static str, usize, usize)> {
        let mut out: Vec<(&'static str, usize, usize)> = Vec::new();
        for r in &self.results {
            match out.iter_mut().find(|(c, _, _)| *c == r.capability) {
                Some(entry) => {
                    entry.2 += 1;
                    if r.passed() {
                        entry.1 += 1;
                    }
                }
                None => out.push((r.capability, usize::from(r.passed()), 1)),
            }
        }
        out
    }

    /// Machine-readable form, for CI to archive or diff between runs.
    ///
    /// Hand-rolled rather than pulling serde into the shipped library for one
    /// struct. The shape is flat and the strings are the only thing needing
    /// escaping.
    pub fn to_json(&self) -> String {
        fn esc(s: &str) -> String {
            let mut out = String::with_capacity(s.len() + 8);
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out
        }

        let cases: Vec<String> = self
            .results
            .iter()
            .map(|r| {
                format!(
                    r#"{{"capability":"{}","slot":"{}","passed":{}{}{}}}"#,
                    esc(r.capability),
                    r.slot.name(),
                    r.passed(),
                    match &r.known_gap {
                        Some(g) => format!(r#","known_gap":"{}""#, esc(g)),
                        None => String::new(),
                    },
                    match &r.failure {
                        Some(f) => format!(r#","failure":"{}""#, esc(f)),
                        None => String::new(),
                    }
                )
            })
            .collect();
        let gaps: Vec<String> = self
            .gaps
            .iter()
            .map(|(c, why)| format!(r#"{{"capability":"{}","reason":"{}"}}"#, esc(c), esc(why)))
            .collect();
        let uncovered: Vec<String> = self
            .uncovered
            .iter()
            .map(|u| format!(r#""{}""#, esc(u)))
            .collect();

        format!(
            r#"{{"total":{},"passed":{},"failed":{},"cases":[{}],"gaps":[{}],"uncovered":[{}]}}"#,
            self.results.len(),
            self.passed(),
            self.failed(),
            cases.join(","),
            gaps.join(","),
            uncovered.join(",")
        )
    }
}

/// Run every case in the matrix, optionally filtered to one capability.
pub fn run_all(only: Option<&str>) -> Report {
    let cases = formats::cases();
    let mut results = Vec::new();

    for c in &cases {
        if let Some(f) = only {
            if c.capability != f {
                continue;
            }
        }
        results.push(CaseResult {
            capability: c.capability,
            slot: c.slot,
            failure: run_case(c).err(),
            known_gap: c.known_gap,
            note: c.note,
        });
    }

    Report {
        results,
        gaps: formats::KNOWN_GAPS.to_vec(),
        uncovered: formats::uncovered(&cases),
    }
}
