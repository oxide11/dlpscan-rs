//! Compliance reporting — PCI-DSS, HIPAA, SOC2, GDPR framework checks.
//!
//! Accumulate scan findings, then generate pass/fail reports in JSON, text,
//! or HTML format.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::models::Match;

// ---------------------------------------------------------------------------
// Framework → failing categories
// ---------------------------------------------------------------------------

fn framework_failing_categories() -> HashMap<&'static str, HashSet<&'static str>> {
    let mut m = HashMap::new();
    m.insert(
        "PCI-DSS",
        ["Credit Card Numbers", "Primary Account Numbers"]
            .into_iter()
            .collect(),
    );
    m.insert("HIPAA", ["Medical Identifiers"].into_iter().collect());
    m.insert(
        "SOC2",
        [
            "Generic Secrets",
            "Cloud Provider Secrets",
            "Code Platform Secrets",
        ]
        .into_iter()
        .collect(),
    );
    m.insert(
        "GDPR",
        ["Contact Information", "Personal Identifiers"]
            .into_iter()
            .collect(),
    );
    m
}

// ---------------------------------------------------------------------------
// ComplianceReport
// ---------------------------------------------------------------------------

/// Generated compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub title: String,
    pub generated_at: String,
    pub scan_summary: ScanSummary,
    pub findings: Vec<FindingRow>,
    pub compliance_status: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_scans: usize,
    pub total_findings: usize,
    pub categories_breakdown: BTreeMap<String, usize>,
    pub severity_breakdown: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRow {
    pub category: String,
    pub sub_category: String,
    pub count: usize,
    pub sample_redacted: String,
    pub confidence_avg: f64,
}

// ---------------------------------------------------------------------------
// ComplianceReporter
// ---------------------------------------------------------------------------

/// Accumulates scan findings and generates compliance reports.
pub struct ComplianceReporter {
    title: String,
    inner: Mutex<ReporterInner>,
}

struct ReporterInner {
    matches: Vec<(Match, String)>, // (match, source)
    scan_count: usize,
}

impl ComplianceReporter {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            inner: Mutex::new(ReporterInner {
                matches: Vec::new(),
                scan_count: 0,
            }),
        }
    }

    /// Add findings from a ScanResult.
    pub fn add_scan_result(&self, findings: &[Match], source: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.scan_count += 1;
        for m in findings {
            inner.matches.push((m.clone(), source.to_string()));
        }
    }

    /// Add raw Match objects.
    pub fn add_findings(&self, findings: &[Match], source: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for m in findings {
            inner.matches.push((m.clone(), source.to_string()));
        }
    }

    /// Generate the compliance report.
    pub fn generate(&self) -> ComplianceReport {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let matches = inner.matches.clone();
        let scan_count = inner.scan_count;
        drop(inner);

        // Aggregate
        let mut cat_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut group_data: BTreeMap<(String, String), Vec<&Match>> = BTreeMap::new();
        let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
        severity_counts.insert("high".to_string(), 0);
        severity_counts.insert("medium".to_string(), 0);
        severity_counts.insert("low".to_string(), 0);

        for (m, _source) in &matches {
            *cat_counts.entry(m.category.clone()).or_default() += 1;
            group_data
                .entry((m.category.clone(), m.sub_category.clone()))
                .or_default()
                .push(m);

            if m.confidence >= 0.75 {
                severity_counts.get_mut("high").map(|v| *v += 1);
            } else if m.confidence >= 0.40 {
                severity_counts.get_mut("medium").map(|v| *v += 1);
            } else {
                severity_counts.get_mut("low").map(|v| *v += 1);
            }
        }

        // Finding rows
        let mut findings_rows = Vec::new();
        for ((cat, sub), group) in &group_data {
            let count = group.len();
            let avg_conf: f64 = group.iter().map(|m| m.confidence).sum::<f64>() / count as f64;
            let sample = group
                .first()
                .map(|m| {
                    let text = &m.text;
                    if text.len() > 20 {
                        let truncated: String = text.chars().take(17).collect();
                        format!("{}...", truncated)
                    } else {
                        text.clone()
                    }
                })
                .unwrap_or_default();

            findings_rows.push(FindingRow {
                category: cat.clone(),
                sub_category: sub.clone(),
                count,
                sample_redacted: sample,
                confidence_avg: (avg_conf * 10000.0).round() / 10000.0,
            });
        }

        // Compliance check
        let compliance_status = check_compliance(&cat_counts);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let generated_at = format_epoch(now);

        ComplianceReport {
            title: self.title.clone(),
            generated_at,
            scan_summary: ScanSummary {
                total_scans: scan_count,
                total_findings: matches.len(),
                categories_breakdown: cat_counts,
                severity_breakdown: severity_counts,
            },
            findings: findings_rows,
            compliance_status,
        }
    }

    /// Generate JSON report.
    pub fn to_json(&self, indent: usize) -> String {
        let report = self.generate();
        if indent > 0 {
            serde_json::to_string_pretty(&report).unwrap_or_default()
        } else {
            serde_json::to_string(&report).unwrap_or_default()
        }
    }

    /// Generate plain text report.
    pub fn to_text(&self) -> String {
        let report = self.generate();
        let sep = "=".repeat(72);
        let mut lines = Vec::new();

        lines.push(sep.clone());
        lines.push(format!("  {}", report.title));
        lines.push(format!("  Generated: {}", report.generated_at));
        lines.push(sep.clone());
        lines.push(String::new());

        lines.push("SUMMARY".to_string());
        lines.push("-".repeat(40));
        lines.push(format!(
            "  Total scans: {}",
            report.scan_summary.total_scans
        ));
        lines.push(format!(
            "  Total findings: {}",
            report.scan_summary.total_findings
        ));
        lines.push(String::new());
        lines.push("  Severity:".to_string());
        for (sev, count) in &report.scan_summary.severity_breakdown {
            lines.push(format!("    {}: {}", sev, count));
        }
        lines.push(String::new());
        lines.push("  Categories:".to_string());
        for (cat, count) in &report.scan_summary.categories_breakdown {
            lines.push(format!("    {}: {}", cat, count));
        }
        lines.push(String::new());

        lines.push("COMPLIANCE STATUS".to_string());
        lines.push("-".repeat(40));
        for (framework, pass) in &report.compliance_status {
            let status = if *pass { "PASS" } else { "FAIL" };
            lines.push(format!("  {}: {}", framework, status));
        }
        lines.push(String::new());

        if !report.findings.is_empty() {
            lines.push("FINDINGS DETAIL".to_string());
            lines.push("-".repeat(40));
            for f in &report.findings {
                lines.push(format!(
                    "  {} / {} — count: {}, avg_conf: {:.4}, sample: {}",
                    f.category, f.sub_category, f.count, f.confidence_avg, f.sample_redacted
                ));
            }
        }

        lines.join("\n")
    }

    /// Generate HTML report.
    pub fn to_html(&self) -> String {
        let report = self.generate();
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html><head><meta charset='utf-8'>\n");
        html.push_str(&format!("<title>{}</title>\n", html_escape(&report.title)));
        html.push_str("<style>\n");
        html.push_str("body { font-family: Arial, sans-serif; margin: 2em; }\n");
        html.push_str("h1 { color: #1a1a2e; }\n");
        html.push_str("table { border-collapse: collapse; width: 100%; margin: 1em 0; }\n");
        html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.push_str("th { background-color: #16213e; color: white; }\n");
        html.push_str("tr:nth-child(even) { background-color: #f2f2f2; }\n");
        html.push_str(".pass { color: #27ae60; font-weight: bold; }\n");
        html.push_str(".fail { color: #c0392b; font-weight: bold; }\n");
        html.push_str("</style></head><body>\n");

        html.push_str(&format!("<h1>{}</h1>\n", html_escape(&report.title)));
        html.push_str(&format!(
            "<p>Generated: {}</p>\n",
            html_escape(&report.generated_at)
        ));

        // Summary table
        html.push_str("<h2>Summary</h2>\n<table>\n");
        html.push_str(&format!(
            "<tr><td>Total Scans</td><td>{}</td></tr>\n",
            report.scan_summary.total_scans
        ));
        html.push_str(&format!(
            "<tr><td>Total Findings</td><td>{}</td></tr>\n",
            report.scan_summary.total_findings
        ));
        for (sev, count) in &report.scan_summary.severity_breakdown {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                html_escape(sev),
                count
            ));
        }
        html.push_str("</table>\n");

        // Compliance status
        html.push_str("<h2>Compliance Status</h2>\n<table>\n");
        html.push_str("<tr><th>Framework</th><th>Status</th></tr>\n");
        for (framework, pass) in &report.compliance_status {
            let (class, label) = if *pass {
                ("pass", "PASS")
            } else {
                ("fail", "FAIL")
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class='{}'>{}</td></tr>\n",
                html_escape(framework),
                class,
                label
            ));
        }
        html.push_str("</table>\n");

        // Findings detail
        if !report.findings.is_empty() {
            html.push_str("<h2>Findings Detail</h2>\n<table>\n");
            html.push_str("<tr><th>Category</th><th>Sub-Category</th><th>Count</th><th>Avg Confidence</th><th>Sample</th></tr>\n");
            for f in &report.findings {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.4}</td><td>{}</td></tr>\n",
                    html_escape(&f.category),
                    html_escape(&f.sub_category),
                    f.count,
                    f.confidence_avg,
                    html_escape(&f.sample_redacted)
                ));
            }
            html.push_str("</table>\n");
        }

        html.push_str("</body></html>");
        html
    }
}

impl Default for ComplianceReporter {
    fn default() -> Self {
        Self::new("DLP Compliance Report")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_compliance(cat_counts: &BTreeMap<String, usize>) -> BTreeMap<String, bool> {
    let frameworks = framework_failing_categories();
    let mut status = BTreeMap::new();

    let mut sorted_frameworks: Vec<_> = frameworks.into_iter().collect();
    sorted_frameworks.sort_by_key(|(k, _)| k.to_string());

    for (framework, failing_cats) in sorted_frameworks {
        let passes = failing_cats
            .iter()
            .all(|cat| cat_counts.get(*cat).copied().unwrap_or(0) == 0);
        status.insert(framework.to_string(), passes);
    }
    status
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn format_epoch(epoch: u64) -> String {
    // Simple UTC ISO 8601 formatter
    let secs_per_day = 86400u64;
    let days = epoch / secs_per_day;
    let time_of_day = epoch % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md as i64 {
            m = i;
            break;
        }
        remaining_days -= md as i64;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining_days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(category: &str, sub_category: &str, confidence: f64) -> Match {
        Match {
            text: "test-data-here".to_string(),
            category: category.to_string(),
            sub_category: sub_category.to_string(),
            has_context: false,
            confidence,
            span: (0, 14),
            context_required: false,
        }
    }

    #[test]
    fn test_compliance_all_pass() {
        let reporter = ComplianceReporter::new("Test Report");
        let report = reporter.generate();
        for (_framework, pass) in &report.compliance_status {
            assert!(pass);
        }
    }

    #[test]
    fn test_compliance_pci_fail() {
        let reporter = ComplianceReporter::new("Test");
        let findings = vec![make_match("Credit Card Numbers", "visa", 0.9)];
        reporter.add_scan_result(&findings, "test");
        let report = reporter.generate();
        assert_eq!(report.compliance_status["PCI-DSS"], false);
        assert_eq!(report.compliance_status["HIPAA"], true);
    }

    #[test]
    fn test_severity_breakdown() {
        let reporter = ComplianceReporter::new("Test");
        let findings = vec![
            make_match("test", "a", 0.9),  // high
            make_match("test", "b", 0.5),  // medium
            make_match("test", "c", 0.1),  // low
        ];
        reporter.add_scan_result(&findings, "test");
        let report = reporter.generate();
        assert_eq!(report.scan_summary.severity_breakdown["high"], 1);
        assert_eq!(report.scan_summary.severity_breakdown["medium"], 1);
        assert_eq!(report.scan_summary.severity_breakdown["low"], 1);
    }

    #[test]
    fn test_json_output() {
        let reporter = ComplianceReporter::new("Test");
        let json = reporter.to_json(2);
        assert!(json.contains("Test"));
        assert!(json.contains("compliance_status"));
    }

    #[test]
    fn test_text_output() {
        let reporter = ComplianceReporter::new("Test Report");
        let text = reporter.to_text();
        assert!(text.contains("Test Report"));
        assert!(text.contains("COMPLIANCE STATUS"));
    }

    #[test]
    fn test_html_output() {
        let reporter = ComplianceReporter::new("Test Report");
        let html = reporter.to_html();
        assert!(html.contains("<html>"));
        assert!(html.contains("Test Report"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_format_epoch() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(format_epoch(1704067200), "2024-01-01T00:00:00Z");
    }
}
