# Compliance Reporting

Generate compliance reports with framework-specific pass/fail checks.

## Supported Frameworks

| Framework | Pass Condition |
|-----------|---------------|
| PCI-DSS | No credit card or PAN findings |
| HIPAA | No medical identifier findings |
| SOC2 | No secret or credential findings |
| GDPR | No PII or contact information findings |

## Usage

```python
from dlpscan.compliance import ComplianceReporter
from dlpscan import InputGuard, Preset, Action

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
reporter = ComplianceReporter(title="Q1 2026 DLP Report")

for text in scan_targets:
    result = guard.scan(text)
    reporter.add_scan_result(result, source="batch")

report = reporter.generate()
print(report.compliance_status)
# {"PCI-DSS": False, "HIPAA": True, "SOC2": True, "GDPR": True}
```

## Export Formats

```python
# JSON
json_str = reporter.to_json()

# HTML (standalone with inline CSS)
html = reporter.to_html()
with open("report.html", "w") as f:
    f.write(html)

# Plain text
print(reporter.to_text())
```
