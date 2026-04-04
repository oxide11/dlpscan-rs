# Control Baselines

Control baselines group dlpscan's detection patterns and context keywords
by compliance and security control objective. Each baseline maps to a
specific data protection domain and identifies the exact patterns and
keywords required to meet that control.

Use these baselines to:

- **Configure scanning presets** aligned to your compliance requirements
- **Audit coverage** across regulatory frameworks (PCI-DSS, HIPAA, GDPR, SOX)
- **Build policies** that enforce detection for a specific data domain
- **Map findings** back to the control objective that triggered them

## Baselines

| Baseline | Domain | Key Regulations |
|----------|--------|-----------------|
| [PII](pii.md) | Personal Identifiable Information | GDPR, CCPA/CPRA, FERPA, GLBA |
| [PCI](pci.md) | Payment Card Industry Information | PCI-DSS |
| [PHI](phi.md) | Personal Health Information & Health Data | HIPAA, HITECH |
| [Internal Financial Data](internal-financial.md) | Financial Data Monitoring | SOX, GLBA, BSA/AML, FINRA |
| [Source Code & Secrets](source-code-secrets.md) | Source Code and Secrets Control | SOC 2, ISO 27001 |
| [Confidential Documents](confidential-documents.md) | Confidential Documents Policy | Corporate governance, legal privilege |

## How Baselines Map to Patterns

Each baseline document lists:

1. **Patterns** -- the regex detection rules that identify sensitive data
2. **Keywords** -- the context keywords that improve detection accuracy
   by requiring proximity to relevant terms
3. **Regional extensions** -- country-specific patterns that fall within
   the baseline's scope

Patterns and keywords are sourced from the existing reference library
under `docs/patterns/` and `docs/keywords/`. A single pattern may appear
in multiple baselines when it serves multiple control objectives (e.g.,
Date of Birth is relevant to both PII and PHI).
