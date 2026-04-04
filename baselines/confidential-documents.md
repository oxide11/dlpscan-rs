# Confidential Documents Policy

Detects classification labels, privilege markings, and sensitivity markers
that indicate a document is confidential, restricted, or subject to special
handling requirements. Covers RBC classification labels, legal privilege
designations, and confidential supervisory information.

## Control Objective

Prevent the unauthorized distribution of documents bearing confidentiality
markings, legal privilege designations, or supervisory classification labels.
Enforce document handling policies by detecting content that has been
explicitly marked as restricted.

---

## Patterns

### RBC Classification

| Category | Source |
|----------|--------|
| TT_Confidential | [rbc_classification](../patterns/generic/rbc_classification.md) |
| TT_MBI | [rbc_classification](../patterns/generic/rbc_classification.md) |
| TT_SPI | [rbc_classification](../patterns/generic/rbc_classification.md) |
| CNB_Confidential | [rbc_classification](../patterns/generic/rbc_classification.md) |
| Sensitive - Business | [rbc_classification](../patterns/generic/rbc_classification.md) |
| Sensitive - Personal | [rbc_classification](../patterns/generic/rbc_classification.md) |
| CNB_Restricted | [rbc_classification](../patterns/generic/rbc_classification.md) |
| CNB_Internal | [rbc_classification](../patterns/generic/rbc_classification.md) |
| CNB_Public | [rbc_classification](../patterns/generic/rbc_classification.md) |
| Public | [rbc_classification](../patterns/generic/rbc_classification.md) |

### Financial Regulatory Labels

| Category | Source |
|----------|--------|
| MNPI | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Inside Information | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Pre-Decisional | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Draft Not for Circulation | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Market Sensitive | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Information Barrier | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Investment Restricted | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| TT_Confidential | `\bTT_Confidential\b` | `confidential`, `classification`, `label`, `sensitive`, `restricted` |
| TT_MBI | `\bTT_MBI\b` | `mbi`, `material business information`, `classification`, `sensitive` |
| TT_SPI | `\bTT_SPI\b` | `spi`, `sensitive personal information`, `classification`, `personal` |
| CNB_Confidential | `\bCNB_Confidential\b` | `confidential`, `cnb`, `classification`, `restricted`, `sensitive` |
| Sensitive - Business | `\b[Ss]ensitive\s*[-–—]\s*[Bb]usiness\b` | `sensitive`, `business`, `classification`, `restricted`, `internal` |
| Sensitive - Personal | `\b[Ss]ensitive\s*[-–—]\s*[Pp]ersonal\b` | `sensitive`, `personal`, `classification`, `pii`, `privacy` |
| CNB_Restricted | `\bCNB_Restricted\b` | `restricted`, `cnb`, `classification`, `limited distribution`, `need to know` |
| CNB_Internal | `\bCNB_Internal\b` | `internal`, `cnb`, `classification`, `employees only`, `not for external` |
| CNB_Public | `\bCNB_Public\b` | `public`, `cnb`, `classification`, `unrestricted` |
| Public | `\b[Pp]ublic\b` | `public`, `unrestricted`, `open`, `classification` |

### Legal Privilege Markings

### Legal Privilege Markings

| Category | Source |
|----------|--------|
| Attorney-Client Privilege | [privileged_information](../patterns/generic/privileged_information.md) |
| Privileged and Confidential | [privileged_information](../patterns/generic/privileged_information.md) |
| Work Product | [privileged_information](../patterns/generic/privileged_information.md) |
| Privileged Information | [privileged_information](../patterns/generic/privileged_information.md) |
| Legal Privilege | [privileged_information](../patterns/generic/privileged_information.md) |
| Litigation Hold | [privileged_information](../patterns/generic/privileged_information.md) |
| Protected by Privilege | [privileged_information](../patterns/generic/privileged_information.md) |

---

### Supervisory Information

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [rbc_classification](../keywords/generic/rbc_classification.md) | 80 chars | TT_Confidential, TT_MBI, TT_SPI, CNB_Confidential, Sensitive - Business, Sensitive - Personal, CNB_Restricted, CNB_Internal, CNB_Public, Public |
| [financial_regulatory_labels](../keywords/generic/financial_regulatory_labels.md) | 80 chars | MNPI, Inside Info, Market Sensitive |
| [supervisory_information](../keywords/generic/supervisory_information.md) | 80 chars | Supervisory, CSI, Examination |
| [privileged_information](../keywords/generic/privileged_information.md) | 100 chars | Attorney-Client, Work Product, Litigation Hold |

---

## Classification Tier Mapping

| Tier | Labels | Typical Handling |
|------|--------|-----------------|
| **Public** | Public, CNB_Public | No restrictions |
| **Internal** | CNB_Internal | Employees only |
| **Confidential** | TT_Confidential, CNB_Confidential, Sensitive - Business, Sensitive - Personal | Need-to-know, encrypted storage |
| **Highly Restricted** | TT_MBI, TT_SPI, CNB_Restricted | Strict access control, audit trail |
| **Legally Protected** | Attorney-Client Privilege, Work Product, Litigation Hold | Legal department control, no external sharing |
| **Supervisory** | CSI, Supervisory Controlled | Information barriers, regulatory compliance |

## Use Cases

- **Email DLP** -- Block outbound emails containing privileged or classified markings
- **File share scanning** -- Flag documents with classification labels in shared drives
- **Chat monitoring** -- Detect confidential document content shared via messaging
- **CI/CD pipeline** -- Prevent classified content from entering code repositories
- **Print monitoring** -- Detect classified content being sent to print queues
