# Personal Health Information (PHI) and Health Data Control

Detects protected health information (PHI) and related health data subject
to HIPAA, HITECH, and international health privacy regulations. Covers
medical identifiers, health plan information, biometric data, and
individual identifiers when associated with health context.

## Control Objective

Prevent the unauthorized use or disclosure of individually identifiable
health information as defined by the HIPAA Privacy Rule (45 CFR 164.501),
including any information that relates to the health condition, provision
of healthcare, or payment for healthcare of an individual.

---

## Pattern & Keyword Reference

| Resource | Description |
|----------|-------------|
| [phi-patterns.md](phi-patterns.md) | All regex patterns for PHI detection |
| [phi-keywords.md](phi-keywords.md) | Keyword proximity lists for each pattern |

---

## HIPAA 18 Identifier Coverage

| # | HIPAA Identifier | dlpscan Pattern | Regex |
|---|-----------------|-----------------|-------|
| 1 | Names | Cardholder Name Pattern (shared) | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` |
| 2 | Geographic data (smaller than state) | GPS Coordinates, ZIP Code | See [phi-patterns.md](phi-patterns.md#geographic-data-hipaa-2) |
| 3 | Dates (except year) | Date of Birth, Date ISO/US/EU | See [phi-patterns.md](phi-patterns.md#date-formats-hipaa-3) |
| 4 | Phone numbers | E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| 5 | Fax numbers | E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| 6 | Email addresses | Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| 7 | Social Security numbers | SSN (regional) | `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| 8 | Medical record numbers | Medical Record Number | `\b\d{6,10}\b` |
| 9 | Health plan beneficiary numbers | Insurance Policy Number, MBI | See [phi-patterns.md](phi-patterns.md#insurance--health-plan-data) |
| 10 | Account numbers | Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |
| 11 | Certificate/license numbers | DEA Number, NPI | `\b[A-Z]{2}\d{7}\b`, `\b[12]\d{9}\b` |
| 12 | Vehicle identifiers | VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` |
| 13 | Device identifiers | IMEI, ICCID | See [phi-patterns.md](phi-patterns.md#device-identifiers-hipaa-13--medical-devices) |
| 14 | Web URLs | URL with Credentials | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| 15 | IP addresses | IPv4, IPv6 | See [phi-patterns.md](phi-patterns.md#contact-information-phi-context) |
| 16 | Biometric identifiers | Biometric Hash, Template ID | See [phi-patterns.md](phi-patterns.md#biometric-identifiers-hipaa-16) |
| 17 | Full-face photographs | *(image OCR scanning)* | -- |
| 18 | Any other unique identifying number | ICD-10, NDC codes | See [phi-patterns.md](phi-patterns.md#medical-identifiers) |
