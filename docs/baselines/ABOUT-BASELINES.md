# About Control Baselines

This document explains what the dlpscan control baselines are, the control
objective each one addresses, and how to use them as a neutral reference
when evaluating or testing other Data Loss Prevention (DLP) solutions
against the same controls.

The baselines are deliberately tool-agnostic: they describe **what** must
be detected, **why** it matters, and **under what context** a finding
should be considered reliable. The companion document
[BASELINE-CONFIGURATION-REFERENCE.md](BASELINE-CONFIGURATION-REFERENCE.md)
provides the concrete regex patterns and keyword proximity lists needed
to implement the same baselines in any scanning engine that supports
regular expressions and keyword context matching.

---

## What Is a Baseline?

A **baseline** is a named bundle of detection rules that addresses a
single data-protection control objective. Each baseline groups together:

1. **Regex patterns** — structural matchers for sensitive values
   (SSNs, credit card numbers, API keys, classification labels, etc.)
2. **Context keywords** — nearby terms that must appear within a
   configured character distance of a regex hit to confirm the match
3. **Category groupings** — logical families of patterns
   (e.g., "Credit Card Numbers", "Biometric Identifiers", "Cloud Provider
   Secrets") that can be enabled, disabled, or tuned together
4. **A control objective** — the regulatory or policy reason the
   baseline exists

Baselines are not implementations. They are a **specification** of the
detection coverage required to enforce a control. Any DLP engine — whether
it is dlpscan, a commercial product, a cloud-provider service, or an
in-house scanner — can be measured against a baseline by asking:

- Does the solution detect every pattern in the baseline?
- Does it support keyword proximity at the required distance?
- Can it honor per-category confidence and context thresholds?
- Does it produce findings that map cleanly back to the control?

---

## The Six Baselines

| Baseline | Domain | Primary Regulations |
|----------|--------|---------------------|
| **PII** | Personally Identifiable Information | GDPR, CCPA/CPRA, FERPA, GLBA, PIPEDA, LGPD, POPIA |
| **PCI** | Payment Card Industry Data | PCI-DSS v4 (Req 3, 4, 7, 8) |
| **PHI** | Protected Health Information | HIPAA Privacy Rule, HITECH |
| **Internal Financial** | Non-public financial data | SOX, GLBA, BSA/AML, FINRA, Dodd-Frank, MiFID II |
| **Source Code & Secrets** | Credentials & keys | SOC 2 CC6.1, ISO 27001 A.9, NIST 800-53 IA-5 |
| **Confidential Documents** | Classification labels & privilege markings | Corporate governance, legal privilege |

### PII — Personally Identifiable Information

**Control objective.** Prevent the unauthorized disclosure of personal
identifiers, contact details, biometric data, government-issued IDs, and
any other information that can be linked to a specific individual.

**What it covers.**

- Personal identifiers (date of birth, gender marker)
- Contact information (email, phone, IP, MAC)
- Biometric identifiers (fingerprint/facial template hashes)
- Employment & education identifiers
- Location data (GPS, geohash, postal codes for US/UK/CA/JP/BR)
- Digital identifiers (IMEI, ICCID, IDFA, social handles)
- Vehicle, insurance, property, and legal identifiers
- **130+ regional government IDs** across North America, Europe,
  Asia-Pacific, Latin America, Middle East, and Africa

**How to test.** A candidate solution should detect documents containing
these identifiers when they co-occur with context keywords. Regional IDs
often collide with other numeric formats (e.g., 9-digit sequences), so
keyword proximity is the primary false-positive control.

---

### PCI — Payment Card Industry Data

**Control objective.** Prevent the unauthorized storage, transmission,
or disclosure of cardholder data (CHD) and sensitive authentication data
(SAD) as defined by PCI-DSS.

**What it covers.**

- Credit card numbers (Visa, MasterCard, Amex, Discover, JCB, Diners, UnionPay)
- Primary Account Number (PAN), masked PAN, BIN/IIN
- Cardholder name and expiration date
- Security codes (CVV/CVC, Amex CID, iCVV, Dynamic CVV)
- PVKI, PVV, Service Code, PIN, PIN Block
- Track 1 / Track 2 magstripe data
- Payment HSM keys and encryption keys
- MICR, check numbers, cashier's check numbers
- Stripe live secret & publishable keys

**PCI-DSS requirement mapping.**

| Requirement | Coverage |
|---|---|
| Req 3 — Protect stored account data | Credit cards, PAN, expiry, cardholder name, track data |
| Req 3.3 — Mask PAN when displayed | Masked PAN detection |
| Req 3.4 — Render PAN unreadable | Full PAN in plaintext |
| Req 4 — Encrypt transmission of CHD | All cardholder data patterns |
| Req 7 — Restrict access to CHD | Stripe, HSM, and encryption keys |
| Req 8 — Authenticate access | PIN, PIN Block |

**How to test.** All candidate solutions must enforce the Luhn check on
PANs and should detect both full and masked PANs. Track data is the
highest-severity finding because it represents SAD that must never be
stored post-authorization.

---

### PHI — Protected Health Information

**Control objective.** Prevent the unauthorized use or disclosure of
individually identifiable health information as defined by the HIPAA
Privacy Rule (45 CFR 164.501).

**What it covers.** All 18 HIPAA identifiers plus health-specific data:

| # | HIPAA Identifier | Covered By |
|---|---|---|
| 1 | Names | Person Name pattern |
| 2 | Geographic data < state | GPS, ZIP |
| 3 | Dates except year | DOB, Date ISO/US/EU |
| 4 | Phone numbers | E.164, US phone |
| 5 | Fax numbers | E.164 |
| 6 | Email addresses | Email |
| 7 | SSN | Regional SSN patterns |
| 8 | Medical record numbers | MRN |
| 9 | Health plan beneficiary | Insurance Policy, MBI |
| 10 | Account numbers | Insurance Claim |
| 11 | Certificate/license | DEA, NPI |
| 12 | Vehicle identifiers | VIN |
| 13 | Device identifiers | IMEI, ICCID, Serial |
| 14 | Web URLs with credentials | URL-with-Password |
| 15 | IP addresses | IPv4, IPv6 |
| 16 | Biometric identifiers | Biometric hash, template ID |
| 17 | Full-face photographs | *(image OCR scope)* |
| 18 | Any other unique identifier | ICD-10, NDC |

Plus medical-specific identifiers (ICD-10, NDC, DEA, NPI, MBI) and
government health IDs (UK NHS, Brazil SUS, etc.).

**How to test.** PHI shares many patterns with PII. The distinguishing
factor is **clinical context** — a solution should use proximity to
health-context keywords (patient, diagnosis, prescription, medical
record, etc.) to promote a generic PII match to a PHI finding.

---

### Internal Financial Data

**Control objective.** Prevent the unauthorized disclosure of non-public
financial data including customer account information, wire transfer
details, securities identifiers, regulatory filings, and
market-sensitive information.

**What it covers.**

- Banking & account data (IBAN, SWIFT/BIC, ABA, bank accounts)
- Internal banking references (account refs, teller/branch/customer IDs)
- Customer financial data (balances, income, DTI, credit scores)
- Wire transfer data (Fedwire IMAD, CHIPS UID, ACH traces, SEPA refs)
- Loan & mortgage data (loan numbers, MERS MIN, ULI, LTV)
- Securities identifiers (CUSIP, ISIN, SEDOL, FIGI, LEI, tickers)
- Cryptocurrency addresses (BTC, ETH, LTC, BCH, XMR, XRP)
- Regulatory filings (SAR, CTR, AML case, OFAC SDN, FinCEN, compliance case)
- Financial regulatory labels (MNPI, Inside Info, Market Sensitive)
- Supervisory information (CSI, MRA/MRIA, examination findings)

**How to test.** Many of these patterns (loan numbers, customer IDs,
internal account refs) are generic alphanumerics and will flood a
solution with false positives if keyword proximity is not enforced.
Candidate solutions should support **required keyword context** for
these categories.

---

### Source Code & Secrets

**Control objective.** Prevent the exposure of authentication
credentials, API keys, private keys, access tokens, and connection
strings in code repositories, logs, chat messages, and documents.

**What it covers.**

- Generic secrets (bearer tokens, JWT, private keys, API key assignments,
  password assignments, DB connection strings)
- URLs with embedded credentials or tokens
- Cloud provider secrets (AWS access/secret, Google API keys)
- Code platform secrets (GitHub classic/fine-grained/OAuth, NPM, PyPI)
- Messaging service secrets (Slack bot/user/webhook, SendGrid, Twilio, Mailgun)
- Payment service secrets (Stripe live keys)
- Authentication tokens (session IDs, CSRF, OTP, refresh tokens)
- Banking HSM and encryption keys

**Framework mapping.**

| Framework | Control | Coverage |
|---|---|---|
| SOC 2 | CC6.1 — Logical access | All keys, tokens, credentials |
| ISO 27001 | A.9 — Access control | Private keys, connection strings |
| NIST 800-53 | IA-5 — Authenticator management | All secrets and tokens |
| CIS Controls | 16 — Application security | Embedded credentials |
| OWASP Top 10 | A07 — Auth failures | Hardcoded secrets |

**How to test.** Most provider-prefixed secrets (`ghp_`, `sk_live_`,
`AIza`, `xoxb-`, etc.) are high-confidence matches and do **not** require
keyword context. Generic patterns (session IDs, refresh tokens) are
lower-confidence and should require keyword proximity. A candidate
solution should be able to distinguish between these two classes.

---

### Confidential Documents

**Control objective.** Prevent the unauthorized distribution of documents
bearing confidentiality markings, legal privilege designations, or
supervisory classification labels.

**What it covers.**

- Corporate classification labels (TT_Confidential, TT_MBI, TT_SPI,
  CNB_Confidential/Restricted/Internal/Public, Sensitive-Business,
  Sensitive-Personal)
- Financial regulatory labels (MNPI, Inside Information, Pre-Decisional,
  Draft Not For Circulation, Market Sensitive, Information Barrier,
  Restricted List)
- Supervisory information (Supervisory Controlled/Confidential, CSI,
  Non-Public Supervisory, MRA/MRIA/Matters Requiring Attention)
- Legal privilege markings (Attorney-Client Privilege,
  Privileged and Confidential, Work Product, Litigation Hold)

**Classification tiers.**

| Tier | Example Labels | Typical Handling |
|---|---|---|
| Public | `Public`, `CNB_Public` | No restrictions |
| Internal | `CNB_Internal` | Employees only |
| Confidential | `TT_Confidential`, `Sensitive - Business` | Need-to-know, encrypted |
| Highly Restricted | `TT_MBI`, `TT_SPI`, `CNB_Restricted` | Strict access control, audit |
| Legally Protected | Attorney-Client, Work Product | Legal dept. control only |
| Supervisory | CSI, Supervisory Controlled | Info barriers, regulator-only |

**How to test.** Unlike the other baselines, this one is almost entirely
**label-driven** — the patterns are literal phrases. A candidate solution
should match the exact labels (case-insensitive where noted) and should
not require keyword proximity, since the label itself is the signal.

---

## How to Use These Baselines to Evaluate Another Solution

The workflow for testing any DLP solution against a baseline is:

1. **Pick a baseline** from the six above that matches your control.
2. **Import the patterns** from
   [BASELINE-CONFIGURATION-REFERENCE.md](BASELINE-CONFIGURATION-REFERENCE.md)
   into the candidate tool's rule engine. Every modern DLP tool accepts
   PCRE-style regex; the patterns are portable.
3. **Configure keyword proximity** per category at the distances listed
   in the reference document. If the tool does not support proximity
   matching, document it as a coverage gap.
4. **Set per-category confidence thresholds** using the values in the
   reference document as a starting point.
5. **Run the tool against a labeled corpus.** dlpscan's test fixtures
   under `tests/` and `examples/` can be used as ground truth.
6. **Measure coverage and false-positive rate.**
   - **Coverage** = (patterns detected) / (patterns in baseline)
   - **FP rate** = (non-sensitive matches) / (total matches)
7. **Map findings back to the control objective.** Each finding should
   be attributable to a pattern, a category, and a regulation.

---

## Design Principles

The baselines follow four principles that testers should preserve when
porting them to other tools:

1. **Patterns are shareable across baselines.** Date of Birth, Email,
   and IP address appear in both PII and PHI. A candidate solution
   should allow the same pattern to be registered under multiple
   baselines without duplication.

2. **Context is mandatory for generic patterns.** Any pattern that
   matches a bare numeric string (`\b\d{6,10}\b`, `\b\d{4}\b`, etc.)
   **must** require keyword proximity, or the solution will produce
   unusable signal.

3. **Provider-prefixed secrets are high-confidence.** Patterns that
   include a fixed provider prefix (`ghp_`, `sk_live_`, `AKIA`, etc.)
   do not need keyword context and should be treated as exact matches.

4. **Classification labels are exact-match signals.** Corporate and
   regulatory classification labels should fire independently of any
   other context.

---

## Companion Documents

- [BASELINE-CONFIGURATION-REFERENCE.md](BASELINE-CONFIGURATION-REFERENCE.md)
  — every pattern and keyword list needed to configure these baselines
  in another DLP tool.
- [index.md](index.md) — short index of the per-baseline detail pages.
- [pii.md](pii.md), [pci.md](pci.md), [phi.md](phi.md),
  [internal-financial.md](internal-financial.md),
  [source-code-secrets.md](source-code-secrets.md),
  [confidential-documents.md](confidential-documents.md) — per-baseline
  detail, regulation mapping, and requirement cross-walks.
