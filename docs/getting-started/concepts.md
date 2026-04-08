# Core Concepts

This guide explains dlpscan's key concepts, how they work together, and
how to tune them for your use case.

---

## The Detection Pipeline

Every piece of text passes through this pipeline:

```
Input text
  |
  +-- 1. Normalization (strip evasion attempts)
  |     +-- Zero-width character removal
  |     +-- Unicode space normalization
  |     +-- Homoglyph substitution (Cyrillic/Greek -> ASCII)
  |     +-- Leet-speak decoding
  |     +-- NFKC normalization
  |
  +-- 2. Context keyword scan (Aho-Corasick, single O(n) pass)
  |     +-- Builds a map of which categories have keywords nearby
  |
  +-- 3. Pattern matching (parallel regex, Rayon)
  |     +-- 107 always-run patterns (high specificity)
  |     +-- 453 context-gated patterns (only if keywords present)
  |     +-- Structural validation (Luhn, SWIFT, CUSIP, SEDOL, TFN, SSN)
  |
  +-- 4. Confidence scoring
  |     +-- Base score from pattern specificity
  |     +-- +0.20 boost if context keyword found nearby
  |     +-- Context-required patterns suppressed without keywords
  |
  +-- 5. Action
        +-- Flag, Redact, Reject, Tokenize, or Obfuscate
```

---

## Patterns

A **pattern** is a regex that matches a specific type of sensitive data.
dlpscan ships with **560 patterns** across **126 categories**.

Each pattern has:

| Property | Description | Example |
|---|---|---|
| **category** | Top-level grouping | "Credit Card Numbers" |
| **sub_category** | Specific pattern name | "Visa" |
| **regex** | The detection regex | `\b4[0-9]{12}(?:[0-9]{3})?\b` |
| **specificity** | Base confidence score (0.0-1.0) | 0.90 |
| **context_required** | Whether keywords are mandatory | false |

Full reference: [docs/PATTERNS.md](../PATTERNS.md)

---

## Specificity

**Specificity** is a number from 0.0 to 1.0 that indicates how likely a
regex match is to be a true positive, based purely on the pattern's
structure.

| Range | Meaning | Examples |
|---|---|---|
| **0.85-1.0** | Very high confidence — the regex is distinctive enough to be reliable without context | JWT tokens (`eyJ...`), AWS keys (`AKIA...`), credit cards (Luhn-validated), Track 1/2 data |
| **0.50-0.84** | Moderate confidence — context keywords help a lot | IBAN, SWIFT/BIC, email, phone numbers, crypto addresses |
| **0.20-0.49** | Low confidence — many false positives without context | Bank account numbers, dates, check numbers |
| **0.00-0.19** | Very low — almost always requires context | Cardholder name patterns, OFAC SDN entries |

### How specificity affects scanning

Patterns with specificity >= 0.85 (or in the critical set) are
**always-run** — they execute on every scan regardless of context
keywords. This ensures high-value detections like credit cards and
API keys are never missed.

Patterns with specificity < 0.85 are **context-gated** — they only
run if the Aho-Corasick keyword scan found relevant keywords nearby.
This eliminates ~80% of regex work on typical text.

### Tuning specificity

You don't directly set specificity — it's built into each pattern's
definition. What you control is the **minimum confidence threshold**:

```toml
# .dlpscanrc
min_confidence = 0.5   # Ignore findings below 50% confidence
```

```bash
dlpscan scan-text "some text" --min-confidence 0.5
```

**Recommended settings:**
- **Production (low false positives):** `min_confidence = 0.5`
- **Audit/discovery (find everything):** `min_confidence = 0.0`
- **High-security (critical only):** `min_confidence = 0.8`

---

## Context Keywords

**Context keywords** are terms that appear near a regex match and boost
confidence that the match is a true positive.

For example, the text `"card number: 4532015112830366"` has the keyword
`"card number"` near the Visa regex match. This boosts confidence by
+0.20 (from 0.90 to 1.0).

Each pattern has a set of associated keywords and a **distance**
(in characters) within which the keyword must appear.

| Pattern | Keywords | Distance |
|---|---|---|
| Visa | `visa`, `credit card`, `card number`, `pan` | 50 chars |
| USA SSN | `social security`, `ssn` | 50 chars |
| IBAN | `iban`, `international bank account` | 50 chars |

Full reference: [docs/KEYWORDS.md](../KEYWORDS.md)

### Context-required patterns

Some patterns are so broad (e.g., 8-digit numbers that could be an
Australia TFN or a random ID) that they are **context-required** — they
are completely suppressed unless a keyword appears nearby.

Context-required patterns: Account Balance, CUSIP, SEDOL, Ticker Symbol,
Teller ID, Australia TFN, US Bank Account Number, Check Number, Card
Expiry, Date of Birth, Gender Marker, and others.

---

## Structural Validators

After a regex match, dlpscan runs **structural validation** to eliminate
false positives. These are post-match checks that verify the matched
text has the correct internal structure.

| Pattern | Validation | What it catches |
|---|---|---|
| Credit Cards | Luhn checksum (mod 10) | Random 16-digit numbers |
| SSN | Area code not 000/666/900+, group/serial not all-zero | Invalid SSN prefixes |
| SWIFT/BIC | ISO 3166 country code at positions 5-6, 400-word English word filter | DECEMBER, SECURITY, PLATFORM |
| CUSIP | Modified Luhn check digit (alphanumeric) | Random 9-character strings |
| SEDOL | Weighted checksum (mod 10) | Random 7-character strings |
| Australia TFN | Weighted checksum (mod 11) | Random 8-9 digit numbers |

Adding a new validator is a one-line addition to `validation::validate_match()`.

---

## Presets

**Presets** are pre-configured bundles of categories for common use cases.

| Preset | What it covers |
|---|---|
| `pci-dss` | Credit card numbers, PANs, track data, card expiry, banking data |
| `ssn-sin` | US Social Security Numbers, Canadian Social Insurance Numbers |
| `pii` | Personal identifiers, geolocation, device IDs, biometrics |
| `pii-strict` | PII + regional identifiers (US DL, UK, Germany, France, etc.) |
| `credentials` | API keys, tokens, secrets, database connection strings |
| `financial` | All financial categories (banking, securities, wire transfers) |
| `healthcare` | Medical identifiers, insurance codes, ICD-10, NDC |
| `contact-info` | Email, phone, IP address, MAC address |

Use presets in the CLI:

```bash
dlpscan guard "text" --presets pci-dss,credentials
```

Or in Rust:

```rust
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Credentials])
    .with_action(Action::Redact);
```

---

## Actions

An **action** determines what happens when sensitive data is found.

| Action | Behavior | Use case |
|---|---|---|
| **Flag** | Return findings without modifying text | Audit, monitoring, discovery |
| **Redact** | Replace sensitive data with redaction characters (e.g., `XXXX`) | Logging, display |
| **Reject** | Return an error when sensitive data is found | Input validation, API gates |
| **Tokenize** | Replace with reversible tokens (e.g., `TOK_CC_a8f3b2c1`) | Data processing where originals are needed later |
| **Obfuscate** | Replace with realistic fake data (Luhn-valid CCs, etc.) | Test data generation, demos |

---

## File Type Controls

The pipeline can block or skip files by extension.

### Blocked extensions (default on)

Cryptographic material is blocked by default to prevent extraction of
binary key/certificate data:

```
.der .p12 .pfx .p7b .p7c .p7m .p7s .p8 .ppk
.jks .keystore .bks .gpg .pgp .asc .sst .stl .spc .pvk
```

Text-based key files (`.pem`, `.key`, `.crt`) are NOT blocked because
the scanner's "Private Key" pattern detects `-----BEGIN.*PRIVATE KEY-----`
in them.

### Block unreadable (opt-in)

Set `block_unreadable: true` to also block executables, compiled objects,
encrypted containers, and media files.

### Double-extension protection

`secret.der.txt` is correctly blocked because ALL dot-separated segments
are checked, not just the last extension.

### Symlink resolution

Paths are canonicalized before the extension check, preventing bypass
via `safe.txt` -> `secret.der` symlinks.

---

## Confidence Scoring

The final **confidence score** for a finding is computed as:

```
if has_context_keyword_nearby:
    confidence = min(specificity + 0.20, 1.0)
elif context_required:
    confidence = specificity * 0.30    # heavily penalized
else:
    confidence = specificity
```

Examples:
- Visa (0.90) + context keyword "credit card" nearby = **1.0**
- Visa (0.90) without context = **0.90**
- Check Number (0.15) without context (required) = **0.045** (suppressed by any min_confidence threshold)

---

## Baseline Mode

**Baseline mode** restricts scanning to only the 107 always-run patterns,
skipping all 453 context-gated patterns. This is faster but may miss
low-specificity detections.

```rust
let guard = InputGuard::new()
    .with_baseline_only(true);
```

Best for: high-throughput pipelines, pre-screening before a full scan,
latency-sensitive applications.

---

## Allowlists

**Allowlists** suppress known false positives by exact text match,
sub-category pattern, or file path glob.

```yaml
allowlist:
  - "4111111111111111"     # Test credit card
  - "test@example.com"    # Test email
ignore_patterns:
  - "TEST-\\d+"           # Internal test IDs
ignore_paths:
  - "tests/"              # Test fixtures
  - "*.test.js"           # Test files
```
