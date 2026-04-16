# Validation Pipeline

> **Entry point:** `src/validation.rs :: validate_match` (line ~2350+)
>
> Every regex match passes through this function before it can become
> a reported finding. If the validator returns `false`, the match is
> silently dropped.

## How validators are wired

`validate_match(category, sub_category, matched_text) -> bool` is a
single `match sub_category { ... }` dispatch. Each arm calls a
dedicated validator function for that pattern. Patterns without a
registered validator hit the `_ => true` fallback and are accepted
unconditionally.

```rust
match sub_category {
    "USA SSN"              => is_valid_ssn(matched_text),
    "Visa" | "MasterCard"  => is_luhn_valid(matched_text),  // via category early-return
    "IBAN Generic"         => is_valid_iban(matched_text),
    "India Aadhaar"        => is_valid_india_aadhaar(matched_text),
    // ... 50+ more
    _ => true,  // no validator — accept
}
```

The category `"Credit Card Numbers"` has a special early-return at the
top of the function (line ~2340): any match in that category goes
through `is_luhn_valid` before the per-sub_category dispatch.

## Validator inventory

As of the Phase 1 close-out, **57 validators** are wired. They fall
into these families:

| Family | Algorithm | Patterns |
|---|---|---|
| **Luhn** | Standard Luhn mod-10 | Visa, MC, Amex, Discover, JCB, Diners Club, UnionPay, PAN, IMEI, Sweden PIN, US NPI, UAE Emirates ID |
| **Weighted mod-11** | Weighted sum mod 11 | SSN (area check), CUSIP, SEDOL, Germany Tax ID (ISO 7064), Japan My Number, South Korea RRN, Argentina CUIL, Denmark CPR (DOB-only), British NHS, Chile RUN/RUT, VIN (ISO 3779) |
| **Mod-97** | ISO 13616 or similar | IBAN Generic, Belgium NRN, France NIR |
| **Dual mod-11** | Two-pass weighted | Brazil CPF, Brazil CNPJ |
| **Verhoeff** | Dihedral D5 group | India Aadhaar |
| **Table-driven** | Lookup table per position | Italy Codice Fiscale (CIN), Spain DNI (letter map), Mexico CURP |
| **Letter-table** | Weighted sum → letter lookup | Singapore NRIC, Singapore FIN, Hong Kong ID |
| **Base58Check** | Double-SHA256 tail | Bitcoin Legacy, Litecoin, Ripple |
| **Polymod** | Polynomial checksum | Bitcoin Bech32 (BIP-173/350), Bitcoin Cash (CashAddr) |
| **Structural filter** | Range/bounds/format check | IPv4 (RFC 1918+), IPv6 (loopback/ULA/multicast), MAC (null/broadcast), GPS (lat/lon bounds), SWIFT (country code + false-positive word list), MICR (control char required) |
| **Plausibility** | Length + entropy + placeholder list | Bearer Token, URL with Token, Slack Webhook, Generic API Key (Shannon entropy ≥ 3.0), Generic Secret Assignment (Shannon entropy ≥ 2.5) |
| **Phone** | Country code + NANP NPA/exchange | E.164 (ITU table), US Phone (NANP), UK Phone (plausibility) |

## Always-run vs context-gated

Every pattern is classified as one of:

### Always-run

The pattern's regex runs on every scan. Either:
- `pattern_specificity >= 0.85` (structurally tight: JWTs, Bitcoin
  Bech32, AWS keys, Private Keys, etc.)
- Listed in `CRITICAL_ALWAYS_RUN` in `src/scanner/mod.rs` (line ~143)
  — the curated set of national IDs, crypto addresses, phones, and
  core PCI/PII patterns

Always-run patterns **must** have a structural validator or a tight
enough regex that false positives are rare. After the Phase 1
precision pass, every pattern in `CRITICAL_ALWAYS_RUN` either:
- Has a checksum validator wired in `validate_match`
- Has a structural filter (IPv4 ranges, GPS bounds, etc.)
- Is structurally tight enough (regex encodes a specific URL prefix,
  restricted alphabet, etc.) that the validator is unnecessary

The one exception is Ethereum Address, which is intentionally
deferred (needs keccak256 for EIP-55).

### Context-gated

The pattern runs only when its keywords are present in the document
(the AC prefilter at stage E filters it out otherwise). Additionally,
even if the regex matches, the match is dropped if no keyword is
within `distance` characters (stage F.3).

A pattern is context-gated if it appears in `is_context_required`
in `src/models.rs` (line ~272). This is the explicit list of patterns
whose regexes are too loose to run without keyword evidence:
US Bank Account Number, ACH Batch Number, Check Number, Date of Birth,
Gender Marker, IMEISV, USA EIN, USA Passport, UK Passport, Australia
Passport, Canada Passport, Saudi Arabia National ID, US MBI, and ~15
more.

## The labeled-corpus regression harness

**File:** `tests/detection_quality.rs`

Every commit is checked against a labeled corpus of positive and
negative documents:

- **Positives** (`tests/corpus/positives/`) — each document has
  expected findings listed in `tests/corpus/labels.jsonl`. Every
  expected finding must fire or the test fails.
- **Negatives** (`tests/corpus/negatives/`) — each document lists
  "forbidden" sub_categories. If any of those sub_categories fire,
  the test fails.

The harness uses **strict assertions**: `total_fn == 0` (no
recall regressions) and `total_fp == 0` (no precision regressions).
Any commit that breaks either must either fix the bug or update the
corpus to explain the change.

Current baseline: **30/30 recall, 0 FPs** across 20 positive docs
and 16 negative docs (after Phase 1 close-out).

## Pattern specificity map

**File:** `src/models.rs :: pattern_specificity` (line ~126)

A hardcoded `match` block mapping each sub_category to a base
specificity score (0.0–1.0). This score determines:
- Whether the pattern is always-run (≥ 0.85)
- The base confidence before context boost
- The dedup tiebreaker when two patterns overlap

The map must stay in sync with the `PatternDef.specificity` field in
`src/patterns/mod.rs`. The print-only `test_patterndef_field_audit`
test (line ~4660 of `patterns/mod.rs`) reports any drift between the
two sources. As of the latest audit, there are ~8 remaining
mismatches that a follow-up commit should sync.
