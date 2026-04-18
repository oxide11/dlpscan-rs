# Classification Labels and Traffic Light Protocol

dlpscan detects classification and sharing-control markings in
documents and enforces a configurable policy that **blocks** inputs
labeled above a severity threshold — regardless of the `Action` setting
(Flag, Redact, Tokenize, Obfuscate). This is a safety net: a document
marked `Confidential` or `TLP:AMBER` is never silently tokenized and
emitted as "clean" output.

## Severity ladder

The scanner normalizes every classification marking — corporate,
government, privilege, or TLP — onto a single ordered severity scale:

| Level | Numeric | Examples |
|---|:---:|---|
| **Public** | 0 | `TLP:CLEAR`, `TLP:WHITE`, Unclassified |
| **Internal** | 1 | `TLP:GREEN`, `Internal Use Only` |
| **Restricted** | 2 | `FOUO`, `CUI`, `SBU`, `LES`, `Proprietary`, `Do Not Distribute`, `Embargoed` |
| **Confidential** | 3 | `Corporate Confidential`, `Strictly Confidential`, `Eyes Only`, `Need to Know`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `Privileged and Confidential`, `Attorney-Client Privilege`, `MNPI`, `CLASSIFIED CONFIDENTIAL` |
| **Secret** | 4 | `CLASSIFIED SECRET`, `NOFORN`, `Highly Confidential`, `TLP:RED` |
| **Top Secret** | 5 | `TOP SECRET`, `TS//SCI`, `TS//SI` |

Higher numbers are more sensitive. Comparison is done with `>=`, so
setting the block threshold to `Confidential` blocks `Confidential`,
`Secret`, and `Top Secret` without having to list each level.

## Default blocking policy

By default `InputGuard::new()` blocks **Confidential and above**, which
includes **TLP:AMBER** and **TLP:AMBER+STRICT**. Any input containing
one of these markings causes `scan()` to return a
`DlpError::ClassificationPolicyViolation` error with the list of
triggering labels.

```rust
use dlpscan::guard::InputGuard;
use dlpscan::errors::DlpError;

let guard = InputGuard::new();
match guard.scan("Marking: TLP:AMBER — limited distribution") {
    Err(DlpError::ClassificationPolicyViolation { level, threshold, labels }) => {
        eprintln!("blocked at {}: {:?}", level.label(), labels);
    }
    Ok(result) => { /* safe to forward downstream */ }
    Err(e) => return Err(e),
}
```

## Adjusting the threshold

To allow confidential content through but still block Secret and above:

```rust
use dlpscan::classification::ClassificationLevel;
use dlpscan::guard::InputGuard;

let guard = InputGuard::new()
    .with_block_classification(ClassificationLevel::Secret);
```

Accepted level names (case-insensitive, includes TLP aliases):
`public`, `internal`, `restricted`, `confidential`, `secret`,
`top-secret`, plus `tlp:clear`, `tlp:green`, `tlp:amber`,
`tlp:amber+strict`, `tlp:red`.

## Disabling the policy entirely

For purely informational scans where classification labels should be
reported as findings but not block the pipeline:

```rust
let guard = InputGuard::new().without_classification_blocking();
let result = guard.scan(text)?;
// result.findings contains the labels; scan did not fail.
// result.classification_level carries the highest level seen.
```

## Enforcement guarantees

1. **Preset-proof**. When the block policy is active, the guard
   force-includes all classification categories in the scan —
   `Traffic Light Protocol`, `Data Classification Labels`,
   `Corporate Classification`, `Legal Privileged Content`,
   `Financial Regulatory Labels` — even when the caller only asked
   for `Preset::PciDss`. A user cannot smuggle a TLP:RED doc through
   by choosing a narrow preset.

2. **Action-proof**. The classification check runs **before** the
   `Action` dispatch. A document marked `Confidential` is rejected
   even if the guard is in `Action::Tokenize` mode — it never gets
   the chance to be silently tokenized and forwarded.

3. **Always-run patterns**. TLP markings are compiled as always-run
   patterns (not context-gated), so they fire even on very short
   inputs without surrounding keyword context.

4. **Overlap dedup prefers the stricter marking**. A substring that
   matches both `TLP:AMBER` and `TLP:AMBER+STRICT` resolves to
   `TLP:AMBER+STRICT`, so no information is lost in the policy
   decision.

## REST API behavior

When the API server blocks an input by classification, it returns
HTTP `422 Unprocessable Entity` with a JSON body:

```json
{
  "detail": "Classification policy violation: found 1 label(s) at level 'confidential' (threshold: 'confidential'): Traffic Light Protocol: TLP:AMBER",
  "level": "confidential",
  "threshold": "confidential",
  "labels": ["Traffic Light Protocol: TLP:AMBER"]
}
```

Every block is logged to the audit trail with the category `"classification_block"`
and the triggering labels, so compliance reviewers can trace enforcement.

## Detected labels (full list)

### Traffic Light Protocol (FIRST.org TLP 2.0)

| Sub-category | Level | Notes |
|---|---|---|
| `TLP:RED` | Secret | Named-recipients only |
| `TLP:AMBER+STRICT` | Confidential | Originating organization only |
| `TLP:AMBER` | Confidential | Limited to recipient organization |
| `TLP:GREEN` | Internal | Community / sector |
| `TLP:CLEAR` | Public | No sharing restrictions (TLP 2.0) |
| `TLP:WHITE` | Public | Pre-TLP-2.0 synonym for `TLP:CLEAR` |

Matched by both `TLP:RED` and `TLP RED` (colon or whitespace).

### Government / IC markings (`Data Classification Labels`)

| Sub-category | Level |
|---|---|
| `Top Secret` (TOP SECRET, TS//SCI, TS//SI) | Top Secret |
| `Secret Classification` (SECRET, CLASSIFIED SECRET) | Secret |
| `NOFORN` | Secret |
| `Confidential Classification` (CLASSIFIED CONFIDENTIAL) | Confidential |
| `CUI` (Controlled Unclassified Information) | Restricted |
| `FOUO` (For Official Use Only) | Restricted |
| `SBU` (Sensitive But Unclassified) | Restricted |
| `LES` (Law Enforcement Sensitive) | Restricted |

### Corporate markings (`Corporate Classification`)

| Sub-category | Level |
|---|---|
| `Highly Confidential` | Secret |
| `Corporate Confidential` | Confidential |
| `Eyes Only` | Confidential |
| `Need to Know` | Confidential |
| `Restricted` | Restricted |
| `Do Not Distribute` | Restricted |
| `Proprietary` | Restricted |
| `Embargoed` | Restricted |
| `Internal Only` | Internal |

### Privilege / regulatory markings

| Category / Sub-category | Level |
|---|---|
| `Legal Privileged Content` / `Privileged and Confidential` | Confidential |
| `Legal Privileged Content` / `Supervisory Confidential` | Confidential |
| `Legal Privileged Content` / `Attorney-Client Privilege` | Confidential |
| `Legal Privileged Content` / `Attorney Work Product` | Confidential |
| `Financial Regulatory Labels` / `MNPI` | Confidential |
