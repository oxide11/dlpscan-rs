# DLP Evasion Techniques

Comprehensive catalog of techniques an adversary can use to bypass DLP
pattern detection, with current defense status and mitigations.

---

## 1. Encoding & Character Manipulation

### 1.1 Zero-Width Character Insertion

| | |
|---|---|
| **How it works** | Insert invisible Unicode characters (ZWSP `U+200B`, ZWJ `U+200D`, ZWNJ `U+200C`, BOM `U+FEFF`, soft hyphen `U+00AD`, etc.) between digits/letters to break regex continuity. |
| **Example** | `4\u200b5\u200b3\u200b2\u200b0151\u200b1283\u200b0366` — Visa number with zero-width spaces. |
| **Patterns bypassed** | All regex-based patterns. |
| **Defense status** | **Defended.** `unicode_normalize.strip_zero_width()` removes 18 known invisible characters before scanning. Integrated into `enhanced_scan_text()` and InputGuard transforms. |
| **Residual risk** | New invisible characters added in future Unicode versions (15.0+) may not be covered. |
| **Mitigation** | Variation selectors (`U+FE00`–`U+FE0F`) and Unicode Tags block (`U+E0001`–`U+E007F`) now stripped. Periodically update `ZERO_WIDTH_CHARS` set. Consider stripping all characters in Unicode category `Cf` (Format). |

### 1.2 Homoglyph / Confusable Character Substitution

| | |
|---|---|
| **How it works** | Replace ASCII digits/letters with visually identical characters from Cyrillic, Greek, fullwidth, subscript/superscript, or mathematical Unicode blocks. |
| **Example** | `\uff14\uff15\uff13\uff12...` (fullwidth Visa), `us\u0435r@t\u0435st.com` (Cyrillic е in email). |
| **Patterns bypassed** | All patterns — regex character classes like `\d` and `[A-Z]` only match ASCII. |
| **Defense status** | **Defended.** `unicode_normalize.normalize_homoglyphs()` applies NFKC normalization + explicit mapping for 200+ Cyrillic, Greek, Armenian, Cherokee, fullwidth, small capitals, and symbol confusables. |
| **Residual risk** | Georgian and mathematical alphanumeric symbols not fully mapped. Unicode Consortium confusables.txt has 6,000+ entries vs our 200+. |
| **Mitigation** | Integrate full Unicode confusables database for comprehensive coverage. |

### 1.3 Bidirectional / RTL Text Manipulation

| | |
|---|---|
| **How it works** | Insert RTL override characters (`U+202E` RLO, `U+2066` LRI, `U+2067` RLI) to visually reorder digits while maintaining logical order in memory. |
| **Example** | `\u202E9876-54-321` displays as `123-45-6789` but regex scans the reversed logical order. |
| **Patterns bypassed** | All digit-sequence patterns (SSN, credit cards, phone numbers). |
| **Defense status** | **Defended.** All directional formatting characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) are stripped by `strip_zero_width()` alongside `U+200E`/`U+200F`. |
| **Mitigation** | Completed. All 11 directional formatting characters added to `ZERO_WIDTH_CHARS`. |

### 1.4 Unicode Normalization Form Inconsistency

| | |
|---|---|
| **How it works** | Use characters that decompose differently under NFC vs NFKC vs NFKD. Ligatures (`ﬁ` → `fi`), compatibility characters, and combining sequences behave differently. |
| **Example** | `ﬁnancial` (fi ligature) — keyword "financial" may not match in context search. |
| **Patterns bypassed** | Context keyword matching primarily. |
| **Defense status** | **Defended.** NFKC is applied, which decomposes compatibility forms. |
| **Residual risk** | Context keywords in `scan_for_context()` are matched against the **normalized** text (done inside `enhanced_scan_text`), but some edge cases with combining marks remain. |
| **Mitigation** | Apply normalization to context keyword search text explicitly. |

---

## 2. Regex-Specific Evasion

### 2.1 Delimiter Variation

| | |
|---|---|
| **How it works** | Use delimiters not in the `_S` pattern (`[-.\s/\\_\u2013\u2014\u00a0]?`). Unicode spaces like ideographic space (`U+3000`), narrow no-break space (`U+202F`), or tabs/form-feeds in unexpected positions. |
| **Example** | `4111\u30001111\u30001111\u30001111` (Visa with ideographic spaces). |
| **Patterns bypassed** | Credit cards, SSN, IBAN, postal codes — any pattern using `_S` delimiter. |
| **Defense status** | **Defended.** `normalize_whitespace()` converts 14 exotic Unicode spaces (`U+2000`–`U+200A`, `U+202F`, `U+205F`, `U+3000`) to ASCII space before scanning. Combined with `_S` delimiter pattern coverage. |
| **Mitigation** | Completed. Unicode whitespace normalization added to the normalization pipeline in `normalize_text()`. |

### 2.2 Word Boundary (`\b`) Bypass

| | |
|---|---|
| **How it works** | Place non-ASCII word characters adjacent to patterns. Python's `\b` uses `\w` = `[a-zA-Z0-9_]`, so non-ASCII letters don't trigger boundaries. |
| **Example** | Prefix a credit card with a Cyrillic letter: `а4111111111111111` — no `\b` boundary between `а` and `4`. |
| **Patterns bypassed** | Most patterns use `\b` anchors. |
| **Defense status** | **Defended** (post-normalization). NFKC + homoglyph mapping converts non-ASCII characters to ASCII before regex matching, so `\b` works correctly on normalized text. |
| **Residual risk** | Unmapped non-ASCII characters adjacent to patterns could still prevent `\b` from firing. |
| **Mitigation** | Use `re.UNICODE` flag so `\b` respects Unicode word boundaries. Or add explicit `(?<!\w)` / `(?!\w)` with Unicode awareness. |

### 2.3 Regex Denial of Service (ReDoS)

| | |
|---|---|
| **How it works** | Craft input that triggers catastrophic backtracking in patterns with nested quantifiers or alternations. IPv6, IBAN, and complex banking patterns are most vulnerable. |
| **Example** | Long string of hex+colon segments targeting IPv6: `AAAA:AAAA:AAAA:...` (50+ segments). |
| **Patterns bypassed** | Not a bypass — a resource exhaustion attack that prevents scanning. |
| **Defense status** | **Defended.** SIGALRM on Unix main thread + `_ThreadTimeout` fallback (threading.Timer) for worker threads, async contexts, and Windows. Checks timeout flag between pattern iterations. |
| **Mitigation** | Completed. Cross-platform timeout added. Audit all patterns with ReDoS analyzer tools. Use atomic groups or possessive quantifiers where possible. |

---

## 3. Structural & Boundary Evasion

### 3.1 Chunk Boundary Splitting

| | |
|---|---|
| **How it works** | In streaming/file scanning, place sensitive data across chunk boundaries where overlap is insufficient to capture the full pattern. |
| **Example** | In a large file, split a credit card number at position `chunk_size - 8` so the first 8 digits are in chunk N and last 8 in chunk N+1, with overlap < 16 chars. |
| **Patterns bypassed** | All patterns, when scanning chunked input. |
| **Defense status** | **Partial.** `chunk_overlap` carries trailing bytes forward, but default overlap may be insufficient for long patterns. |
| **Mitigation** | Set overlap to at least the longest expected pattern match (50+ chars). Test patterns at chunk boundaries. |

### 3.2 Offset Map Poisoning

| | |
|---|---|
| **How it works** | Heavily inject zero-width characters to create large discrepancies between normalized and original text positions, potentially causing span calculation errors. |
| **Example** | 100 zero-width chars inserted before a credit card — offset map indices shift by 100. |
| **Patterns bypassed** | Affects span accuracy rather than detection. Redaction/obfuscation could target wrong positions. |
| **Defense status** | **Defended.** Offset map is built correctly in `strip_zero_width()`. Bounds checks exist in span mapping. |
| **Residual risk** | NFKC normalization can change string length (e.g., ligature `ﬁ` → 2 chars), but offset map only accounts for zero-width removal, not NFKC length changes. |
| **Mitigation** | Rebuild offset map after NFKC normalization. Add assertion: `len(offset_map) == len(normalized_text)`. |

### 3.3 OCR Confidence Manipulation

| | |
|---|---|
| **How it works** | Provide intentionally degraded images (blur, noise, low contrast) so OCR produces text at just above the `MIN_OCR_CONFIDENCE = 30` threshold, introducing errors that break pattern matching. |
| **Example** | Scanned credit card image with strategic blur — OCR reads `4111111111111l11` (lowercase L instead of 1). |
| **Patterns bypassed** | All patterns in image-based scanning. |
| **Defense status** | **Partial.** Threshold raised to 60% (from 30%). No per-pattern confidence requirements yet. |
| **Mitigation** | Add per-pattern OCR confidence requirements. Apply fuzzy digit matching post-OCR. |

---

## 4. Context Manipulation

### 4.1 Context Distance Overflow

| | |
|---|---|
| **How it works** | Place sensitive data far from context keywords — beyond the configured `distance` (default 50 chars). |
| **Example** | `SSN:` + 75 spaces + `123-45-6789` — keyword is 75 chars away, beyond 50-char proximity. |
| **Patterns bypassed** | All context-dependent patterns (those in `CONTEXT_REQUIRED_PATTERNS`). |
| **Defense status** | **Partial.** Distance is configurable per category. Default is 50 chars, some categories use 80. |
| **Mitigation** | Increase default distance to 150+. Use paragraph-level context detection. Consider section-aware proximity. |

### 4.2 Context Keyword Evasion

| | |
|---|---|
| **How it works** | Use synonyms, misspellings, abbreviations, or non-English translations not in the hardcoded keyword lists. |
| **Example** | `CC#: 4111111111111111` (not in keywords), `número de tarjeta: ...` (Spanish), `Kreditkartennummer: ...` (German). |
| **Patterns bypassed** | All context-dependent patterns. |
| **Defense status** | **Defended.** `scan_for_context()` uses two-pass matching: exact regex (fast path) + Levenshtein fuzzy matching (edit distance ≤ 2) for keywords ≥ 5 characters. Multi-word keywords are matched using n-grams. |
| **Residual risk** | Non-English synonyms and translations not covered. Keywords under 5 characters are exact-match only to avoid false positives. |
| **Mitigation** | Add multilingual keyword translations. Consider embedding-based semantic matching. |

### 4.3 Context Dilution via Homoglyphs

| | |
|---|---|
| **How it works** | Use homoglyphs within context keywords to prevent keyword matching while maintaining visual appearance. |
| **Example** | `Viѕa card: 4111111111111111` — Cyrillic `ѕ` in "Viѕa" prevents keyword "visa" from matching. |
| **Patterns bypassed** | Context-dependent patterns. Non-context-required patterns still match. |
| **Defense status** | **Defended.** Context keywords are searched in the normalized text (normalization happens before `scan_for_context` runs inside `enhanced_scan_text`). |
| **Residual risk** | If homoglyph mapping is incomplete, some confusable characters in keywords won't normalize. |
| **Mitigation** | Ensure keyword matching uses the same normalization pipeline as pattern matching. |

---

## 5. Format & Pipeline Evasion

### 5.1 Unsupported File Format

| | |
|---|---|
| **How it works** | Embed sensitive data in file formats without registered extractors. The file is silently skipped or treated as binary. |
| **Example** | Hide SSN in `.pages` (Apple), `.odt` (OpenDocument), `.rtf` (Rich Text), or custom archive format. |
| **Patterns bypassed** | All patterns — file content is never extracted for scanning. |
| **Defense status** | **Partial.** Common formats have extractors (.txt, .pdf, .docx, .xlsx, .pptx, .csv, .json, .xml, .html, .rtf, .eml, .msg, images via OCR). Magic-byte content-type detection provides fallback when file extension is missing or misleading. |
| **Mitigation** | Add ODS and Pages extractors. Log warnings for unextractable files. |

### 5.2 Format-Specific Encoding Escape

| | |
|---|---|
| **How it works** | Use format-specific escape sequences that decode to sensitive data but don't match regex in escaped form. |
| **Example** | JSON: `"\u0034\u0031\u0031\u0031..."` → decodes to `4111...`. HTML: `&#52;&#49;&#49;&#49;...`. |
| **Patterns bypassed** | All patterns, if the format parser doesn't decode before scanning. |
| **Defense status** | **Partial.** Extractors decode JSON/XML/HTML before scanning. Nested or double-encoded content may slip through. |
| **Mitigation** | Apply recursive decoding (check if decoded output still contains escape sequences). Test with nested encoding. |

### 5.3 Max Matches Truncation

| | |
|---|---|
| **How it works** | Flood a document with 50,000+ pattern matches so the scanner hits `MAX_MATCHES` and silently stops. Sensitive data after the limit is unscanned. |
| **Example** | File with 50,001 fake SSNs — the first 50,000 are scanned, the real SSN at position 50,001 is ignored. |
| **Patterns bypassed** | All patterns after the truncation point. |
| **Defense status** | **Partial.** Limit is enforced; a warning is logged. `ScanResult.scan_truncated` and `ScanResult.scan_complete` expose truncation status to API consumers. |
| **Mitigation** | Completeness indicator added to `ScanResult`. Consider per-category limits. Implement sampling for high-match documents. |

### 5.4 Global Scan Timeout Bypass

| | |
|---|---|
| **How it works** | Exploit that SIGALRM-based timeout only works on Unix main thread. In async/threaded/Windows environments, there's no timeout — a ReDoS pattern runs indefinitely. |
| **Patterns bypassed** | All patterns (resource exhaustion). |
| **Defense status** | **Defended.** `MAX_SCAN_SECONDS = 120` enforced via SIGALRM on Unix main thread, with `_ThreadTimeout` (threading.Timer) fallback on all other platforms/threads. |
| **Mitigation** | Completed. Cross-platform timeout implemented. |

---

## 6. Allowlist & Suppression Evasion

### 6.1 Allowlist Value Mutation

| | |
|---|---|
| **How it works** | Modify allowlisted test values by 1 character to bypass exact-match allowlist filtering while preserving the sensitive data format. |
| **Example** | If `4111111111111111` is allowlisted, use `4111111111111112` (still valid Visa). |
| **Patterns bypassed** | Any pattern whose specific values are allowlisted. |
| **Defense status** | **Defended.** Allowlist supports exact matching, glob/wildcard patterns (`4111*`, `test?@*.com`, `[seq]`), and sub-category filtering. |
| **Mitigation** | Consider category-level allowlisting for broader suppression. |

### 6.2 Directory/Path Exclusion Abuse

| | |
|---|---|
| **How it works** | If `skip_paths` or `skip_patterns` are user-controllable, an attacker can configure broad exclusions to prevent scanning of sensitive directories. |
| **Example** | Config: `skip_paths: ["*.json", "config/*", "data/*"]` — sensitive data in these paths is never scanned. |
| **Patterns bypassed** | All patterns in excluded paths. |
| **Defense status** | **Weak.** Skip patterns are fully user-configurable with no guardrails. |
| **Mitigation** | Hard-code critical paths that are always scanned. Warn when skip patterns match common sensitive locations (`.env`, `secrets/`, `credentials/`). |

---

## 7. Pattern-Specific Weaknesses

### 7.1 Overly Broad Patterns

| Pattern | Regex | False Positive Risk |
|---------|-------|---------------------|
| Session ID | `[0-9a-f]{32,64}` | Matches SHA-256 hashes, git commits, UUIDs |
| US Bank Account | `\d{8,17}` | Matches phone numbers, invoice IDs, zip codes |
| Employee ID | `[A-Z]{1,3}\d{4,8}` | Matches product codes, serial numbers |
| State DL (many) | `\d{7}` to `\d{9}` | Overlaps with SSN, phone, ZIP |

**Defense status:** Most broad patterns are in `CONTEXT_REQUIRED_PATTERNS` so they only fire with keyword context. But context evasion (§4.1–4.2) weakens this defense.

### 7.2 Luhn Check Dependency

| | |
|---|---|
| **How it works** | Credit card detection depends on Luhn validation. If the Luhn check is somehow bypassed or the card number is intentionally made Luhn-invalid, it won't be detected. |
| **Defense status** | **Defended.** Luhn check is hardcoded for `Credit Card Numbers` category, cannot be disabled via config. |
| **Residual risk** | Some legitimate card-like numbers (prepaid, virtual cards) may use non-standard check digit algorithms. |

---

## 8. Advanced Adversarial Techniques

### 8.1 Polymorphic Encoding Chain

| | |
|---|---|
| **How it works** | Layer multiple evasion techniques: zero-width insertion + homoglyph substitution + format-specific encoding + delimiter variation. |
| **Example** | `\uff14\u200b\uff11\u200b\uff11\u200b\uff11...` — fullwidth digits with zero-width spaces between each. |
| **Defense status** | **Defended.** Normalization pipeline strips zero-width chars first, then normalizes homoglyphs. Chained techniques are handled by the two-stage pipeline. |
| **Residual risk** | Triple-layered attacks (e.g., base64-encoded homoglyphs with zero-width chars) would bypass if the outer encoding isn't decoded first. |

### 8.2 Steganographic Hiding

| | |
|---|---|
| **How it works** | Embed sensitive data in image least-significant bits, document metadata (EXIF/XMP), whitespace patterns, or Unicode tag characters (`U+E0001`–`U+E007F`). |
| **Defense status** | **Partial.** Unicode Tags block (`U+E0001`–`U+E007F`) now stripped. No steganalysis capability. Metadata extraction is limited. |
| **Mitigation** | Unicode Tags stripping completed. Extract and scan EXIF/XMP metadata. Consider steganalysis library for image scanning. |

---

## Summary — Defense Coverage Matrix

| Technique | Status | Severity |
|-----------|--------|----------|
| Zero-width char insertion | **Defended** (incl. variation selectors, Unicode Tags) | High |
| Homoglyph substitution | **Defended** (200+ mappings) | High |
| RTL/Bidi manipulation | **Defended** | High |
| Delimiter variation | **Defended** | Medium |
| Word boundary bypass | **Defended** | High |
| ReDoS | **Defended** (SIGALRM + threading.Timer fallback) | Medium |
| Chunk boundary splitting | Partial | Medium |
| OCR confidence manipulation | Partial (threshold raised to 60) | Medium |
| Unsupported file format | Partial (RTF added, content-type detection) | Medium |
| Context distance overflow | Partial | Medium |
| Context keyword evasion | **Defended** (fuzzy Levenshtein ≤ 2) | High |
| Max matches truncation | Partial (completeness indicator exposed) | High |
| Timeout bypass (non-Unix) | **Defended** (threading.Timer fallback) | Medium |
| Allowlist value mutation | **Defended** (wildcard/glob matching) | Medium |
| Path exclusion abuse | Weak | High |
| Polymorphic encoding | **Defended** | High |
| Steganographic hiding | Partial (Unicode Tags stripped) | Medium |

---

## Priority Remediation Roadmap

### Completed

- ~~**Add RTL/Bidi stripping**~~ — ✅ Added `U+202A`–`U+202E`, `U+2066`–`U+2069` to strip set
- ~~**Cross-platform regex timeout**~~ — ✅ `_ThreadTimeout` (threading.Timer) fallback for non-Unix/non-main-thread
- ~~**Scan completeness indicator**~~ — ✅ `ScanResult.scan_truncated` / `scan_complete` exposed to API consumers
- ~~**Delimiter variation defense**~~ — ✅ `normalize_whitespace()` converts 14 exotic Unicode spaces to ASCII
- ~~**Variation selector stripping**~~ — ✅ `U+FE00`–`U+FE0F` added to strip set
- ~~**Unicode Tags stripping**~~ — ✅ `U+E0001`–`U+E007F` added to strip set

- ~~**Expand homoglyph coverage**~~ — ✅ 200+ mappings: added Armenian, Cherokee, small capitals, circled/dingbat digits, fullwidth symbols
- ~~**Enhance context keywords**~~ — ✅ Fuzzy Levenshtein matching (edit distance ≤ 2) with n-gram support for multi-word keywords
- ~~**File format coverage**~~ — ✅ RTF extractor added, magic-byte content-type detection fallback for misnamed files
- ~~**OCR confidence hardening**~~ — ✅ `MIN_OCR_CONFIDENCE` raised from 30 to 60
- ~~**Allowlist pattern matching**~~ — ✅ Wildcard/glob support (`*`, `?`, `[seq]`) in allowlist text entries

### Remaining

1. **Full Unicode confusables.txt** — integrate the complete 6,000+ entry database from Unicode Consortium
2. **Multilingual context keywords** — add translations and synonyms in non-English languages
3. **Per-pattern OCR confidence** — different patterns may need different OCR thresholds
4. **ODS/Pages extractors** — add extractors for OpenDocument Spreadsheet and Apple Pages formats
5. **Path exclusion guardrails** — warn when skip patterns match sensitive locations (`.env`, `secrets/`)
