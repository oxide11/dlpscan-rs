# Normalization Pipeline

> **Entry point:** `crates/siphon-core/src/normalize/mod.rs :: normalize_text` (line ~1009)
>
> Transforms input text to defeat evasion while preserving a byte-level
> mapping back to the original input.

## Why normalization exists

Adversaries obfuscate sensitive data to bypass pattern matching:
percent-encoding (`123%2D45%2D6789`), zero-width character injection,
HTML entities, homoglyph substitution (Cyrillic `а` for Latin `a`),
hex-spaced byte sequences, and more. The normalizer undoes these
transformations before the regex engine sees the text, so the patterns
only need to match the *canonical* form.

## The offset map invariant

`normalize_text` returns `(String, Vec<usize>)`. The `Vec<usize>` is
the **offset map**: `offset_map[i]` is the byte position in the
original input that produced byte `i` in the normalized output.

This map is consumed in the scanner (stage F.6) to translate match
spans from normalized coordinates back to original-input coordinates.
Without it, every span we report would be wrong, and downstream
redaction would corrupt the text.

**Every normalization stage must preserve this invariant.** If a stage
deletes bytes, the offset map entries for the surviving bytes must
still point back to their original positions. If a stage replaces
bytes, the replacement bytes inherit the offset of the source byte
they came from.

The stages are implemented via the `apply_stage!` macro (line ~1021)
which threads `(current_text, current_offsets)` through each stage.

## The 10 stages

Each stage is gated by a cheap check (e.g., `current.contains('%')`)
so clean ASCII text skips most of them. Stages 7-10 only run if the
text contains non-ASCII bytes.

### Stage 1: URL percent-decode

**Function:** `decode_percent_encoding`

Decodes `%XX` sequences to their byte values. Runs **two passes** to
handle double-encoding (`%2525` → `%25` → `%`).

**Defends against:** `123%2D45%2D6789` → `123-45-6789`

### Stage 2: HTML entity decode

**Function:** `decode_html_entities`

Decodes `&#NN;` numeric character references to their Unicode
codepoints.

**Defends against:** `&#49;&#50;&#51;-45-6789` → `123-45-6789`

### Stage 3: Strip empty comments

**Function:** `strip_comments`

Removes `/**/` (CSS) and `<!---->` (HTML) injected between characters
to break keyword matching.

**Defends against:** `pass/**/word` → `password`

### Stage 4: Hex-spaced decode

**Function:** `decode_hex_spaced`

Converts space-separated hex byte sequences to their ASCII
representation. Requires ≥3 hex pairs, all decoding to printable
ASCII.

**Defends against:** `34 35 36 2d 34 35` → `456-45`

### Stage 4b: Hex-escape decode

**Function:** `decode_hex_escapes`

Converts `\xHH` escape sequences to their byte values.

**Defends against:** `\x31\x32\x33-45-6789` → `123-45-6789`

### Stage 4c: Token-level encoded-data decode

**Function:** `decode_encoded_tokens`

Scans the text for tokens that look like encoded data, tries multiple
codecs in priority order, and replaces the token inline with the
decoded text if it passes the printable-UTF-8 gate. Runs up to **3
iterations** to handle nested encoding (e.g., `base64(base64(text))`).

**Supported codecs (in priority order):**

| Codec | Alphabet | Min token length |
|---|---|---|
| Base64 standard | A-Za-z0-9+/ | 12 chars |
| Base64URL | A-Za-z0-9_- | 12 chars |
| Base32 | A-Z2-7 (tried first for all-uppercase tokens) | 12 chars |
| Hex | 0-9a-fA-F (even length, optional 0x prefix) | 16 chars |

**Defends against:** `api_key = MTIzLTQ1LTY3ODk=` → `api_key = 123-45-6789`

**Safety gates:**
- Decoded bytes must be valid UTF-8 with ≥ 50% printable ASCII
- Decoded result must have ≥ 4 non-whitespace characters
- Decoded result must have ≥ 3 distinct characters (rejects `BBBBBBBB`)
- Tokens adjacent to `.` are skipped (protects JWT/OAuth segments)

**Offset map:** All decoded bytes inherit the offset of the first byte
of the source token. The match span in the scanner output points to the
START of the encoded token in the original input.

### Stage 5: Collapse padding

**Function:** `collapse_padding`

Strips whitespace that sits between two non-alphabetic characters.
This is the stage that turns `4242 4242 4242 4242` (a display-
formatted PAN) into `4242424242424242` so the credit card regex
can match.

**Defends against:** Space-separated digit evasion.

**Known gotcha:** The "non-alphabetic on both sides" rule is too
aggressive. It also collapses whitespace between two complete PANs
on adjacent lines (`4242424242424242\n4242424242424242` → one 32-digit
blob), between IPv6 addresses (`fc00::1\n2001:db8::1` → merged),
and between any other pair of digit-heavy values. This has caused
recurring issues in the corpus and stress tests. The workaround is
to ensure corpus documents have alphabetic text between consecutive
sensitive values. A proper fix would scope the collapse to runs shorter
than a maximum (e.g., 19 digits for the longest PAN) but this hasn't
been implemented yet.

### Stage 6: Normalize delimiters

**Function:** `normalize_delimiters`

Collapses runs of repeated hyphens or dots between alphanumeric
characters: `123--45` → `123-45`.

### Stage 7: Strip zero-width characters

**Function:** `remap_strip_zero_width`

Removes zero-width spaces (U+200B), zero-width joiners (U+200D), and
similar invisible Unicode characters.

**Defends against:** `1\u{200B}2\u{200B}3-45-6789` → `123-45-6789`

### Stage 8: Normalize exotic whitespace

Converts Unicode whitespace characters (em space, thin space, etc.)
to plain ASCII space.

### Stage 9: NFKC normalization

**Function:** `remap_nfkc`

Applies Unicode NFKC (Normalization Form KC) which decomposes and
recomposes characters, mapping compatibility equivalents to their
canonical forms. Turns fullwidth digits (`０１２`) into ASCII (`012`),
decomposes ligatures, etc.

### Stage 10: Homoglyph map

A static character-to-character mapping that replaces visual lookalike
characters with their ASCII equivalents:

- Cyrillic `а` → Latin `a`
- Greek `ε` → Latin `e`
- Fullwidth `Ａ` → `A`
- ... and ~200 other mappings

**Defends against:** Visually identical text that differs at the byte
level.

## Alternative decodings (separate from normalization)

`generate_alternative_decodings` (line ~1129) is NOT part of the
normalization pipeline — it runs much later, in the scanner's stage H.
It generates entirely new text buffers (base32/base64 decode, ROT13,
leet-speak, morse) that are then re-normalized and scanned separately.
See [pipeline.md](pipeline.md#stage-h-alt-decodings-second-pass).
