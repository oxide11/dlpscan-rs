# Extending dlpscan-rs — Cookbook

This doc answers "I want to add X" questions with specific file paths
and line references. If you're adding a new detection capability, this
is the quickest path to getting it wired in correctly.

---

## Add a new pattern

1. **Define the `PatternDef`** in `src/patterns/mod.rs` inside the
   `PATTERNS` static array. Each entry needs:

   ```rust
   PatternDef {
       category: "My Category",
       sub_category: "My Pattern",
       regex: r"\b...\b",
       case_insensitive: false,
       specificity: 0.40,     // 0.0–1.0; higher = more structurally unique
       context_required: false, // true if the regex is too loose without keywords
   }
   ```

2. **Add context keywords** in `src/context/keywords.rs`. Without
   keywords, context-gated patterns can never fire, and always-run
   patterns get no confidence boost:

   ```rust
   ("My Category", "My Pattern", ContextEntry {
       keywords: &["my keyword", "another keyword"],
       distance: 50,
   }),
   ```

3. **Add specificity to the map** in `src/models.rs :: pattern_specificity`.
   The hardcoded map determines the always-run threshold (≥ 0.85) and
   the confidence calculation. If you skip this, your pattern falls
   through to `DEFAULT_SPECIFICITY = 0.40`.

4. **Decide: always-run or context-gated?**
   - If `specificity >= 0.85`, it's automatically always-run.
   - If you want always-run below 0.85, add it to `CRITICAL_ALWAYS_RUN`
     in `src/scanner/mod.rs` (line ~143). **Only do this if the pattern
     has a validator or a structurally tight regex.**
   - If context-gated, add it to `is_context_required` in
     `src/models.rs` (line ~272) AND set `context_required: true` on
     the `PatternDef`.

5. **Update the pattern count test** in `src/patterns/mod.rs ::
   test_pattern_count` — it asserts `PATTERNS.len() == 561` (or
   whatever the current count is).

---

## Add a new validator

1. **Write the validator function** in `src/validation.rs`. Convention:

   ```rust
   pub fn is_valid_my_pattern(matched_text: &str) -> bool {
       // Parse, compute checksum, return true/false
   }
   ```

   Keep validators pure functions — no I/O, no allocation beyond what
   parsing requires.

2. **Wire it into `validate_match`** at the bottom of
   `src/validation.rs`. Add a new arm:

   ```rust
   "My Pattern" => is_valid_my_pattern(matched_text),
   ```

3. **Add unit tests** in the `#[cfg(test)] mod tests` block at the
   bottom of `validation.rs`. At minimum:
   - 2+ known-valid test vectors (hand-verified)
   - 2+ known-invalid test vectors (bumped check digit)
   - Edge cases: all-same sentinel, wrong length, wrong alphabet

4. **Add a corpus negative** in `tests/corpus/negatives/` — a document
   containing checksum-invalid values that the regex would match but
   the validator should reject. Add a `forbidden` entry in
   `tests/corpus/labels.jsonl`.

5. **Add a corpus positive** in `tests/corpus/positives/` — a document
   containing a real (checksum-valid) value. Add an `expected` entry
   in `labels.jsonl`.

6. **Run the detection-quality harness:** `cargo test --test detection_quality`.
   It will fail if your negative produces an FP or your positive
   produces a miss.

---

## Add a new file extractor

1. **Write the extractor function** in `src/extractors.rs`:

   ```rust
   pub fn extract_my_format(file_path: &str) -> Result<ExtractionResult, String> {
       // Read the file, parse the format, produce text
       Ok(ExtractionResult::new(text, "my_format"))
   }
   ```

2. **Register the file extension** in `get_extractor` (line ~123):

   ```rust
   "myext" => Some(extract_my_format),
   ```

3. **If the extractor needs a new crate dependency**, add it as
   `optional = true` in `Cargo.toml`, create a feature flag, and gate
   the function and the `get_extractor` arm with
   `#[cfg(feature = "my-format")]`.

---

## Add a corpus test

The detection-quality harness uses `tests/corpus/labels.jsonl` to know
what to expect. Each line is a JSON object:

**Positive (recall test):**
```json
{
  "path": "positives/category/my_test.txt",
  "expected": [
    {"sub_category": "My Pattern", "text": "the-matched-value"}
  ]
}
```

The harness scans the file and asserts that every expected finding
fires. The `text` field is a substring check against the match's
reported text — it doesn't need to be the full match span.

**Negative (precision test):**
```json
{
  "path": "negatives/my_negative.txt",
  "forbidden": ["My Pattern", "Another Pattern"]
}
```

The harness scans the file and asserts that no match with a listed
sub_category fires.

**Gotcha:** don't embed valid examples of a pattern inside a negative
document's prose (e.g., "known-valid 1234 with check bumped"). The
scanner will match the valid example and report it as an FP.

**Gotcha:** GitHub Push Protection rejects files containing strings
that match its secret detectors (Stripe keys, Slack webhooks). Use
non-brand-prefixed random strings or runtime-construction workarounds
for those patterns.

---

## Modify the normalization pipeline

1. **New stage:** Add a function with signature
   `fn my_stage(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>)`
   in `src/normalize/mod.rs`. The function transforms the text and
   returns a new offset map where `new_offsets[i]` is the original
   byte position of `new_text[i]`.

2. **Insert it into `normalize_text`** using `apply_stage!`:
   ```rust
   apply_stage!(my_stage, current, offsets);
   ```
   Order matters: earlier stages run first. Put your stage where it
   makes sense in the evasion-defense chain.

3. **Test it** with both a functional test ("does it transform the
   input correctly?") and an offset-map test ("are the reported spans
   still correct after the transformation?").

---

## Common debugging techniques

**"Why isn't my pattern matching?"** — check in order:
1. Is the pattern's regex correct? Test it with
   `regex::Regex::new(r"...").unwrap().find(text)` in a unit test.
2. Is the pattern in `active_patterns`? If it's context-gated and
   no keyword is in the document, the AC prefilter drops it.
3. Is `validate_match` rejecting it? Add a print to see if the
   validator returns `false`.
4. Is dedup removing it? Run with `config.deduplicate = false` to
   see all raw matches before dedup.
5. Is normalization changing the input? Print the normalized text
   and compare with the original.

**"Why is my pattern matching something it shouldn't?"** — check:
1. Is the regex too loose? Test with known false-positive inputs.
2. Is the pattern always-run when it should be context-gated? Check
   `CRITICAL_ALWAYS_RUN` and `is_context_required`.
3. Is the alt-decodings pass (stage H) producing a spurious match?
   The alt pass skips context checks — a pattern in
   `CRITICAL_ALWAYS_RUN` without a validator will fire through alt.
4. Is another pattern matching and winning dedup? Run with
   `config.deduplicate = false` to see the raw set.
