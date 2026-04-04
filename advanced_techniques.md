# Advanced DLP Techniques

Technical reference for dlpscan's advanced detection modules.

**Version:** 1.7.0

---

## Table of Contents

1. [Aho-Corasick Context Matching](#aho-corasick-context-matching)
2. [Exact Data Match (EDM)](#exact-data-match-edm)
3. [Locality-Sensitive Hashing (LSH)](#locality-sensitive-hashing-lsh)
4. [Count-Min Sketch](#count-min-sketch)
5. [HyperLogLog](#hyperloglog)
6. [Cuckoo Filter](#cuckoo-filter)
7. [Session Correlator](#session-correlator)
8. [Rabin-Karp Rolling Hash](#rabin-karp-rolling-hash)
9. [Entropy Analysis & Recursive Unpacking](#entropy-analysis--recursive-unpacking)
10. [Benchmark Results](#benchmark-results)
11. [Architecture Overview](#architecture-overview)

---

## Aho-Corasick Context Matching

### What It Does

Replaces the default regex-based context keyword matching with a single-pass
trie-based automaton that matches all 2,500+ context keywords simultaneously
in O(n) time.

### The Problem It Solves

dlpscan's context matching verifies that sensitive data patterns (e.g., credit
card numbers) appear near relevant keywords (e.g., "credit card", "payment",
"visa"). The default regex backend compiles 560 separate alternation patterns:

```
\b(visa|credit card|card number|card no|pan)\b
```

Each pattern match in the text triggers a context check, which searches for
keywords in the surrounding window. With 560 patterns and potentially thousands
of matches, this creates O(M x K) context checks per scan.

### How Aho-Corasick Works

1. **Build Phase**: All 2,500+ keywords are inserted into a trie (prefix tree).
   Failure links are computed using BFS — these let the automaton "fall back"
   to the longest matching suffix when a character doesn't match, similar to
   how KMP works for single patterns.

2. **Search Phase**: The text is scanned character-by-character. The automaton
   follows trie edges, falling back via failure links as needed. Every time a
   keyword is completed, it's emitted with its position. This is a single O(n)
   pass that finds ALL keywords simultaneously.

3. **Index Phase**: Keyword hits are organized into a `ContextHitIndex` — a
   sorted position list per (category, sub_category) pair. Proximity queries
   use binary search for O(log n) per lookup.

```
Text: "credit card number 4111111111111111 expires 12/28"

Trie traversal: c→r→e→d→i→t→ →c→a→r→d  → EMIT "credit card" at pos 0
                                  n→u→m→b→e→r → EMIT "card number" at pos 12
                                  e→x→p→i→r→e→s → EMIT "expires" at pos 35

Hit Index: {
  ('Credit Card Numbers', 'Visa'): [0, 12, 35]  ← sorted positions
}

Query: has_hit_in_range('Visa', match_start-50, match_end+50)
       → binary search → O(log 3)
```

### Configuration

Three ways to enable:

```python
# 1. Programmatic (per-guard)
from dlpscan import InputGuard, Preset
guard = InputGuard(presets=[Preset.PCI_DSS], context_backend="ahocorasick")

# 2. Programmatic (global)
from dlpscan import set_context_backend
set_context_backend("ahocorasick")

# 3. Environment variable
# DLPSCAN_CONTEXT_BACKEND=ahocorasick

# 4. Config file (pyproject.toml)
# [tool.dlpscan]
# context_backend = "ahocorasick"

# 5. Config file (.dlpscanrc)
# {"context_backend": "ahocorasick"}
```

To switch back: `set_context_backend("regex")`

### C Extension vs Pure Python

The module uses **pyahocorasick** (C extension) when available:

```bash
pip install dlpscan[ahocorasick]   # or: pip install pyahocorasick
```

If not installed, a pure-Python fallback automaton is used. The C extension
is significantly faster for large keyword sets.

### Fuzzy Matching Integration

Aho-Corasick performs **exact** keyword matching. It does NOT replace fuzzy
Levenshtein matching. When the Aho-Corasick backend is active:

1. First: O(1) lookup in the Aho-Corasick hit index (exact match)
2. If no exact match: fall through to Levenshtein fuzzy matching (edit distance ≤ 2)

This means typo detection ("credti card" → "credit card") still works.

### Thread Safety

The automaton is built once and is read-only during scanning. Multiple threads
can share the same matcher. The automaton is rebuilt automatically when custom
patterns are registered/unregistered.

### API Reference

```python
# Module: dlpscan.ahocorasick

class AhoCorasickMatcher:
    def build(context_keywords=None, custom_context=None) -> None
    def search(text: str) -> ContextHitIndex
    def has_context_near(hit_index, match_start, match_end,
                         category, sub_category, distance=50) -> bool
    @property
    def is_built(self) -> bool
    @property
    def keyword_count(self) -> int

class ContextHitIndex:
    def has_hit_in_range(category, sub_category, range_start, range_end) -> bool
    @property
    def empty(self) -> bool

# Singleton access
get_matcher() -> AhoCorasickMatcher
rebuild_matcher(custom_context=None) -> None

# Scanner integration
set_context_backend(backend: str) -> None   # "regex" or "ahocorasick"
get_context_backend() -> str
```

---

## Exact Data Match (EDM)

### What It Does

Detects specific known sensitive values (e.g., a list of 50,000 employee SSNs)
with **zero false positives** using salted cryptographic hashes. Unlike pattern
matching which finds anything that *looks like* an SSN, EDM only matches values
you've explicitly registered.

### The Problem It Solves

Pattern matching with `\d{3}-\d{2}-\d{4}` catches SSN-like patterns but also
matches phone numbers, ZIP codes, and other numeric sequences. EDM eliminates
this ambiguity entirely: if the hash matches, the exact value was present.

### How It Works

1. **Registration**: Each known sensitive value is normalized (lowercase, strip
   separators) and hashed with HMAC-SHA256 using a per-deployment salt:
   ```
   H(salt, normalize("123-45-6789")) → "a1b2c3d4..."
   ```
   Only the hash is stored — the original value is never kept.

2. **Scanning**: Text is tokenized into candidate values using configurable
   tokenizers (numeric sequences, emails, word n-grams). Each candidate is
   normalized, hashed, and checked against the hash set.

3. **Privacy**: The hash set is safe to distribute (e.g., to scanning nodes)
   because recovering original values from HMAC-SHA256 hashes is
   computationally infeasible. The salt must be kept secret.

```
Registration:
  "123-45-6789" → normalize → "123456789" → HMAC-SHA256(salt, "123456789") → "a1b2..."
  "987-65-4321" → normalize → "987654321" → HMAC-SHA256(salt, "987654321") → "f3e4..."

  Hash set: {"a1b2...", "f3e4..."}

Scanning:
  Text: "Employee SSN is 123-45-6789 on file."
  Tokenizer: extracts "123-45-6789" at span (16, 27)
  Normalize: "123456789"
  Hash: HMAC-SHA256(salt, "123456789") → "a1b2..."
  Lookup: "a1b2..." in hash_set → MATCH (confidence: 1.0)
```

### Usage

```python
from dlpscan import ExactDataMatcher

# Create matcher with auto-generated salt
matcher = ExactDataMatcher()

# Or with explicit salt (for reproducibility / persistence)
matcher = ExactDataMatcher(salt=b'my-secret-deployment-salt-32bytes')

# Register known sensitive values
matcher.register_values("employee_ssn", [
    "123-45-6789",
    "987-65-4321",
    "555-12-3456",
])

matcher.register_values("customer_cc", [
    "4111-1111-1111-1111",
    "5500-0000-0000-0004",
])

# Scan text
hits = matcher.scan("Employee SSN is 123-45-6789 on file.")
for hit in hits:
    print(f"EDM match: category={hit.category}, span={hit.span}, "
          f"confidence={hit.confidence}")

# Quick check
matcher.check_value("123-45-6789", category="employee_ssn")  # True
matcher.check_value("000-00-0000", category="employee_ssn")  # False

# Persistence
matcher.save("edm_hashes.json")
loaded = ExactDataMatcher.load("edm_hashes.json")
```

### Tokenizers

Tokenizers extract candidate values from text for hashing:

| Tokenizer | What It Extracts | Use Case |
|-----------|-----------------|----------|
| `numeric` | Digit sequences with separators (`\d[\d\-. ]{3,18}\d`) | SSNs, credit cards, phone numbers |
| `email` | Email addresses | Email addresses |
| `word_1gram` | Single words (2+ chars) | Names, keywords |
| `word_2gram` | Two-word phrases | Full names |
| `word_3gram` | Three-word phrases | Addresses |

```python
# Custom tokenizer configuration
matcher = ExactDataMatcher(tokenizers=['numeric', 'email', 'word_2gram'])

# Register custom tokenizer
import re
def my_tokenizer(text):
    return [(m.group(), m.span()) for m in re.finditer(r'PRJ-\d{6}', text)]

matcher.register_tokenizer('project_code', my_tokenizer)
```

### Value Normalization

Before hashing, values are normalized to handle formatting variations:

```
"123-45-6789"      → "123456789"     (separators stripped)
"4111 1111 1111 1111" → "4111111111111111" (spaces stripped)
"John.Doe@EXAMPLE.com" → "johndoeexamplecom" (lowercased, dots stripped)
```

This ensures that `411-1111-1111-1111`, `4111 1111 1111 1111`, and
`4111111111111111` all produce the same hash.

### Persistence Format

```json
{
  "version": 1,
  "salt": "base64-encoded-salt==",
  "tokenizers": ["numeric", "email"],
  "categories": {
    "employee_ssn": ["a1b2c3d4...", "f3e4d5c6..."],
    "customer_cc": ["7890abcd...", "ef012345..."]
  }
}
```

### API Reference

```python
# Module: dlpscan.edm

class ExactDataMatcher:
    def __init__(salt=None, tokenizers=None, normalize=None)
    def register_values(category: str, values: Iterable[str]) -> int
    def register_tokenizer(name: str, func: Callable) -> None
    def scan(text: str, categories=None) -> List[EDMMatch]
    def check_value(value: str, category=None) -> bool
    def save(path: str) -> None
    @classmethod
    def load(path: str) -> ExactDataMatcher
    def clear(category=None) -> None
    @property
    def categories(self) -> List[str]
    @property
    def total_hashes(self) -> int

class EDMMatch:
    value_hash: str       # Truncated HMAC-SHA256 hash
    category: str         # Category of the matched value
    span: Tuple[int, int] # Position in text
    matched_text: str     # The raw text that matched
    confidence: float     # Always 1.0 for EDM matches
    def to_dict() -> dict
```

---

## Locality-Sensitive Hashing (LSH)

### What It Does

Detects documents that are **similar** to known sensitive documents, even after
editing, reformatting, cropping, or partial paraphrasing. Unlike pattern
matching (which finds specific data types), LSH operates at the document level.

### The Problem It Solves

A confidential contract might be leaked by copying it, changing a few words,
and reformatting it. Standard hashing (SHA-256) would produce a completely
different hash for even a single character change. Pattern matching wouldn't
catch it because the document doesn't necessarily contain patterns like SSNs.

### How It Works

1. **Shingling**: Break documents into overlapping word 3-grams (shingles):
   ```
   "the quick brown fox jumps"
   → {"the quick brown", "quick brown fox", "brown fox jumps"}
   ```

2. **MinHash**: Generate a compact signature (128 hash values) that approximates
   the Jaccard similarity of shingle sets. Documents with similar content
   produce similar signatures.
   ```
   Jaccard(A, B) = |A ∩ B| / |A ∪ B|

   Document A: 1000 shingles
   Document B: 950 shingles (edited copy)
   Overlap: 800 shingles
   Jaccard ≈ 800/1150 ≈ 0.70

   MinHash signature (128 values) estimates this Jaccard in O(1).
   ```

3. **LSH Banding**: Split the 128-hash signature into 16 bands of 8 rows.
   Documents that share ANY band hash are candidate near-duplicates. This
   gives sub-linear query time — you don't compare against every document.

4. **Verification**: For each candidate, compute the exact estimated Jaccard
   from the full 128-hash signatures. Only report matches above the threshold.

```
Registration:
  "This is a confidential contract about project Alpha..."
  → 500 shingles → MinHash signature [h1, h2, ..., h128]
  → 16 band hashes → inserted into 16 hash tables

Query:
  "This is a confidential contract about project Alpha with minor edits..."
  → 480 shingles → MinHash signature [h1', h2', ..., h128']
  → 16 band hashes → check against 16 hash tables
  → Candidate: "contract_v1" (shares 12 of 16 bands)
  → Verify: Jaccard ≈ 0.85 ≥ threshold (0.80)
  → MATCH: SimilarityMatch(doc_id="contract_v1", similarity=0.85)
```

### Usage

```python
from dlpscan import DocumentVault

# Create vault with 80% similarity threshold
vault = DocumentVault(threshold=0.8)

# Register known sensitive documents
vault.register("contract_v1", contract_text, sensitivity="confidential")
vault.register("employee_handbook", handbook_text, sensitivity="internal")
vault.register("source_code_auth", auth_module_text, sensitivity="proprietary")

# Query incoming text for similarity
matches = vault.query(suspicious_email_text)
for m in matches:
    print(f"Similar to {m.doc_id}: {m.similarity:.0%} "
          f"(sensitivity: {m.sensitivity})")

# Quick boolean check
if vault.contains_similar(outgoing_email):
    block_and_alert()

# Persistence
vault.save("sensitive_docs_vault.json")
vault = DocumentVault.load("sensitive_docs_vault.json")
```

### Tuning Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `num_hashes` | 128 | More hashes = more accurate similarity estimate |
| `bands` | 16 | More bands = catches lower-similarity matches |
| `threshold` | 0.8 | Minimum Jaccard similarity to report as match |
| `shingle_size` | 3 | Words per shingle. Smaller = more sensitive to edits |

**Threshold tuning guide:**

| Threshold | Use Case |
|-----------|----------|
| 0.9+ | Near-exact copies (reformatting only) |
| 0.8 | Default — catches moderate edits |
| 0.6-0.7 | Catches significant paraphrasing |
| 0.5 | Aggressive — may produce false positives |
| <0.5 | Not recommended (too many false positives) |

**Memory usage:** ~1 KB per registered document (128 x 8-byte hashes + metadata).
10,000 documents ≈ 10 MB.

### API Reference

```python
# Module: dlpscan.lsh

class DocumentVault:
    def __init__(num_hashes=128, bands=16, threshold=0.8, shingle_size=3)
    def register(doc_id: str, text: str, sensitivity="sensitive",
                 metadata=None) -> None
    def unregister(doc_id: str) -> bool
    def query(text: str, threshold=None) -> List[SimilarityMatch]
    def contains_similar(text: str, threshold=None) -> bool
    def save(path: str) -> None
    @classmethod
    def load(path: str) -> DocumentVault
    def clear() -> None
    @property
    def document_count(self) -> int
    @property
    def threshold(self) -> float

class SimilarityMatch:
    doc_id: str           # ID of the matching document
    similarity: float     # Estimated Jaccard similarity (0.0-1.0)
    sensitivity: str      # Sensitivity label
    doc_metadata: dict    # Custom metadata
    def to_dict() -> dict
```

---

## Count-Min Sketch

### What It Does

Probabilistic frequency estimation using constant memory. Answers "how many
times has X been seen?" without storing individual items.

### DLP Use Case

Threshold-based alerting: "flag any channel where >50 SSNs have passed in
the last hour." Uses ~280 KB regardless of traffic volume.

### How It Works

A `width × depth` grid of counters with `depth` independent hash functions.
Each `increment(key)` increments one counter per row. `estimate(key)` returns
the minimum across all rows — guaranteed ≥ true count (never undercounts) but
may overcount due to hash collisions.

### Usage

```python
from dlpscan import CountMinSketch

cms = CountMinSketch(width=10000, depth=7)
cms.increment("user:123:ssn")
cms.increment("user:123:ssn")
print(cms.estimate("user:123:ssn"))  # 2

# Merge distributed sketches
other = CountMinSketch(width=10000, depth=7)
other.increment("user:123:ssn", 5)
cms.merge(other)
print(cms.estimate("user:123:ssn"))  # 7
```

### Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `width` | 10,000 | More = less overcount |
| `depth` | 7 | More = higher confidence |

**Memory:** `width × depth × 4` bytes (32-bit counters). Default: ~280 KB.

### API Reference

```python
class CountMinSketch:
    def __init__(width=10000, depth=7)
    def increment(key: str, count=1) -> None
    def estimate(key: str) -> int
    def merge(other: CountMinSketch) -> None
    def clear() -> None
    @property total -> int
    @property width -> int
    @property depth -> int
```

---

## HyperLogLog

### What It Does

Estimates the number of *unique* items in a stream using ~1.5 KB of memory,
regardless of volume (even billions of items).

### DLP Use Case

Detect mass exfiltration: "if 10,000 unique confidential file hashes pass
through the firewall in an hour, trigger lockdown." All using <2 KB.

### How It Works

Hashes each item to a 64-bit value. Uses the first `p` bits as a register
index, counts leading zeros in the remaining bits, and stores the maximum
per register. The harmonic mean across all registers estimates cardinality.

### Usage

```python
from dlpscan import HyperLogLog

hll = HyperLogLog(precision=14)
for record in stream:
    hll.add(record)
print(f"~{hll.count()} unique records")

# Merge distributed estimators
other = HyperLogLog(precision=14)
hll.merge(other)
```

### Parameters

| Precision | Registers | Memory | Standard Error |
|-----------|-----------|--------|----------------|
| 10 | 1,024 | 1 KB | ±3.25% |
| 12 | 4,096 | 4 KB | ±1.63% |
| 14 | 16,384 | 16 KB | ±0.81% |
| 16 | 65,536 | 64 KB | ±0.41% |

### API Reference

```python
class HyperLogLog:
    def __init__(precision=14)
    def add(value: str) -> None
    def count() -> int
    def merge(other: HyperLogLog) -> None
    def clear() -> None
    @property precision -> int
    @property memory_bytes -> int
    @property standard_error -> float
```

---

## Cuckoo Filter

### What It Does

Space-efficient probabilistic set with deletion support. Like a Bloom filter,
but you can remove items.

### DLP Use Case

Memory-efficient alternative to Python `set()` for EDM hash lookups. 100K
items in ~150 KB vs ~6.4 MB for a Python set of 64-char hex strings. Supports
dynamic add/remove without rebuilding.

### How It Works

Stores tiny fingerprints in buckets using cuckoo hashing. Each item maps to
two candidate buckets. If both are full, an existing fingerprint is evicted
to its alternate bucket (cuckoo displacement), up to `max_kicks` attempts.

### Usage

```python
from dlpscan import CuckooFilter

cf = CuckooFilter(capacity=100000, fingerprint_bits=16)
cf.insert("secret-value-hash")
cf.contains("secret-value-hash")  # True
cf.delete("secret-value-hash")    # True
cf.contains("secret-value-hash")  # False
```

### False Positive Rates

| fingerprint_bits | bucket_size=4 FP Rate |
|------------------|----------------------|
| 8 | ~3.1% |
| 12 | ~0.19% |
| 16 | ~0.012% |
| 32 | ~0.00000006% |

### API Reference

```python
class CuckooFilter:
    def __init__(capacity=100000, bucket_size=4, fingerprint_bits=16, max_kicks=500)
    def insert(item: str) -> bool
    def contains(item: str) -> bool
    def delete(item: str) -> bool
    def clear() -> None
    @property count -> int
    @property capacity -> int
    @property load_factor -> float
    @property memory_bytes -> int
```

---

## Session Correlator

### What It Does

Tracks cumulative data exposure across scans, users, and time windows.
Catches insiders who leak small amounts of data over long periods.

### DLP Use Case

"An employee can email up to 5 customer IDs per day, but flag anyone sending
more than 50 in aggregate." Pattern matching catches each individual ID;
session correlation catches the pattern of abuse.

### How It Works

Combines Count-Min Sketch (frequency estimation) and HyperLogLog (cardinality
estimation) to track per-user, per-category exposure over sliding time windows.
Policies define thresholds; alerts fire when exceeded.

### Usage

```python
from dlpscan import SessionCorrelator

correlator = SessionCorrelator(window_seconds=3600)
correlator.set_policy("Credit Card Numbers", max_total=50, max_unique=20)

# After each scan:
alerts = correlator.record_scan(scan_result, user_id="user@company.com")
for alert in alerts:
    print(f"ALERT: {alert.alert_type} — {alert.user_id} "
          f"({alert.count}/{alert.limit} {alert.category})")

# User-specific stats
stats = correlator.get_user_stats("user@company.com")
print(f"Total matches: {stats.total_matches}")
```

### Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `window_seconds` | 3600 | Monitoring window duration |
| `cms_width` | 50,000 | CMS accuracy |
| `cms_depth` | 7 | CMS confidence |
| `hll_precision` | 12 | HLL accuracy |

### API Reference

```python
class SessionCorrelator:
    def __init__(window_seconds=3600, cms_width=50000, cms_depth=7, hll_precision=12)
    def set_policy(category, max_total=0, max_unique=0, user_pattern="*", action="alert")
    def record_scan(scan_result, user_id, source=None) -> List[CorrelationAlert]
    def record_matches(matches, user_id) -> List[CorrelationAlert]
    def get_user_stats(user_id) -> Optional[SessionStats]
    def estimate_total(user_id, category) -> int
    def estimate_unique(user_id) -> int
    def reset() -> None
    @property window_seconds -> int
    @property window_remaining -> float
    @property total_alerts -> int
    @property active_users -> int
    @property policies -> List[Policy]
```

---

## Rabin-Karp Rolling Hash

### What It Does

Detects when fragments of sensitive documents appear in outgoing text. Unlike
LSH (whole-document similarity), Rabin-Karp catches someone copying specific
paragraphs from a classified document.

### DLP Use Case

An employee copies 3 crucial paragraphs from a 100-page confidential contract
into an email. Pattern matching won't catch it (no SSNs). LSH might miss it
(only 3% of the document). Rolling hash catches the exact fragment match.

### How It Works

1. **Registration**: For each sensitive document, compute a Rabin-Karp rolling
   hash for every sliding window position. Store `hash → (doc_id, position, text)`
   in an index.

2. **Scanning**: Compute the same rolling hash over incoming text. For each
   hash match, verify the text slice to eliminate hash collisions.

### Usage

```python
from dlpscan import PartialDocumentMatcher

matcher = PartialDocumentMatcher(window_size=50)
matcher.register("contract_v1", contract_text)
matcher.register("source_auth", auth_module_code)

hits = matcher.scan("Email with copied contract text...")
for hit in hits:
    print(f"Fragment from {hit.doc_id} at position {hit.doc_position}")

# Quick check
if matcher.contains_fragment(outgoing_email):
    block_and_alert()
```

### Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `window_size` | 50 | Chars per window. Smaller = catches shorter fragments but more FPs |
| `normalize` | True | Lowercase + collapse whitespace before hashing |

**Memory:** ~40 bytes per window position per registered document. A 10,000-char
document with window_size=50 produces ~10,000 hashes ≈ 400 KB.

### API Reference

```python
class PartialDocumentMatcher:
    def __init__(window_size=50, normalize=True)
    def register(doc_id: str, text: str) -> int
    def unregister(doc_id: str) -> bool
    def scan(text: str, min_consecutive=1) -> List[FragmentMatch]
    def contains_fragment(text: str) -> bool
    def clear() -> None
    @property document_count -> int
    @property fingerprint_count -> int
    @property window_size -> int
```

---

## Entropy Analysis & Recursive Unpacking

### What It Does

Detects encrypted, compressed, or obfuscated payloads by computing Shannon
entropy. Recursively extracts nested archives (ZIP, tar, gzip) before scanning.

### DLP Use Case

An attacker compresses sensitive data into a nested ZIP, renames it .docx,
and emails it. Entropy analysis detects that the file has suspiciously high
randomness for a document file. Recursive unpacking cracks open the archive
layers and scans the contents.

### How It Works

**Entropy Analysis:**
- Computes Shannon entropy (0.0-8.0 bits/byte) of file content
- Format-specific thresholds: a .txt file at 7.5 entropy is suspicious;
  a .zip file at 7.5 is normal
- Classifications: normal, moderately_random, compressed_or_encrypted,
  likely_encrypted, suspicious_for_format

**Recursive Unpacking:**
- Detects ZIP, tar, gzip formats
- Extracts each layer, analyzes entropy at each depth
- Zip bomb protection: checks claimed size before extracting
- Configurable max depth (default 5) and max total size (default 500 MB)

### Usage

```python
from dlpscan import EntropyAnalyzer, RecursiveExtractor

# Analyze a file's entropy
analyzer = EntropyAnalyzer()
result = analyzer.analyze_file("suspicious.docx")
if result.is_suspicious:
    print(f"High entropy ({result.entropy:.2f}): {result.classification}")

# Recursively extract and scan nested archives
with RecursiveExtractor() as extractor:
    for item in extractor.extract("nested_archive.zip"):
        print(f"{item.original_name} (depth {item.depth}): "
              f"entropy={item.entropy:.2f} {item.classification}")
```

### Expected Entropy by Format

| Format | Normal Range | Suspicious Above |
|--------|-------------|------------------|
| .txt, .csv, .log | 3.0 – 5.5 | 6.0 |
| .json, .xml, .html | 3.5 – 5.5 | 6.0 |
| .pdf | 5.0 – 7.8 | 8.0+ |
| .docx, .xlsx, .zip | 7.0 – 8.0 | N/A (naturally high) |
| .gz | 7.5 – 8.0 | N/A |

### API Reference

```python
class EntropyAnalyzer:
    def __init__(threshold=7.5, sample_size=8192)
    @staticmethod shannon_entropy(data: bytes) -> float
    def analyze_bytes(data, format_hint=None) -> EntropyResult
    def analyze_file(path: str) -> EntropyResult

class RecursiveExtractor:
    def __init__(max_depth=5, max_total_size=500*1024*1024, entropy_threshold=7.5)
    def extract(path: str) -> List[ExtractedItem]
    def cleanup() -> None
    # Context manager support (__enter__/__exit__)
```

---

## Benchmark Results

Benchmarks comparing the Regex and Aho-Corasick context matching backends.
Run on Python 3.11 with `pyahocorasick` 2.3.0 (C extension).

### Throughput

| Text Size | Backend | Avg (ms) | Ops/sec | MB/s |
|-----------|---------|----------|---------|------|
| 1 KB (normal density) | regex | 6.7 | 149 | 0.15 |
| 1 KB (normal density) | ahocorasick | 6.6 | 151 | 0.15 |
| 10 KB (normal density) | regex | 71.9 | 13.9 | 0.14 |
| 10 KB (normal density) | ahocorasick | 72.6 | 13.8 | 0.13 |
| 100 KB (normal density) | regex | 974 | 1.0 | 0.10 |
| 100 KB (normal density) | ahocorasick | 966 | 1.0 | 0.10 |
| 1 MB (normal density) | regex | 10,134 | 0.1 | 0.10 |
| 1 MB (normal density) | ahocorasick | 10,142 | 0.1 | 0.10 |
| 10 KB (high density) | regex | 256 | 3.9 | 0.04 |
| 10 KB (high density) | ahocorasick | 248 | 4.0 | 0.04 |
| 100 KB (high density) | regex | 3,460 | 0.3 | 0.03 |
| 100 KB (high density) | ahocorasick | 3,324 | 0.3 | 0.03 |

### Key Observations

1. **Throughput parity**: Both backends are within 1-4% of each other on all
   text sizes. The 560 regex `finditer()` calls dominate scan time, not context
   matching.

2. **Dense text advantage**: Aho-Corasick shows a consistent 3-4% advantage on
   high-density texts (many matches). This is because the single-pass hit index
   is shared across all pattern matches, while the regex backend runs a separate
   context search per match.

3. **Accuracy**: Both backends produce identical matches on most texts. Minor
   differences in overlap deduplication occur on large texts where Aho-Corasick
   finds additional context hits (it performs a more comprehensive single-pass
   search vs. the regex backend's per-match windowed search).

4. **Scaling projection**: The Aho-Corasick advantage grows with:
   - More context keywords (currently 2,531 — at 10,000+ the gap widens)
   - Higher match density (more context checks per scan)
   - Batch processing (automaton built once, reused across scans)

### When to Use Each

| Scenario | Recommended Backend |
|----------|-------------------|
| Default / simple use | `regex` (zero dependencies) |
| Small texts (<10 KB) | Either (equivalent performance) |
| Large documents (>100 KB) | `ahocorasick` (slight advantage) |
| High match density | `ahocorasick` (3-4% faster) |
| Batch file processing | `ahocorasick` (amortized build cost) |
| Custom keyword sets (>5,000) | `ahocorasick` (single pass scales better) |
| No external dependencies | `regex` (stdlib only) |
| Maximum compatibility | `regex` (no C extension needed) |

### Running Benchmarks

```bash
# Full comparison suite
python tests/bench_context_backends.py

# Machine-readable JSON output
python tests/bench_context_backends.py --json

# General performance benchmarks
python tests/benchmarks.py
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Input Text                                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────┐                                            │
│  │ Unicode Normalize    │  Stage 1: Strip zero-width chars          │
│  │ (unicode_normalize)  │  Stage 2: Normalize whitespace            │
│  │                      │  Stage 3: Map homoglyphs to ASCII         │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Pattern Matching     │  560 compiled regex patterns               │
│  │ (scanner.py)         │  126 categories, finditer() per pattern   │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────────────────────────────────────────┐        │
│  │ Context Matching (configurable backend)                  │        │
│  │                                                          │        │
│  │  ┌─────────────────────┐  ┌──────────────────────────┐  │        │
│  │  │ REGEX (default)      │  │ AHO-CORASICK (opt-in)   │  │        │
│  │  │                      │  │                          │  │        │
│  │  │ 560 compiled         │  │ Single O(n) trie pass   │  │        │
│  │  │ alternation patterns │  │ ContextHitIndex with     │  │        │
│  │  │ Per-match regex      │  │ binary search lookups    │  │        │
│  │  │ search in window     │  │                          │  │        │
│  │  └──────────┬───────────┘  └────────────┬─────────────┘  │        │
│  │             │                           │                │        │
│  │             └─────────┬─────────────────┘                │        │
│  │                       │                                  │        │
│  │             ┌─────────▼───────────┐                      │        │
│  │             │ Fuzzy Levenshtein    │  Edit distance ≤ 2  │        │
│  │             │ (fallback for both)  │  Keywords ≥ 5 chars │        │
│  │             └─────────────────────┘                      │        │
│  └──────────────────────────────────────────────────────────┘        │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Confidence Scoring   │  Base specificity + context boost         │
│  │ Deduplication        │  Overlap removal, highest confidence wins │
│  │ Plugin Validators    │  Custom match validation                  │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Match Output         │  List[Match] with spans, confidence       │
│  └─────────────────────┘                                            │
│                                                                      │
│  ── Parallel / Independent Modules ──                               │
│                                                                      │
│  ┌─────────────────────┐  ┌─────────────────────┐                   │
│  │ EDM (edm.py)         │  │ LSH (lsh.py)         │                  │
│  │ Salted HMAC-SHA256   │  │ MinHash signatures   │                  │
│  │ Known-value matching │  │ Document similarity   │                  │
│  │ Zero false positives │  │ LSH band indexing     │                  │
│  └──────────────────────┘  └──────────────────────┘                  │
│                                                                      │
│  ┌─────────────────────┐  ┌─────────────────────┐                   │
│  │ Rabin-Karp           │  │ Entropy Analyzer     │                  │
│  │ (rabin_karp.py)      │  │ (entropy.py)         │                  │
│  │ Rolling hash partial │  │ Shannon entropy +    │                  │
│  │ document matching    │  │ recursive unpacking  │                  │
│  └──────────────────────┘  └──────────────────────┘                  │
│                                                                      │
│  ┌─────────────────────┐  ┌─────────────────────┐                   │
│  │ Session Correlator   │  │ Probabilistic DS     │                  │
│  │ (session.py)         │  │                      │                  │
│  │ Drip exfiltration    │  │ CountMinSketch       │                  │
│  │ CMS + HLL + policy   │  │ HyperLogLog          │                  │
│  │ Per-user tracking    │  │ CuckooFilter          │                  │
│  └──────────────────────┘  └──────────────────────┘                  │
└──────────────────────────────────────────────────────────────────────┘
```

**Independent modules** — these don't replace or modify the core pattern
matching pipeline. They provide complementary detection capabilities:

- **Pattern matching**: "Find anything that looks like a credit card"
- **EDM**: "Find these exact 50,000 known credit card numbers"
- **LSH**: "Find documents similar to this confidential contract"
- **Rabin-Karp**: "Detect copied paragraphs from sensitive documents"
- **Entropy**: "Flag files with suspicious randomness levels"
- **Session Correlator**: "Catch slow drip exfiltration over time"
- **CMS / HLL / Cuckoo**: Building blocks for the above + custom use

Use them together for defense in depth.
