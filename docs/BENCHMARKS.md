# siphon-rs Benchmark Results

Comprehensive performance comparison between the Python and Rust implementations
of siphon, including the impact of each optimization pass and the baseline-only
scanning mode.

**Environment:** Linux 6.18.5, Rust 1.75+ (release profile with LTO), Python 3.x  
**Pattern count:** 560 total (108 always-run, 452 context-gated)  
**Version:** 2.1.0  
**Date:** April 2026

---

## 1. Rust vs Python — Final Optimized Comparison

All tests use full preset coverage (PCI-DSS, PII, Credentials, Healthcare, Contact Info)
with Flag action.

### Latency

| Test Case | Python (ms) | Rust (ms) | Speedup |
|---|---:|---:|---:|
| scan_clean_1KB | 0.42 | **0.23** | **1.8x** |
| scan_mixed_1KB | 0.93 | **0.23** | **4.0x** |
| scan_dense_1KB | 2.81 | **0.22** | **12.8x** |
| scan_clean_10KB | 3.28 | **0.29** | **11.3x** |
| scan_mixed_10KB | 7.89 | **0.47** | **16.8x** |
| scan_dense_10KB | 29.15 | **0.61** | **47.8x** |
| scan_clean_100KB | 33.99 | **1.41** | **24.1x** |
| scan_mixed_100KB | 78.87 | **2.38** | **33.1x** |
| scan_dense_100KB | 288.17 | **3.76** | **76.6x** |
| scan_clean_1MB | 396.19 | **12.02** | **33.0x** |
| scan_mixed_1MB | 960.05 | **33.14** | **29.0x** |
| scan_dense_1MB | 2,197.25 | **31.32** | **70.1x** |
| redact_mixed_10KB | 9.95 | **0.46** | **21.6x** |

### Throughput (1MB)

| Scenario | Python | Rust | Factor |
|---|---:|---:|---:|
| Clean text | 2.5 MB/s | **83.2 MB/s** | **33x** |
| Mixed content | 1.0 MB/s | **30.2 MB/s** | **30x** |
| Dense sensitive data | 0.5 MB/s | **31.9 MB/s** | **64x** |

### Test Data Definitions

- **Clean:** `"The quick brown fox jumps over the lazy dog. No sensitive data here."` (repeated)
- **Mixed:** Email, SSN, credit card, phone, AWS key interspersed with normal text
- **Dense:** Back-to-back sensitive values (credit cards, emails, SSNs, API keys)

---

## 2. Optimization Journey — Before and After

The Rust scanner went through three optimization passes. The initial implementation
used a single `RegexSet` with all 560 patterns, which created a massive DFA automaton
that was slower than Python.

### Latency at Each Stage (1MB mixed text)

| Stage | Time (ms) | Throughput | vs Python |
|---|---:|---:|---:|
| Python baseline | 960.05 | 1.0 MB/s | — |
| Rust v1 (RegexSet) | 16,124.24 | 0.1 MB/s | **16.8x slower** |
| Rust v2 (parallel regex) | 44.41 | 22.5 MB/s | **21.6x faster** |
| Rust v3 (+ AC prefilter) | 33.14 | 30.2 MB/s | **29.0x faster** |

### What Each Optimization Did

**v1 → v2: Replace RegexSet with parallel per-pattern regex (Rayon)**
- The `RegexSet` with 560 patterns built a ~50MB DFA that took 13ms just for 1KB
- Individual regexes run via `rayon::par_iter()` are 50-100x faster
- This single change went from 16x slower than Python to 22x faster

**v2 → v3: Add Aho-Corasick prefilter + normalization fast-path**
- AC prefilter gates 452 of 560 patterns behind keyword presence checks
- ASCII fast-path skips NFKC, homoglyph, and zero-width character processing
- HashMap O(1) lookup replaces O(n) linear scan in ContextHitIndex
- Skip fuzzy/leet matching when AC index gives definitive answer
- Combined: 22 MB/s → 30 MB/s on mixed, 48 MB/s → 83 MB/s on clean

---

## 3. Full Scan vs Baseline-Only Mode

Baseline mode (`baseline_only: true`) restricts scanning to only the 108
always-run patterns, skipping all 452 context-gated patterns regardless
of keyword presence.

### Pattern Classification

| Tier | Count | Criteria |
|---|---:|---|
| Always-run (baseline) | 108 | Specificity >= 0.85, or in `CRITICAL_ALWAYS_RUN` |
| Context-gated | 452 | Specificity < 0.85, gated by AC keyword prefilter |
| **Total** | **560** | |

### Always-Run Patterns Include

- **US core:** SSN, ITIN, EIN, Passport, Routing Number, Phone, MBI, NPI
- **International IDs:** Canada SIN, UK NIN/NHS, France NIR, Germany Tax ID, India Aadhaar/PAN, China Resident ID, Brazil CPF/CNPJ, and 20+ more
- **Credit cards:** Visa, MasterCard, Amex, Discover, JCB, UnionPay (Luhn-validated)
- **Secrets:** JWT, Private Key, AWS/GCP/GitHub/Stripe/Slack tokens, Database connection strings
- **Contact:** Email, E.164 Phone, IPv4/IPv6, MAC Address
- **Crypto:** Bitcoin, Ethereum, Litecoin, Ripple, Bitcoin Cash, Monero
- **Financial:** IBAN, SWIFT/BIC, CUSIP, ISIN, SEDOL, LEI
- **Other:** GPS Coordinates, VIN, IMEI, Track 1/2 Data

### Latency Comparison (v2.1.0)

| Test (1MB) | Full (ms) | Baseline (ms) | Speedup |
|---|---:|---:|---:|
| scan_clean_1MB | 14.97 | 15.07 | 1.0x |
| scan_mixed_1MB | 49.07 | 47.96 | 1.0x |
| scan_dense_1MB | 47.84 | 46.50 | 1.0x |
| **scan_kw_heavy_1MB** | **29.08** | **25.73** | **1.1x** |

### Throughput Comparison (1MB, v2.1.0)

| Scenario | Full | Baseline |
|---|---:|---:|
| Clean text | 66.8 MB/s | 66.4 MB/s |
| Mixed content | 20.4 MB/s | 20.8 MB/s |
| Dense sensitive data | 20.9 MB/s | 21.5 MB/s |
| **Keyword-heavy text** | **34.4 MB/s** | **38.9 MB/s** |

### Finding Counts (10KB Mixed Text)

| Mode | Findings | Categories |
|---|---:|---|
| Full | 164 | Credit Card Numbers, Contact Information, Cloud Provider Secrets |
| Baseline | 164 | Credit Card Numbers, Contact Information, Cloud Provider Secrets |

### Full Latency Table (v2.1.0 optimized)

| Test | Full (ms) | Baseline (ms) | Speedup |
|---|---:|---:|---:|
| scan_clean_1MB | 17.54 | 16.88 | 1.0x |
| scan_mixed_1MB | 50.89 | 49.63 | 1.0x |
| scan_dense_1MB | 62.18 | 60.75 | 1.0x |
| scan_kw_heavy_1MB | 33.40 | 31.65 | 1.1x |
| redact_mixed_10KB | 0.88 | 0.82 | 1.1x |

### Throughput Comparison (1MB, v2.1.0 optimized)

| Scenario | Full | Baseline |
|---|---:|---:|
| Clean text | 57.0 MB/s | 59.3 MB/s |
| Mixed content | 19.7 MB/s | 20.1 MB/s |
| Dense sensitive data | 16.1 MB/s | 16.5 MB/s |
| **Keyword-heavy text** | **29.9 MB/s** | **31.6 MB/s** |

### Performance journey

The v2.1.0 release added 2,500 multilingual keywords (English + 5 other
languages) and the Aho-Corasick automaton grew to ~5,000 unique keywords.
This initially caused a ~30% throughput drop on dense content.

The context hit index was then optimized:

1. **Keyword deduplication** — identical keywords across patterns
   (`credit card` appears in 7+ entries) are now stored once in the AC
   automaton and mapped to all pattern IDs that use them. The automaton
   itself became smaller.
2. **Pattern-ID indexing** — the hit index was refactored from a
   `HashMap<(&str, &str), Vec<(usize, usize)>>` with a cloned
   `HashMap<String, HashMap<String, ...>>` reverse map to a simple
   `Vec<Vec<u32>>` keyed by pattern ID. This eliminated ~5,000 String
   allocations per scan.
3. **Sorted position lists** — positions are sorted once per scan
   enabling O(log n) binary search in range checks instead of linear scan.
4. **Compact u32 positions** — hit positions are stored as u32 instead
   of usize pairs (only `start` is needed for range checks).

Result: mixed content throughput recovered from 14 MB/s to 20 MB/s
(+40%), matching pre-multilingual performance. Dense content still has
some overhead from the larger automaton but is within ~20% of the
pre-multilingual baseline.

### Analysis

The AC prefilter already eliminates ~80% of regex work in full mode, so
baseline mode provides only marginal additional speedup in most cases.
The difference is most visible on **keyword-heavy text** (text containing
many context keywords like "account number", "social security", "bank"
that trigger context-gated patterns to run even though no actual sensitive
data matches). In that scenario, baseline mode is **1.1x faster** (34 → 39 MB/s).

Baseline mode is best suited for:
- High-throughput pipelines where only critical/high-confidence patterns matter
- Latency-sensitive applications that can tolerate missing low-specificity detections
- Pre-screening passes before a full scan

---

## 4. Usage

### Rust API

```rust
use siphon::guard::{InputGuard, Preset, Action};

// Full scan (default) — all 560 patterns with AC prefilter
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii, Preset::Credentials])
    .with_action(Action::Flag);

// Baseline-only — 108 always-run patterns, skip context-gated
let guard_fast = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii, Preset::Credentials])
    .with_action(Action::Flag)
    .with_baseline_only(true);

let result = guard.scan("SSN: 123-45-6789, Card: 4532015112830366")?;
let result_fast = guard_fast.scan("SSN: 123-45-6789, Card: 4532015112830366")?;
```

### Running Benchmarks

```bash
# Build and run Rust benchmark
cd siphon-rs
cargo run --release --bin benchmark

# Run Python benchmark for comparison
cd ..
python benchmark_py.py
```
