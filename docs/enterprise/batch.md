# Batch Scanning

Scan CSV, JSON, and JSONL files at scale.

## Basic Usage

```rust
use dlpscan::batch::BatchScanner;
use dlpscan::InputGuard;

let guard = InputGuard::new();
let scanner = BatchScanner::new(guard);

// Scan multiple texts — each item is a (source_id, text) pair
let results = scanner.scan_texts(&[
    ("item-1", "Card: 4111111111111111"),
    ("item-2", "SSN: 123-45-6789"),
    ("item-3", "Clean text here"),
]);

let duration_seconds = 0.5;
let report = BatchScanner::summarize(&results, duration_seconds);
println!(
    "Found {} findings in {} items",
    report.total_findings, report.items_with_findings
);
```

## CSV Scanning

```rust
let results = scanner.scan_csv(
    "customers.csv",
    &["name", "email", "notes"],  // columns to scan
    Some(','),                     // delimiter (None for default comma)
);
```

## JSON Scanning

```rust
let results = scanner.scan_json(
    "events.json",
    &["message", "user_input"],  // fields to extract and scan
);
```

## JSONL Scanning

```rust
let results = scanner.scan_jsonl(
    "events.jsonl",
    &["message", "user_input"],  // fields to extract and scan
);
```

## Summary Report

The `summarize` function takes the results and the elapsed duration in
seconds:

```rust
use std::time::Instant;

let start = Instant::now();
let results = scanner.scan_texts(&items);
let elapsed = start.elapsed().as_secs_f64();

let report = BatchScanner::summarize(&results, elapsed);
println!("Total items:    {}", report.total_items);
println!("With findings:  {}", report.items_with_findings);
println!("Total findings: {}", report.total_findings);
println!("Duration:       {:.2}s", report.duration_seconds);
```
