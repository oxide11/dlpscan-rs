# Batch Scanning

Scan CSV, JSON, databases, and DataFrames at scale with parallel processing.

## Basic Usage

```python
from dlpscan.batch import BatchScanner

scanner = BatchScanner(max_workers=4)

# Scan multiple texts
results = scanner.scan_texts([
    "Card: 4111111111111111",
    "SSN: 123-45-6789",
    "Clean text here",
])

report = BatchScanner.summarize(results)
print(f"Found {report.total_findings} findings in {report.items_with_findings} items")
```

## CSV Scanning

```python
results = scanner.scan_csv("customers.csv", columns=["name", "email", "notes"])
```

## JSON / JSONL Scanning

```python
results = scanner.scan_json("events.jsonl", fields=["message", "user_input"])
```

## Database Scanning

```python
# SQLite (stdlib)
results = scanner.scan_database(
    "sqlite:///app.db",
    "SELECT name, email, notes FROM customers",
    columns=["name", "email", "notes"],
)
```

## DataFrame Scanning

```python
import pandas as pd
df = pd.read_csv("data.csv")
results = scanner.scan_dataframe(df, columns=["email", "phone"])
```

## Progress Tracking

```python
scanner = BatchScanner(
    max_workers=4,
    on_progress=lambda done, total: print(f"{done}/{total}"),
    on_result=lambda r: print(f"{r.source_id}: {r.scan_result.finding_count} findings"),
)
```

## Chunked Processing

Large datasets are processed in chunks (default 1000) to limit memory:

```python
scanner = BatchScanner(chunk_size=500)
```
