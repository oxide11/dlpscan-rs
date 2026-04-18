# Microservice Architecture

<p align="center">
  <img src="../assets/logo.png" alt="Polygon Siphon" width="200">
</p>

Polygon Siphon is designed as a family of specialized pods sharing a
common scanning core. Each pod handles one class of data ingestion;
the scanning logic is identical across all of them.

## Pods

```
                    ┌─────────────────┐
                    │   Siphon-Core   │
                    │  (Rust library) │
                    └────────┬────────┘
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼───────┐ ┌───▼────────┐ ┌───▼──────────┐
     │  Siphon-FS     │ │ Siphon-DS  │ │  Siphon-GW   │
     │  File Scanner  │ │ Data Stream│ │  Gateway     │
     │                │ │            │ │  Proxy       │
     │  PDF, DOCX,    │ │  Kafka     │ │              │
     │  archives,     │ │  consumer  │ │  HTTP/gRPC   │
     │  email, QR,    │ │  real-time │ │  inline scan │
     │  Parquet, ...  │ │  scanning  │ │  + forward   │
     └────────────────┘ └────────────┘ └──────────────┘
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Unified Finding │
                    │   Wire Format   │
                    │     (JSON)      │
                    └─────────────────┘
```

### Siphon-Core

The shared library. Contains the scanner engine, patterns, validators,
normalization pipeline, context matching, scoring, and all detection
logic. Zero file-format dependencies — operates on `&str` input only.

**Crate:** `siphon-core`

**Modules:**
- `scanner` — parallel regex matching with Rayon + AC prefilter
- `patterns` — 561 compiled patterns across 126 categories
- `validation` — 72 checksum validators
- `normalize` — 10-stage evasion defense pipeline
- `context` — Aho-Corasick keyword proximity matching
- `scoring` — confidence computation + dedup
- `models` — `Match`, `PatternDef`, specificity scores
- `guard` — `InputGuard` (scan/redact/tokenize/obfuscate)
- `edm` — exact data match (HMAC-SHA256)
- `lsh` — document similarity (MinHash)
- `policy` — TOML-based policy engine
- `compliance` — PCI-DSS/HIPAA/SOC2/GDPR reports
- `audit` — HMAC-signed audit logging

### Siphon-FS (File Scanner)

Batch and on-demand file processing. This is the current primary
binary — the CLI and HTTP API server.

**Crate:** `siphon-fs`

**Depends on:** `siphon-core` + `siphon-extractors`

**Responsibilities:**
- Text extraction from 20+ file formats (PDF, DOCX, XLSX, archives,
  email, QR codes, Parquet, SQLite)
- Directory traversal and recursive scanning
- Pipeline orchestration (extract → scan → report)
- CLI interface (`siphon scan`, `siphon scan-dir`)
- HTTP API server (optional, with `async-support` feature)
- SIEM forwarding and webhook notifications

**Protocols:** filesystem, HTTP API

### Siphon-DS (Data Stream)

Real-time stream scanning for event-driven architectures.

**Crate:** `siphon-ds`

**Depends on:** `siphon-core` (no extractors needed — messages are text)

**Responsibilities:**
- Kafka consumer group management
- Message deserialization (JSON, Avro, Protobuf)
- Scan each message through `siphon-core`
- Emit findings to a findings topic or SIEM
- Back-pressure handling and consumer lag monitoring
- Offset commit only after scan completes (at-least-once)

**Protocols:** Kafka, optionally Redis Streams, AMQP

### Siphon-GW (Gateway Proxy)

Inline HTTP/gRPC proxy that intercepts requests, scans the body,
and either forwards or blocks.

**Crate:** `siphon-gw`

**Depends on:** `siphon-core` (no extractors — bodies are text/JSON)

**Responsibilities:**
- Reverse proxy (accept → scan body → forward or reject)
- gRPC request/response interception
- Streaming body scan for large payloads
- Policy-based action (block, redact-and-forward, log-and-forward)
- Health check and readiness endpoints
- mTLS termination

**Protocols:** HTTP/1.1, HTTP/2, gRPC

### Siphon-Vision (Future)

OCR and ML-based document understanding. Deferred — this is a
fundamentally different problem (computer vision, not text matching).

**Responsibilities:**
- Image → text via OCR (Tesseract or cloud API)
- Document layout analysis
- Handwriting recognition
- Table extraction from scanned documents
- Classification model inference

## Crate Workspace Layout

```
polygon-siphon/
├── Cargo.toml              # workspace root
├── crates/
│   ├── siphon-core/        # scanner engine (no file I/O deps)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── scanner/
│   │       ├── patterns/
│   │       ├── validation.rs
│   │       ├── normalize/
│   │       ├── context/
│   │       ├── scoring.rs
│   │       ├── models.rs
│   │       ├── guard/
│   │       ├── edm.rs
│   │       ├── lsh.rs
│   │       ├── policy.rs
│   │       ├── compliance.rs
│   │       ├── audit.rs
│   │       └── ...
│   │
│   ├── siphon-extractors/  # file format handlers
│   │   ├── Cargo.toml      # pdf-extract, calamine, rxing, etc.
│   │   └── src/
│   │       └── lib.rs      # extract_text(), format detection
│   │
│   ├── siphon-fs/          # file scanner binary + HTTP API
│   │   ├── Cargo.toml      # depends on core + extractors
│   │   └── src/
│   │       ├── main.rs
│   │       └── pipeline.rs
│   │
│   ├── siphon-ds/          # Kafka consumer binary
│   │   ├── Cargo.toml      # depends on core + rdkafka
│   │   └── src/
│   │       └── main.rs
│   │
│   └── siphon-gw/          # gateway proxy binary
│       ├── Cargo.toml      # depends on core + hyper
│       └── src/
│           └── main.rs
│
├── tests/                  # shared integration tests
├── docs/
└── deploy/
    ├── helm/
    │   ├── siphon-fs/
    │   ├── siphon-ds/
    │   └── siphon-gw/
    └── docker/
        ├── Dockerfile.fs
        ├── Dockerfile.ds
        └── Dockerfile.gw
```

## Unified Finding Wire Format

Every pod emits findings in the same JSON schema. Downstream consumers
(SIEM, dashboards, alerting) don't need to know which pod produced a
finding.

```json
{
  "source_pod": "siphon-fs",
  "source_id": "file:///data/uploads/report.pdf",
  "timestamp": "2026-04-18T12:00:00Z",
  "findings": [
    {
      "category": "Credit Card Numbers",
      "sub_category": "Visa",
      "text": "4532****0366",
      "confidence": 0.95,
      "has_context": true,
      "span": [42, 58],
      "metadata": {
        "bin_brand": "Visa",
        "bin_country": "US"
      }
    }
  ],
  "scan_duration_ms": 12,
  "policy_action": "redact"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `source_pod` | string | `siphon-fs`, `siphon-ds`, `siphon-gw` |
| `source_id` | string | File path, Kafka topic:partition:offset, or request ID |
| `timestamp` | ISO 8601 | When the scan completed |
| `findings` | array | Same `Match` fields as the core scanner output |
| `scan_duration_ms` | int | Wall-clock scan time |
| `policy_action` | string | What the pod did: `flag`, `redact`, `block`, `forward` |

## Deployment

### Kubernetes

Each pod runs as an independent Deployment with its own HPA. They
share no state — all scanning is stateless. EDM and LSH state is
loaded at startup from a ConfigMap or mounted volume.

```
┌──────────────────────────────────────────────┐
│                 Kubernetes Cluster            │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │Siphon-FS │  │Siphon-DS │  │Siphon-GW │   │
│  │ replicas  │  │ replicas  │  │ replicas  │   │
│  │  1-10     │  │  1-50     │  │  2-20     │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │         │
│       └──────────────┼──────────────┘         │
│                      ▼                        │
│              ┌──────────────┐                 │
│              │   Findings   │                 │
│              │  Kafka Topic │                 │
│              │  or SIEM     │                 │
│              └──────────────┘                 │
└──────────────────────────────────────────────┘
```

**Scaling:**
- Siphon-FS: scale on CPU (extraction is CPU-bound)
- Siphon-DS: scale on consumer lag (Kafka partition count)
- Siphon-GW: scale on request rate (HPA on RPS)

### Helm

Each pod gets its own Helm chart under `deploy/helm/`. Common values
(core scanner config, policy, EDM state) are shared via a base chart
or ConfigMap.

## Migration Path

The workspace split is the prerequisite. The migration is incremental:

1. **Split the workspace** — move scanner logic to `siphon-core`,
   extractors to `siphon-extractors`, CLI/pipeline to `siphon-fs`.
   Everything still builds and tests pass. No new pods yet.

2. **Build Siphon-DS** — new crate that depends on `siphon-core` +
   `rdkafka`. Start with a single-topic consumer that scans JSON
   message bodies.

3. **Build Siphon-GW** — new crate that depends on `siphon-core` +
   `hyper`. Start with a simple reverse proxy that scans request
   bodies.

4. **Helm charts** — one chart per pod with shared ConfigMap for
   scanner config.

5. **Siphon-Vision** — separate repo, separate timeline. Integrates
   via the unified finding format.
