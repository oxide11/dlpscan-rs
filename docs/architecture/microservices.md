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
          ┌──────────────┬────────┴────────┬──────────────┐
          │              │                 │              │
  ┌───────▼──────┐ ┌────▼──────┐ ┌────────▼─────┐ ┌──────▼──────┐
  │  Siphon-FS   │ │ Siphon-API│ │  Siphon-DS   │ │  Siphon-GW  │
  │File Scanner  │ │Sync API   │ │ Stream Input │ │Inline Proxy │
  │              │ │           │ │              │ │             │
  │PDF, DOCX,    │ │POST /scan │ │Syslog,       │ │HTTP/gRPC    │
  │archives,     │ │gRPC scan  │ │Fluent,       │ │scan+forward │
  │email, QR,    │ │req/resp   │ │AMQP, Redis   │ │or block     │
  │Parquet, ...  │ │           │ │Streams, SQS  │ │             │
  └──────────────┘ └───────────┘ └──────────────┘ └─────────────┘
          │              │                 │              │
          └──────────────┴────────┬────────┴──────────────┘
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

Batch and on-demand file processing. Handles files on disk, in
archives, or from object storage (S3, GCS, Azure Blob).

**Crate:** `siphon-fs`

**Depends on:** `siphon-core` + `siphon-extractors`

**Responsibilities:**
- Text extraction from 20+ file formats (PDF, DOCX, XLSX, archives,
  email, QR codes, Parquet, SQLite)
- Directory traversal and recursive scanning
- Pipeline orchestration (extract → scan → report)
- CLI interface (`siphon scan`, `siphon scan-dir`)
- Bucket event triggers (S3 → scan new uploads)

**Ingestion:** filesystem, S3/GCS/Azure bucket events

### Siphon-API (Sync Scan Service)

Synchronous HTTP/gRPC endpoint. Apps POST text and receive findings
in the response. The simplest integration — no queue, no proxy, just
a function call over the network.

**Crate:** `siphon-api`

**Depends on:** `siphon-core`

**Responsibilities:**
- `POST /scan` — accept JSON body with text, return findings
- `POST /guard` — scan-and-redact in one call
- gRPC service with unary and streaming RPCs
- Per-tenant API key auth + rate limiting
- Request-level policy enforcement

**Ingestion:** HTTP/1.1, HTTP/2, gRPC

**Wire format:**
```http
POST /scan HTTP/1.1
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "text": "My SSN is 425-71-3482",
  "options": {
    "min_confidence": 0.5,
    "categories": ["National IDs", "Credit Card Numbers"]
  }
}

→ 200 OK
{
  "findings": [...],
  "scan_duration_ms": 3
}
```

### Siphon-DS (Data Stream)

Async consumer for event streams. Multi-protocol adapter — speaks
the stream sources your infrastructure already uses. No single
protocol is the default.

**Crate:** `siphon-ds`

**Depends on:** `siphon-core`

**Ingestion adapters** (pick the ones you need at build time):
- **Syslog** (RFC 5424 UDP/TCP) — most enterprise apps, firewalls,
  routers already emit syslog
- **Fluent forward** — drop-in for Kubernetes log pipelines running
  Fluent Bit or Fluentd
- **AMQP** — RabbitMQ, enterprise message buses
- **Redis Streams** — lightweight, reuses existing Redis deployments
- **AWS SQS / GCP Pub/Sub / Azure Service Bus** — managed cloud queues
- **NATS** — cloud-native pub/sub
- **Kafka** — optional adapter, not the default
- **MQTT** — IoT and lightweight pub/sub

Each adapter is a feature flag. The core DS binary is protocol-agnostic;
adapters are compiled in as needed.

**Responsibilities:**
- Subscribe to configured streams
- Deserialize messages (JSON, plain text, syslog, etc.)
- Scan message body through `siphon-core`
- Emit findings to a findings sink (SIEM, another stream, HTTP webhook)
- At-least-once semantics with offset/ack discipline
- Back-pressure handling and lag monitoring

### Siphon-GW (Inline Proxy)

Reverse proxy that intercepts HTTP/gRPC traffic in-flight. Scans the
request body, then forwards, blocks, or redacts based on policy.

**Crate:** `siphon-gw`

**Depends on:** `siphon-core`

**Responsibilities:**
- HTTP/1.1, HTTP/2, gRPC reverse proxy
- Streaming body scan for large payloads
- Policy action: `forward`, `block`, `redact-and-forward`, `log-and-forward`
- mTLS termination
- Upstream health checks and load balancing

**Ingestion:** HTTP/1.1, HTTP/2, gRPC (as a reverse proxy)

**Difference from Siphon-API:** API is request/response — the client
knows it's talking to a scanner. GW is transparent — the client doesn't
know its traffic is being scanned. GW has upstream forwarding, circuit
breakers, and proxy semantics that API doesn't need.

### Siphon-Vision (Future)

OCR and ML-based document understanding. Deferred — fundamentally
different problem (computer vision, not text matching).

**Responsibilities:**
- Image → text via OCR (Tesseract or cloud API)
- Document layout analysis
- Handwriting recognition
- Table extraction from scanned documents
- Classification model inference

## Which Pod Do I Use?

| Use case | Pod | Why |
|----------|-----|-----|
| Scan files on disk | FS | Has extractors |
| S3 bucket DLP monitoring | FS | Bucket events trigger file scan |
| App submits text, wants findings back | API | Sync HTTP call |
| Microservice needs scan during request processing | API (gRPC) | Low-latency RPC |
| Already running Fluent Bit in K8s | DS (fluent adapter) | Zero app changes |
| Enterprise apps emit syslog | DS (syslog adapter) | Zero app changes |
| RabbitMQ-based message bus | DS (amqp adapter) | Reuse existing infra |
| Outbound HTTP traffic monitoring | GW | Transparent interception |
| Air-gap blocking of egress | GW | `block` policy |
| Scanned documents / images | FS + Vision | Extract with OCR, then scan |

## Crate Workspace Layout

```
polygon-siphon/
├── Cargo.toml              # workspace root
├── crates/
│   ├── siphon-core/        # scanner engine (no file I/O deps)
│   ├── siphon-extractors/  # file format handlers
│   ├── siphon-fs/          # file scanner binary
│   ├── siphon-api/         # sync HTTP/gRPC scan service
│   ├── siphon-ds/          # multi-protocol stream consumer
│   └── siphon-gw/          # inline HTTP/gRPC proxy
├── tests/
├── docs/
└── deploy/
    ├── helm/
    │   ├── siphon-fs/
    │   ├── siphon-api/
    │   ├── siphon-ds/
    │   └── siphon-gw/
    └── docker/
        ├── Dockerfile.fs
        ├── Dockerfile.api
        ├── Dockerfile.ds
        └── Dockerfile.gw
```

## Unified Finding Wire Format

Every pod emits findings in the same JSON schema. Downstream consumers
(SIEM, dashboards, alerting) don't need to know which pod produced a
finding.

```json
{
  "source_pod": "siphon-api",
  "source_id": "req:7f3a9e2b-1c8d-4a5f-b6e9-0d3c4e5a7b2f",
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
| `source_pod` | string | `siphon-fs`, `siphon-api`, `siphon-ds`, `siphon-gw` |
| `source_id` | string | File path, request ID, stream offset, or connection ID |
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
┌──────────────────────────────────────────────────────┐
│                 Kubernetes Cluster                    │
│                                                       │
│  ┌────────┐  ┌─────────┐  ┌────────┐  ┌────────┐    │
│  │Siphon- │  │Siphon-  │  │Siphon- │  │Siphon- │    │
│  │  FS    │  │  API    │  │  DS    │  │  GW    │    │
│  │1-10    │  │2-50     │  │1-30    │  │2-20    │    │
│  └────┬───┘  └────┬────┘  └───┬────┘  └───┬────┘    │
│       │            │            │            │        │
│       └────────────┴────┬───────┴────────────┘        │
│                         ▼                             │
│                 ┌──────────────┐                      │
│                 │   Findings   │                      │
│                 │  Stream/SIEM │                      │
│                 └──────────────┘                      │
└──────────────────────────────────────────────────────┘
```

**Scaling:**
- Siphon-FS: scale on CPU (extraction is CPU-bound)
- Siphon-API: scale on request rate
- Siphon-DS: scale on consumer lag (per-adapter signal)
- Siphon-GW: scale on request rate + upstream latency

### Helm

Each pod gets its own Helm chart. Common values (core scanner config,
policy, EDM state) are shared via a base chart or ConfigMap.

## Migration Path

The workspace split is the prerequisite. The migration is incremental:

1. **Split the workspace** — move scanner logic to `siphon-core`,
   extractors to `siphon-extractors`, CLI/pipeline to `siphon-fs`.
   Everything still builds and tests pass. No new pods yet.

2. **Build Siphon-API** — new crate that depends on `siphon-core` +
   `hyper` or `axum`. `POST /scan` endpoint with API-key auth. This
   is the simplest new pod and covers most integration use cases.

3. **Build Siphon-DS** — new crate with pluggable ingestion adapters.
   Ship syslog + fluent first (most enterprise value, zero app changes
   for existing log pipelines). Add AMQP / Redis Streams / cloud
   queues as follow-ups.

4. **Build Siphon-GW** — new crate for the inline proxy use case.
   Higher complexity (mTLS, upstream management, streaming bodies)
   so ship it after API and DS are stable.

5. **Helm charts** — one chart per pod with shared ConfigMap for
   scanner config.

6. **Siphon-Vision** — separate repo, separate timeline. Integrates
   via the unified finding format.
