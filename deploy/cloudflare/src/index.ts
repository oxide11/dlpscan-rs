/**
 * Cloudflare Worker entrypoint for the Siphon demo deployment.
 *
 * Architecture: Worker (edge) -> Container (siphon-api).
 * The Worker owns everything that must NOT be delegated to the origin —
 * client-IP rate limiting, the public surface allowlist, and payload caps —
 * then forwards to the container, which runs the unmodified siphon-api image.
 */
import type { DurableObject } from "cloudflare:workers";
import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  SIPHON: DurableObjectNamespace<SiphonContainer>;
  DEMO_LIMITER: RateLimit;
  /** Set with: wrangler secret put SIPHON_API_KEY */
  SIPHON_API_KEY: string;
  /**
   * Hex HMAC-SHA256 key enabling the tamper-evident audit chain.
   * Set with: wrangler secret put SIPHON_AUDIT_SIGNING_KEY_HEX
   * Optional — without it the audit log is written but unsigned.
   */
  SIPHON_AUDIT_SIGNING_KEY_HEX?: string;
}

/**
 * Durable audit storage.
 *
 * The container's filesystem does not survive a wake, so siphon-api's own
 * chain-tail file is gone on every cold start and the HMAC chain would
 * restart — losing the property that makes it worth having. The Durable
 * Object's SQLite storage *is* durable and strongly consistent, so it owns
 * the audit record: this DO periodically drains siphon-api's in-memory ring
 * (GET /v1/audit) into SQLite, and hands the last tail signature back to the
 * next container via SIPHON_AUDIT_CHAIN_SEED so the chain continues unbroken.
 *
 * Drain cadence vs. ring capacity is the correctness constraint. siphon-api's
 * ring holds SIPHON_AUDIT_RING_CAP events; anything that overflows between
 * two drains is lost before we see it, which leaves a real gap in the stored
 * chain. Keep the interval well under (ring capacity / peak event rate) — the
 * ring is raised to 2000 below for exactly this reason.
 */
const AUDIT_DRAIN_INTERVAL_SECONDS = 30;

/** Per-drain page size. Must stay <= SIPHON_AUDIT_RING_CAP. */
const AUDIT_DRAIN_LIMIT = 1000;

/**
 * Rows kept in DO SQLite. A demo does not need unbounded history, and DO
 * storage is billed. Oldest rows are trimmed past this.
 */
const AUDIT_RETENTION_ROWS = 50_000;

/** Shape of GET /v1/audit. Mirrors AuditResponse in siphon-api. */
interface AuditEventJson {
  event_type: string;
  timestamp: string;
  outcome?: string | null;
  request_id?: string | null;
  finding_count?: number;
  categories_found?: string[];
  signature?: string | null;
  prev_signature?: string | null;
}
interface AuditResponseJson {
  total: number;
  returned: number;
  capacity: number;
  events: AuditEventJson[];
}

/**
 * Reject bodies larger than this at the edge, before any container time is
 * billed. siphon-core rejects >10 MB itself, but a demo has no reason to
 * accept anything near that.
 *
 * IMPORTANT — this is a courtesy/cost-control check, NOT a security boundary.
 * It reads the client-supplied Content-Length header, which a caller can lie
 * about or omit entirely (e.g. chunked Transfer-Encoding carries no
 * Content-Length). In practice the check is bounded by Cloudflare's
 * platform-level request-size limit and siphon-core's own 10 MB hard cap, so
 * there is no exploitable gap — but do not rely on this check alone for
 * enforcement. The real enforcement is upstream (platform + origin).
 */
const MAX_BODY_BYTES = 256 * 1024;

/**
 * Public surface for the demo. siphon-api exposes admin and mutating
 * endpoints (POST /v1/overrides/apply, POST /v1/findings/prune,
 * POST /v1/evadex/runs, GET /v1/audit, ...) that must not be reachable from
 * the internet. Allowlist rather than denylist so a future siphon-api route
 * is closed by default instead of silently exposed.
 */
const PUBLIC_PATHS = new Set([
  "/health",
  "/ready",
  "/scan",
  "/scan/batch",
  "/v1/scan/explain",
  "/v1/categories",
]);

export class SiphonContainer extends Container<Env> {
  defaultPort = 8080;

  /**
   * Containers bill memory/disk on provisioned capacity while awake, and
   * charges stop on sleep — so idle time is the cost lever. 15m is long
   * enough that a demo session stays warm across a pause, short enough that
   * an unattended day costs almost nothing.
   */
  sleepAfter = "15m";

  /** siphon-api's /health is unauthenticated, so it works as a readiness ping. */
  pingEndpoint = "/health";

  constructor(ctx: DurableObject["ctx"], env: Env) {
    super(ctx, env);

    // DO SQLite reads are synchronous, which is what makes this work at all:
    // the chain seed has to be known before the container starts, and a
    // constructor cannot await.
    this.initAuditSchema();
    const seed = this.readChainTail();

    // Set here rather than as a class-field initializer because the API key
    // comes from `this.env`, which is only populated once super() has run.
    this.envVars = {
      // CRITICAL: siphon-api defaults to binding 127.0.0.1, which would make
      // it unreachable from outside the container. Must bind all interfaces.
      SIPHON_BIND: "0.0.0.0",
      SIPHON_PORT: "8080",
      SIPHON_API_KEY: env.SIPHON_API_KEY,

      // Audit. siphon-api refuses to start without SIPHON_AUDIT_LOG_PATH
      // unless SIPHON_DEV_MODE is set (GAP-07: an in-memory ring alone is not
      // a durable audit trail). Rather than declare a public demo "dev mode",
      // the log is written to container-local disk and drained to DO SQLite,
      // which is the actual durable store — see the comment on
      // AUDIT_DRAIN_INTERVAL_SECONDS.
      SIPHON_AUDIT_LOG_PATH: "/tmp/siphon/audit.jsonl",
      SIPHON_AUDIT_TAIL_PATH: "/tmp/siphon/audit.tail",
      // Ring sized so a drain interval cannot plausibly overflow it.
      SIPHON_AUDIT_RING_CAP: "2000",
      ...(env.SIPHON_AUDIT_SIGNING_KEY_HEX
        ? { SIPHON_AUDIT_SIGNING_KEY_HEX: env.SIPHON_AUDIT_SIGNING_KEY_HEX }
        : {}),
      // Resume the chain across the wake. Omitted on first ever start, when
      // there is no prior tail to link to.
      ...(seed ? { SIPHON_AUDIT_CHAIN_SEED: seed } : {}),

      // Deliberately unset for the demo:
      //   SIPHON_DATABASE_URL - no Postgres; findings live in the in-memory
      //                         ring only (db.rs handles this as Unconfigured).
      //                         Findings rows carry matched sensitive values,
      //                         so persisting them needs a deliberate decision
      //                         about where that data lives; audit events
      //                         carry counts and categories, not match text.
      SIPHON_RATE_LIMIT: "600",
      RUST_LOG: "info",
    };
  }

  /** Idempotent; runs on every DO activation. */
  private initAuditSchema(): void {
    const sql = this.ctx.storage.sql;
    // Events are stored verbatim. Stripping or rewriting any field would
    // invalidate the HMAC signature computed over the canonical JSON, which
    // would defeat the point of persisting them — a record you cannot verify
    // is not an audit trail.
    sql.exec(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id             TEXT PRIMARY KEY,
        signature      TEXT,
        prev_signature TEXT,
        timestamp      TEXT NOT NULL,
        event_type     TEXT NOT NULL,
        outcome        TEXT,
        finding_count  INTEGER,
        body           TEXT NOT NULL,
        drained_at     TEXT NOT NULL
      )
    `);
    sql.exec(
      `CREATE INDEX IF NOT EXISTS audit_events_timestamp ON audit_events(timestamp)`,
    );
    sql.exec(`
      CREATE TABLE IF NOT EXISTS audit_chain (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        tail       TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);
  }

  private readChainTail(): string | null {
    const rows = this.ctx.storage.sql
      .exec<{ tail: string }>(`SELECT tail FROM audit_chain WHERE id = 1`)
      .toArray();
    return rows.length > 0 ? rows[0].tail : null;
  }

  /**
   * Absorb cold start. The first scan in a fresh process pays ~324 ms of lazy
   * init (568 regex DFAs + the ~5k-keyword Aho-Corasick automaton) versus
   * ~0.5 ms warm — and because container disk is ephemeral, every wake is a
   * cold one. Warming here moves that cost off the first user request.
   */
  override async onStart(): Promise<void> {
    try {
      await this.containerFetch("http://localhost/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.env.SIPHON_API_KEY}`,
        },
        body: JSON.stringify({
          text: "warmup 4111-1111-1111-1111 warmup@example.com 536-90-4399",
        }),
      });
    } catch (err) {
      // Best-effort only — a failed warmup must not block the container.
      console.log("warmup failed (non-fatal):", err);
    }

    // Start the drain loop. schedule() is the library's own alarm wrapper —
    // overriding alarm() directly would fight its container-lifecycle timers.
    await this.schedule(AUDIT_DRAIN_INTERVAL_SECONDS, "drainAudit");
  }

  /**
   * Drain siphon-api's audit ring into DO SQLite, then re-arm.
   *
   * Public and named because `schedule()` dispatches by method name.
   */
  async drainAudit(): Promise<void> {
    try {
      await this.persistAuditPage();
    } catch (err) {
      // Never let a drain failure kill the loop — the next tick retries, and
      // the ring still holds recent events.
      console.error("audit drain failed (non-fatal):", err);
    } finally {
      await this.schedule(AUDIT_DRAIN_INTERVAL_SECONDS, "drainAudit");
    }
  }

  /**
   * Final drain before the container sleeps. Without this, up to one whole
   * interval of events would be lost on every sleep — and sleeps are frequent
   * by design (sleepAfter = 15m).
   */
  override async onStop(): Promise<void> {
    try {
      await this.persistAuditPage();
    } catch (err) {
      console.error("final audit drain failed (non-fatal):", err);
    }
  }

  private async persistAuditPage(): Promise<void> {
    // /v1/audit is admin-gated (RequireAdminAction); the container's own key
    // resolves to Admin under the single-key model. This call goes straight
    // to the container and never crosses the Worker's public allowlist, which
    // deliberately does not expose /v1/audit to the internet.
    const res = await this.containerFetch(
      `http://localhost/v1/audit?limit=${AUDIT_DRAIN_LIMIT}`,
      { headers: { authorization: `Bearer ${this.env.SIPHON_API_KEY}` } },
    );
    if (!res.ok) {
      throw new Error(`GET /v1/audit returned ${res.status}`);
    }
    const page = (await res.json()) as AuditResponseJson;
    if (!page.events?.length) return;

    // Response is newest-first. Insert oldest-first so that if we are
    // interrupted partway the stored prefix is still contiguous.
    const oldestFirst = [...page.events].reverse();
    const sql = this.ctx.storage.sql;
    const drainedAt = new Date().toISOString();
    let newestSignature: string | null = null;
    let inserted = 0;

    for (const ev of oldestFirst) {
      // Signature is the natural identity for a signed event. Unsigned events
      // (no signing key configured) fall back to a synthetic key so the drain
      // still deduplicates across overlapping pages.
      const id =
        ev.signature ??
        `unsigned:${ev.timestamp}:${ev.event_type}:${ev.request_id ?? ""}`;
      const cursor = sql.exec(
        `INSERT OR IGNORE INTO audit_events
           (id, signature, prev_signature, timestamp, event_type, outcome,
            finding_count, body, drained_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        id,
        ev.signature ?? null,
        ev.prev_signature ?? null,
        ev.timestamp,
        ev.event_type,
        ev.outcome ?? null,
        ev.finding_count ?? null,
        JSON.stringify(ev),
        drainedAt,
      );
      if (cursor.rowsWritten > 0) inserted++;
      if (ev.signature) newestSignature = ev.signature;
    }

    // Advance the chain tail only to a signature we have actually stored, so
    // a future container is never seeded past the end of the record.
    if (newestSignature) {
      sql.exec(
        `INSERT INTO audit_chain (id, tail, updated_at) VALUES (1, ?, ?)
           ON CONFLICT(id) DO UPDATE SET tail = excluded.tail,
                                         updated_at = excluded.updated_at`,
        newestSignature,
        drainedAt,
      );
    }

    // The ring reports how many events it has seen in total; if that has
    // outrun its own capacity between two drains, events existed that we
    // never saw. Surface it rather than leaving a silent hole in the chain.
    if (page.total > page.capacity) {
      console.warn(
        `audit ring reported total=${page.total} > capacity=${page.capacity}; ` +
          `events may have been evicted before this drain — consider a shorter ` +
          `AUDIT_DRAIN_INTERVAL_SECONDS or a larger SIPHON_AUDIT_RING_CAP`,
      );
    }

    if (inserted > 0) {
      sql.exec(
        `DELETE FROM audit_events WHERE id NOT IN (
           SELECT id FROM audit_events ORDER BY timestamp DESC LIMIT ?
         )`,
        AUDIT_RETENTION_ROWS,
      );
    }
  }

  override onError(error: unknown) {
    console.error("siphon container error:", error);
    throw error;
  }
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/health";

    if (!PUBLIC_PATHS.has(path)) {
      return json(
        { error: "not_found", detail: "Endpoint not exposed in the demo deployment." },
        404,
      );
    }

    // Rate limit on the true client IP. Cloudflare sets CF-Connecting-IP and
    // strips any client-supplied copy, so it is trustworthy here in a way it
    // would not be at an arbitrary origin. Probes stay unmetered so uptime
    // checks cannot exhaust a real user's budget.
    if (path !== "/health" && path !== "/ready") {
      const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const { success } = await env.DEMO_LIMITER.limit({ key: ip });
      if (!success) {
        return json(
          { error: "rate_limited", detail: "Demo limit is 30 requests/minute." },
          429,
        );
      }
    }

    const declared = Number(request.headers.get("content-length") ?? 0);
    if (declared > MAX_BODY_BYTES) {
      return json(
        { error: "payload_too_large", detail: `Demo limit is ${MAX_BODY_BYTES} bytes.` },
        413,
      );
    }

    // Inject the upstream credential at the edge so demo callers do not need
    // one. Flip this to forwarding the caller's Authorization header if you
    // would rather gate the demo behind issued keys.
    const upstream = new Request(request);
    upstream.headers.set("authorization", `Bearer ${env.SIPHON_API_KEY}`);

    // One named instance keeps a single container warm for the whole demo
    // rather than spreading traffic across cold ones.
    return getContainer(env.SIPHON, "demo").fetch(upstream);
  },
};
