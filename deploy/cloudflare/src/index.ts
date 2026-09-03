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
    // Set here rather than as a class-field initializer because the API key
    // comes from `this.env`, which is only populated once super() has run.
    this.envVars = {
      // CRITICAL: siphon-api defaults to binding 127.0.0.1, which would make
      // it unreachable from outside the container. Must bind all interfaces.
      SIPHON_BIND: "0.0.0.0",
      SIPHON_PORT: "8080",
      SIPHON_API_KEY: env.SIPHON_API_KEY,
      // Deliberately unset for the demo:
      //   SIPHON_DATABASE_URL   - no Postgres; findings live in the in-memory
      //                           ring only (db.rs handles this as Unconfigured).
      //   SIPHON_AUDIT_LOG_PATH - container disk is ephemeral and reset on every
      //                           wake, which would break the tamper-evident
      //                           HMAC chain's continuity. Better absent than
      //                           silently discontinuous.
      SIPHON_RATE_LIMIT: "600",
      RUST_LOG: "info",
    };
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
