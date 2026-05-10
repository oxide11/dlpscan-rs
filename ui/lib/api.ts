// Thin fetch wrapper around the Siphon REST API.
//
// The UI is served by Nginx under /ui/ and talks to siphon-api
// under /api/. Nginx handles forward-auth (see deploy/nginx/
// nginx.conf) so we don't bolt an API-key onto every request here —
// Authelia's session cookie is already attached by the browser.
//
// Errors are normalized into a single shape so pages can render a
// consistent "something broke" panel.

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const API_BASE = process.env.NEXT_PUBLIC_SIPHON_API_BASE ?? "/api";

// Optional bearer token for the local-dev path. In production the
// SPA is served behind nginx + Authelia, which attaches the
// session cookie via `credentials: "include"` below; the API key
// isn't needed and shouldn't be exposed to the browser. For
// `pnpm dev` against a port-forwarded siphon-api, set this in
// `ui/.env.local` so requests carry `Authorization: Bearer <key>`
// and the dev session can hit the auth-gated endpoints.
const API_KEY = process.env.NEXT_PUBLIC_SIPHON_API_KEY;

type JsonBody = Record<string, unknown> | Array<unknown>;

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: JsonBody;
};

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const { body, headers, ...rest } = opts;
  const baseHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (API_KEY) {
    baseHeaders.Authorization = `Bearer ${API_KEY}`;
  }
  const init: RequestInit = {
    credentials: "include",
    headers: { ...baseHeaders, ...(headers as Record<string, string> ?? {}) },
    ...rest,
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);

  const contentType = res.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await res.json().catch(() => null)
    : await res.text().catch(() => null);

  if (!res.ok) {
    throw new ApiError(
      `API ${init.method ?? "GET"} ${path} failed with ${res.status}`,
      res.status,
      payload,
    );
  }
  return payload as T;
}

// ----- endpoint helpers ---------------------------------------------------

export interface Finding {
  category: string;
  text: string;
  span: [number, number];
  confidence: number;
  severity?: "critical" | "high" | "medium" | "low" | "info";
}

export interface ScanResponse {
  findings: Finding[];
  summary: {
    findings_count: number;
    categories: Record<string, number>;
  };
}

// ----- k8s (Ops) ---------------------------------------------------------

export interface PodSummary {
  name: string;
  namespace: string;
  phase: string;
  ready: boolean;
  restarts: number;
  image: string | null;
  node: string | null;
  deployment: string | null;
  created_at: string | null;
}

export interface PodListResponse {
  namespace: string;
  count: number;
  pods: PodSummary[];
}

export interface RollOutcome {
  deployment: string;
  namespace: string;
  status: "rolled" | "skipped" | "error";
  error: string | null;
}

export interface RollResponse {
  status: string;
  rolled_at: string;
  namespace: string;
  deployments: RollOutcome[];
  note: string;
}

export const api = {
  scan: (text: string) =>
    request<ScanResponse>("/scan", {
      method: "POST",
      body: { text },
    }),

  health: () => request<{ status: string }>("/health"),

  // k8s discovery + rollout. Both hit the `k8s-roll`-gated handlers
  // in siphon-api and require the ServiceAccount Role provisioned
  // by the Helm chart.
  pods: () => request<PodListResponse>("/v1/k8s/pods"),

  rollout: (deployment: string) =>
    request<RollResponse>(
      `/v1/k8s/deployments/${encodeURIComponent(deployment)}/rollout`,
      { method: "POST" },
    ),
};
