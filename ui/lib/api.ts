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

const API_BASE =
  process.env.NEXT_PUBLIC_SIPHON_API_BASE ?? "/api";

type JsonBody = Record<string, unknown> | Array<unknown>;

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: JsonBody;
};

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const { body, headers, ...rest } = opts;
  const init: RequestInit = {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(headers ?? {}),
    },
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

export const api = {
  scan: (text: string) =>
    request<ScanResponse>("/v1/scan", {
      method: "POST",
      body: { text },
    }),

  health: () => request<{ status: string }>("/health"),
};
