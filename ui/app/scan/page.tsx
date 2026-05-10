"use client";

import { useState } from "react";
import { Loader2, ScanLine } from "lucide-react";

import {
  SubHeader,
  SubHeaderTitle,
} from "@/components/layout/sub-header";
import { ShellContent } from "@/components/layout/shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api, ApiError, type Finding } from "@/lib/api";

// Smoke-test form that posts text to /api/scan. Proves the
// Nginx → Authelia → siphon-api path end-to-end from the browser.

export default function ScanPage() {
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);

  async function onSubmit(ev: React.FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    setPending(true);
    setError(null);
    setFindings(null);
    try {
      const res = await api.scan(text);
      setFindings(res.findings);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError("Unknown error");
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <SubHeader>
        <SubHeaderTitle
          title="Ad-hoc scan"
          description="Paste text, run it through the scanner"
        />
      </SubHeader>

      <ShellContent>
        <Card>
          <CardHeader>
            <CardTitle>Scan text</CardTitle>
            <CardDescription>
              Posts to{" "}
              <code className="rounded bg-muted px-1 py-0.5">
                /api/scan
              </code>{" "}
              via the Nginx forward-auth proxy.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="flex flex-col gap-3">
              <label htmlFor="scan-text" className="sr-only">
                Text to scan
              </label>
              <textarea
                id="scan-text"
                className="min-h-40 w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                placeholder="Paste text containing potential PII here…"
                value={text}
                onChange={(e) => setText(e.target.value)}
                required
              />
              <div className="flex items-center gap-3">
                <Button type="submit" disabled={pending || !text.trim()}>
                  {pending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ScanLine className="h-4 w-4" />
                  )}
                  {pending ? "Scanning…" : "Run scan"}
                </Button>
                {error ? (
                  <span className="text-sm text-destructive" role="alert">
                    {error}
                  </span>
                ) : null}
              </div>
            </form>

            {findings ? (
              <div className="mt-6">
                <h2 className="mb-2 text-sm font-semibold">
                  Findings ({findings.length})
                </h2>
                {findings.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Clean — no detections.
                  </p>
                ) : (
                  <ul className="divide-y text-sm">
                    {findings.map((f, i) => (
                      <li
                        key={i}
                        className="flex items-center gap-3 py-2 font-mono"
                      >
                        <Badge variant={f.severity ?? "info"}>
                          {f.category}
                        </Badge>
                        <span className="truncate">{f.text}</span>
                        <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                          {(f.confidence * 100).toFixed(0)}%
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </ShellContent>
    </>
  );
}
