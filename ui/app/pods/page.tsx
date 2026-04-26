"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  Loader2,
  RefreshCw,
  RotateCw,
  XCircle,
} from "lucide-react";

import {
  SubHeader,
  SubHeaderActions,
  SubHeaderMeta,
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
import { ErrorAlert } from "@/components/ui/error-alert";
import { api, ApiError, type PodSummary } from "@/lib/api";
import { formatRelativeAge } from "@/lib/formatters";
import { cn } from "@/lib/utils";

// Poll cadence for the pods list. Five seconds feels live without
// hammering the k8s API server — kubelet pushes pod status updates
// at ~5 s intervals anyway so anything faster just repeats the
// same snapshot.
const POLL_INTERVAL_MS = 5_000;

export default function PodsPage() {
  const [pods, setPods] = useState<PodSummary[] | null>(null);
  const [namespace, setNamespace] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [rollingOut, setRollingOut] = useState<Record<string, boolean>>({});
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.pods();
      setPods(res.pods);
      setNamespace(res.namespace);
      setError(null);
      setLastUpdated(new Date());
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError("Unknown error");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [load]);

  async function restartDeployment(deployment: string) {
    setRollingOut((r) => ({ ...r, [deployment]: true }));
    try {
      await api.rollout(deployment);
      // Give k8s a moment to start cycling pods before the next
      // refresh picks up the new restart count.
      setTimeout(load, 1_500);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      }
    } finally {
      setRollingOut((r) => ({ ...r, [deployment]: false }));
    }
  }

  const counts = useMemo(() => {
    if (!pods) return { total: 0, ready: 0, unhealthy: 0 };
    let ready = 0;
    let unhealthy = 0;
    for (const p of pods) {
      if (p.ready) ready++;
      else if (p.phase === "Failed" || !p.ready) unhealthy++;
    }
    return { total: pods.length, ready, unhealthy };
  }, [pods]);

  // Group pods by their Deployment (component label) so the
  // restart button applies to the whole set, not a single pod
  // (Deployments own pods, not the other way around).
  const byDeployment = useMemo(() => {
    const out = new Map<string, PodSummary[]>();
    for (const p of pods ?? []) {
      const key = p.deployment ?? "(unlabeled)";
      const list = out.get(key) ?? [];
      list.push(p);
      out.set(key, list);
    }
    return [...out.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [pods]);

  return (
    <>
      <SubHeader>
        <SubHeaderTitle
          title="Live pods"
          description={
            namespace
              ? `namespace: ${namespace}`
              : "namespace: (resolving)"
          }
        />
        <SubHeaderMeta>
          <Badge variant="outline">
            {counts.total} {counts.total === 1 ? "pod" : "pods"}
          </Badge>
          <Badge variant={counts.ready === counts.total ? "low" : "medium"}>
            {counts.ready} ready
          </Badge>
          {counts.unhealthy > 0 ? (
            <Badge variant="critical">{counts.unhealthy} unhealthy</Badge>
          ) : null}
        </SubHeaderMeta>
        <SubHeaderActions>
          <span className="hidden text-xs text-muted-foreground sm:inline">
            {lastUpdated
              ? `updated ${Math.round(
                  (Date.now() - lastUpdated.getTime()) / 1000,
                )}s ago`
              : ""}
          </span>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw
              className={cn(
                "h-4 w-4",
                loading && "animate-spin",
              )}
            />
            Refresh
          </Button>
        </SubHeaderActions>
      </SubHeader>

      <ShellContent>
        {error ? (
          <ErrorAlert
            className="mb-4"
            title="Pod discovery unavailable"
            message={error}
            hint={
              <>
                The Ops view needs siphon-api built with{" "}
                <code className="rounded bg-muted px-1">
                  --features k8s-roll
                </code>{" "}
                and the Role provisioned by the Helm chart (
                <code className="rounded bg-muted px-1">
                  api.k8sRoll.enabled=true
                </code>
                ).
              </>
            }
          />
        ) : null}

        {loading && pods === null ? (
          <Card>
            <CardContent className="flex items-center gap-3 py-8 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading pods…
            </CardContent>
          </Card>
        ) : null}

        <div className="flex flex-col gap-4">
          {byDeployment.map(([deployment, group]) => {
            const allReady = group.every((p) => p.ready);
            const rolling = rollingOut[deployment] ?? false;
            return (
              <Card key={deployment}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
                  <div>
                    <CardTitle className="text-base">{deployment}</CardTitle>
                    <CardDescription>
                      {group.length} {group.length === 1 ? "pod" : "pods"}
                      {" · "}
                      {group.filter((p) => p.ready).length}/{group.length} ready
                    </CardDescription>
                  </div>
                  {deployment !== "(unlabeled)" ? (
                    <Button
                      variant={allReady ? "outline" : "default"}
                      size="sm"
                      disabled={rolling}
                      onClick={() => restartDeployment(deployment)}
                    >
                      {rolling ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <RotateCw className="h-4 w-4" />
                      )}
                      {rolling ? "Rolling…" : "Restart"}
                    </Button>
                  ) : null}
                </CardHeader>
                <CardContent className="pt-0">
                  <ul className="divide-y text-sm">
                    {group.map((p) => (
                      <li
                        key={p.name}
                        className="flex flex-wrap items-center gap-3 py-2"
                      >
                        <PhaseIcon phase={p.phase} ready={p.ready} />
                        <span className="font-mono">{p.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {p.phase}
                        </span>
                        {p.restarts > 0 ? (
                          <Badge variant="medium">
                            {p.restarts}{" "}
                            {p.restarts === 1 ? "restart" : "restarts"}
                          </Badge>
                        ) : null}
                        <span className="ml-auto text-xs text-muted-foreground">
                          {p.node ?? "—"} · {formatRelativeAge(p.created_at)}
                        </span>
                        {p.image ? (
                          <span className="w-full truncate font-mono text-xs text-muted-foreground">
                            {p.image}
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            );
          })}

          {!loading && pods !== null && pods.length === 0 && !error ? (
            <Card>
              <CardContent className="py-8 text-sm text-muted-foreground">
                No pods carry the{" "}
                <code className="rounded bg-muted px-1">
                  app.kubernetes.io/part-of=siphon
                </code>{" "}
                label in this namespace. If you deployed via the{" "}
                <code className="rounded bg-muted px-1">siphon</code> Helm
                chart, this should populate within a few seconds of install.
              </CardContent>
            </Card>
          ) : null}
        </div>
      </ShellContent>
    </>
  );
}

function PhaseIcon({ phase, ready }: { phase: string; ready: boolean }) {
  if (ready) {
    return (
      <CheckCircle2
        className="h-4 w-4 shrink-0 text-green-500"
        aria-label="Ready"
      />
    );
  }
  if (phase === "Failed" || phase === "Unknown") {
    return (
      <XCircle
        className="h-4 w-4 shrink-0 text-destructive"
        aria-label={phase}
      />
    );
  }
  return (
    <Loader2
      className="h-4 w-4 shrink-0 animate-spin text-muted-foreground"
      aria-label={phase}
    />
  );
}

