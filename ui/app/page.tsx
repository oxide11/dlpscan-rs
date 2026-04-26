"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  ScanLine,
  Server,
  ShieldCheck,
} from "lucide-react";

import {
  SubHeader,
  SubHeaderActions,
  SubHeaderTitle,
} from "@/components/layout/sub-header";
import { ShellContent } from "@/components/layout/shell";
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

// Landing-page pod summary polls less aggressively than /pods
// itself (15 s vs 5 s) — the Ops view is where you go when you
// need live readings.
const POLL_INTERVAL_MS = 15_000;

export default function DashboardPage() {
  const [pods, setPods] = useState<PodSummary[] | null>(null);
  const [namespace, setNamespace] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.pods();
      setPods(res.pods);
      setNamespace(res.namespace);
      setError(null);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      }
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [load]);

  const summary = useMemo(() => {
    if (!pods) return { total: 0, ready: 0, unhealthy: 0, restarts: 0 };
    let ready = 0;
    let unhealthy = 0;
    let restarts = 0;
    for (const p of pods) {
      if (p.ready) ready++;
      else unhealthy++;
      restarts += p.restarts;
    }
    return { total: pods.length, ready, unhealthy, restarts };
  }, [pods]);

  const deployments = useMemo(() => {
    const seen = new Set<string>();
    for (const p of pods ?? []) {
      if (p.deployment) seen.add(p.deployment);
    }
    return [...seen].sort();
  }, [pods]);

  return (
    <>
      <SubHeader>
        <SubHeaderTitle
          title="Overview"
          description={
            namespace
              ? `siphon cluster · ${namespace}`
              : "Siphon operational overview"
          }
        />
        <SubHeaderActions>
          <Button asChild variant="outline" size="sm">
            <Link href="/pods">
              Live pods
              <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/scan">
              New scan
              <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
        </SubHeaderActions>
      </SubHeader>

      <ShellContent>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Pods total"
            value={pods === null && !error ? "…" : String(summary.total)}
            icon={Server}
            description={namespace ?? "resolving namespace"}
          />
          <StatCard
            title="Ready"
            value={pods === null && !error ? "…" : String(summary.ready)}
            icon={Activity}
            description={
              summary.total === 0
                ? "—"
                : `${Math.round((summary.ready / summary.total) * 100)}% of fleet`
            }
          />
          <StatCard
            title="Unhealthy"
            value={pods === null && !error ? "…" : String(summary.unhealthy)}
            icon={ShieldCheck}
            description="Failed, pending, or not-ready"
            tone={summary.unhealthy > 0 ? "warn" : "ok"}
          />
          <StatCard
            title="Restarts (total)"
            value={pods === null && !error ? "…" : String(summary.restarts)}
            icon={ScanLine}
            description="Sum across pod containers"
          />
        </div>

        {error ? (
          <ErrorAlert
            className="mt-6"
            title="Pod discovery unavailable"
            message={error}
            hint={
              <>
                The overview reads siphon-api&apos;s{" "}
                <code className="rounded bg-muted px-1">/v1/k8s/pods</code>,
                which requires the chart&apos;s{" "}
                <code className="rounded bg-muted px-1">
                  api.k8sRoll.enabled=true
                </code>{" "}
                Role. Outside a cluster, the endpoint returns an init error.
              </>
            }
          />
        ) : null}

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Deployments</CardTitle>
            <CardDescription>
              Workloads the Ops Role is watching. Click through for
              details and restart actions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {deployments.length === 0 ? (
              <p className="py-2 text-sm text-muted-foreground">
                No Deployments labelled{" "}
                <code className="rounded bg-muted px-1">
                  app.kubernetes.io/part-of=siphon
                </code>{" "}
                visible in this namespace yet.
              </p>
            ) : (
              <ul className="divide-y text-sm">
                {deployments.map((name) => {
                  const group = (pods ?? []).filter(
                    (p) => p.deployment === name,
                  );
                  const ready = group.filter((p) => p.ready).length;
                  return (
                    <li
                      key={name}
                      className="flex items-center justify-between py-2"
                    >
                      <span className="font-mono">{name}</span>
                      <span className="text-xs text-muted-foreground">
                        {ready}/{group.length} ready
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
      </ShellContent>
    </>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  description,
  tone,
}: {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  tone?: "ok" | "warn";
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon
          className={
            tone === "warn"
              ? "h-4 w-4 text-destructive"
              : "h-4 w-4 text-muted-foreground"
          }
          aria-hidden
        />
      </CardHeader>
      <CardContent>
        <div
          className={
            tone === "warn"
              ? "text-2xl font-semibold text-destructive"
              : "text-2xl font-semibold"
          }
        >
          {value}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
