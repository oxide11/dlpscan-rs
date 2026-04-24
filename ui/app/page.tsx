import Link from "next/link";
import { ArrowRight, Activity, FileSearch, ScanLine, ShieldCheck } from "lucide-react";

import {
  SubHeader,
  SubHeaderTitle,
  SubHeaderActions,
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

export default function DashboardPage() {
  return (
    <>
      <SubHeader>
        <SubHeaderTitle
          title="Overview"
          description="Operational snapshot of the Siphon fleet"
        />
        <SubHeaderActions>
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
            title="Scans (24h)"
            value="—"
            icon={ScanLine}
            description="Wires to /api/v1/metrics in Phase 3"
          />
          <StatCard
            title="Findings (24h)"
            value="—"
            icon={FileSearch}
            description="Total detections across the fleet"
          />
          <StatCard
            title="Pods healthy"
            value="—"
            icon={Activity}
            description="Pulled from Linkerd viz in Phase 3"
          />
          <StatCard
            title="Policy"
            value="Audit"
            icon={ShieldCheck}
            description="Siphon-C2 policy mode"
          />
        </div>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>App shell</CardTitle>
            <CardDescription>
              Phase 0 scaffold — header, sub-header, component
              library. Stats above are placeholders until the
              findings DB (Phase 3) lands.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <p>
              The design-token system lives in{" "}
              <code className="rounded bg-muted px-1 py-0.5">
                app/globals.css
              </code>
              . Primitives in{" "}
              <code className="rounded bg-muted px-1 py-0.5">
                components/ui/
              </code>{" "}
              follow shadcn/ui conventions so swapping in a new
              component from upstream is a copy.
            </p>
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
}: {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
        <p className="mt-1 text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
