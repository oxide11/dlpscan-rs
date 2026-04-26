import { ChevronLeft, ChevronRight } from "lucide-react";

import {
  SubHeader,
  SubHeaderTitle,
  SubHeaderMeta,
  SubHeaderActions,
  SubHeaderDivider,
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
import { formatTimestampUtc } from "@/lib/formatters";

export const metadata = {
  title: "Findings",
};

// Placeholder sample data — the Phase 3 findings DB will replace
// this with a real query. Shape matches the /v1/scan response so
// swapping to a fetch is a one-line change.

const SAMPLE = {
  scanId: "sc_01HZKF2E4CA7Q3W6JX0P9YGV2T",
  document: "quarterly-payroll-2026-q1.xlsx",
  scannedAt: "2026-04-23T19:42:11Z",
  durationMs: 412,
  chips: [
    { label: "Critical", count: 3, variant: "critical" as const },
    { label: "High", count: 7, variant: "high" as const },
    { label: "Medium", count: 12, variant: "medium" as const },
    { label: "Low", count: 4, variant: "low" as const },
  ],
  findings: [
    {
      category: "CREDIT_CARD",
      text: "4532-0151-1283-0366",
      severity: "critical" as const,
      confidence: 0.98,
    },
    {
      category: "US_SSN",
      text: "123-45-6789",
      severity: "high" as const,
      confidence: 0.92,
    },
    {
      category: "EMAIL",
      text: "jane.doe@example.com",
      severity: "low" as const,
      confidence: 0.85,
    },
  ],
};

export default function FindingsPage() {
  return (
    <>
      <SubHeader>
        <SubHeaderTitle
          title={SAMPLE.document}
          description={`Scan ${SAMPLE.scanId} · ${formatTimestampUtc(
            SAMPLE.scannedAt,
          )} · ${SAMPLE.durationMs} ms`}
        />

        <SubHeaderDivider />

        <SubHeaderMeta>
          {SAMPLE.chips.map((chip) => (
            <Badge key={chip.label} variant={chip.variant} role="listitem">
              {chip.label}: {chip.count}
            </Badge>
          ))}
        </SubHeaderMeta>

        <SubHeaderActions>
          <Button variant="ghost" size="icon" aria-label="Previous document">
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" aria-label="Next document">
            <ChevronRight className="h-4 w-4" />
          </Button>
        </SubHeaderActions>
      </SubHeader>

      <ShellContent>
        <Card>
          <CardHeader>
            <CardTitle>Detections</CardTitle>
            <CardDescription>
              Preview — live data lands with the Phase 3 findings
              database + server-side pagination.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y text-sm">
              {SAMPLE.findings.map((f, i) => (
                <li
                  key={i}
                  className="flex items-center justify-between gap-3 py-3"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <Badge variant={f.severity}>{f.severity}</Badge>
                    <span className="font-mono text-xs text-muted-foreground">
                      {f.category}
                    </span>
                    <span className="truncate font-mono">{f.text}</span>
                  </div>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    confidence {(f.confidence * 100).toFixed(0)}%
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </ShellContent>
    </>
  );
}

