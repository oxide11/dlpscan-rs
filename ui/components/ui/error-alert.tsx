import * as React from "react";
import { AlertCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";

// Inline error panel — the destructive-tinted Card + AlertCircle +
// title + body shape that pages render when an API call fails or a
// gated feature isn't available in the current deployment. Both
// today's call sites (the dashboard `app/page.tsx` and the Ops
// `app/pods/page.tsx`) had near-identical copies; this is the
// single component they now share.
//
// `hint` is the optional small-print row beneath the message —
// usually a "you probably need to enable X" follow-up. ReactNode
// rather than string so callers can drop <code> blocks in.

export interface ErrorAlertProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  title: React.ReactNode;
  message: React.ReactNode;
  hint?: React.ReactNode;
}

export function ErrorAlert({
  title,
  message,
  hint,
  className,
  ...props
}: ErrorAlertProps) {
  return (
    <Card
      role="alert"
      className={cn("border-destructive/50 bg-destructive/5", className)}
      {...props}
    >
      <CardContent className="flex items-start gap-3 py-4">
        <AlertCircle
          aria-hidden="true"
          className="mt-0.5 h-5 w-5 shrink-0 text-destructive"
        />
        <div className="text-sm">
          <div className="font-semibold text-destructive">{title}</div>
          <div className="mt-0.5 text-muted-foreground">{message}</div>
          {hint ? (
            <div className="mt-2 text-xs text-muted-foreground">{hint}</div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
