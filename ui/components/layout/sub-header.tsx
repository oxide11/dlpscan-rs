import * as React from "react";

import { cn } from "@/lib/utils";
import { Separator } from "@/components/ui/separator";

// Secondary chrome — the "dedicated sub-header box" called out in
// the Phase 0 navigation-UX fix. Detection chips (category counts)
// and event metadata (timestamps, IDs, scan duration) live here so
// they don't reflow the primary header when the user pages through
// findings with Prev / Next.
//
// Composition rather than props explosion: pages render whatever
// they want inside <SubHeader> and rely on the two slots
// (<SubHeaderTitle>, <SubHeaderMeta>) to get consistent spacing.

export function SubHeader({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "border-b bg-muted/30",
        "px-6 py-4",
        className,
      )}
      role="region"
      aria-label="Page context"
      {...props}
    >
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3">
        {children}
      </div>
    </div>
  );
}

export function SubHeaderTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div className="flex min-w-0 flex-col">
      <h1 className="truncate text-lg font-semibold leading-tight">{title}</h1>
      {description ? (
        <p className="truncate text-sm text-muted-foreground">{description}</p>
      ) : null}
    </div>
  );
}

export function SubHeaderMeta({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2" role="list">
      {children}
    </div>
  );
}

export function SubHeaderActions({ children }: { children: React.ReactNode }) {
  return <div className="ml-auto flex items-center gap-2">{children}</div>;
}

// Visual divider between Meta and Actions when both are present —
// pages that don't want it just omit this.
export function SubHeaderDivider() {
  return <Separator orientation="vertical" className="h-6" />;
}
