import * as React from "react";

// Shell is the fixed column grid every page drops into. Header at
// top (sticky), optional sub-header below, then the main content
// with consistent horizontal padding. Having a single Shell keeps
// spacing + max-width in lock-step across routes so nothing jumps
// when the user navigates.

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-[calc(100vh-3.5rem)] flex-col">{children}</main>
  );
}

export function ShellContent({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-7xl flex-1 px-6 py-6">{children}</div>
  );
}
