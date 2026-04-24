"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  FileSearch,
  ScanLine,
  Server,
  ShieldCheck,
} from "lucide-react";

import { cn } from "@/lib/utils";

// Primary chrome. Fixed height so nothing jumps between routes —
// the roadmap Phase 0 item about "navigation UX" called out header
// reflow during Prev/Next, so keeping the top chrome rigid at 56px
// is deliberate.
//
// Nav items live in a single array so adding a new top-level
// section is a one-line edit rather than a JSX scavenger hunt.

const NAV = [
  { href: "/", label: "Overview", icon: Activity },
  { href: "/pods", label: "Pods", icon: Server },
  { href: "/findings", label: "Findings", icon: FileSearch },
  { href: "/scan", label: "Scan", icon: ScanLine },
] as const;

export function Header() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-40 h-14 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-full max-w-7xl items-center gap-6 px-6">
        <Link
          href="/"
          className="flex items-center gap-2 text-base font-semibold"
        >
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden />
          <span>Siphon</span>
        </Link>

        <nav className="flex h-full items-center gap-1" aria-label="Primary">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active =
              href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  active
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )}
                aria-current={active ? "page" : undefined}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          {/* User menu slot — wires to Authelia's /auth logout once
              the SPA ships a profile popover. Phase 2 defer. */}
          <span className="text-xs text-muted-foreground">v2.1.0</span>
        </div>
      </div>
    </header>
  );
}
