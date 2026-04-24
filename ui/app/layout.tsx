import type { Metadata } from "next";
import "@/app/globals.css";

import { Header } from "@/components/layout/header";
import { Shell } from "@/components/layout/shell";

export const metadata: Metadata = {
  title: {
    default: "Siphon",
    template: "%s · Siphon",
  },
  description:
    "High-performance DLP scanner — detect, redact, and protect sensitive data.",
  robots: {
    // The SPA sits behind Authelia forward-auth, so bots can't
    // reach it anyway. This is belt-and-braces in case a dev
    // instance gets exposed on a public LB.
    index: false,
    follow: false,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Header />
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
