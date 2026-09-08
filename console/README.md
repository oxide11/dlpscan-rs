# Siphon C2 console

Analyst console for the Siphon DLP engine. Built to the contract in
`docs/COMPONENTS.md` — read the four hard rules there before changing
anything in `src/ui/`.

## Stack

Vite · React 19 · TypeScript strict · TanStack Query/Table/Virtual/Router ·
Tailwind v4 (CSS-first tokens) · Radix where focus/portal/dismiss matter ·
cmdk. No Next.js, no client-state store, no runtime CSS-in-JS, no component
library.

Static output only. The bundle is meant to be embedded in the siphon-api
binary via `rust-embed`, so Node exists at build time and never in production.

## Develop

```sh
pnpm install
pnpm dev                       # proxies /api → http://127.0.0.1:8080
SIPHON_API=http://host:8080 pnpm dev
pnpm build                     # → dist/
pnpm exec tsc -b --noEmit      # typecheck
node shot.mjs --mock           # render check, both themes, fixtures
node shot.mjs                  # render check with the API absent
```

`shot.mjs` fails on any unexpected console error. The **API-absent** pass is
not a degraded run — it is the case the contract cares most about, because
that is when a screen has to say "not measured" rather than show a zero.

## Two things that are load-bearing

**The API lives under `/api`, never the origin root.** siphon-api serves
`POST /scan` and this console has a `/scan` route; served from one origin they
are the same path, separated only by HTTP method. The prefix removes the
collision and matches how the stack already deploys behind Nginx.

**Auth never touches `localStorage`.** Admin endpoints return unredacted
matched values, so an XSS here would be credential theft against them. Either
the proxy sets an httpOnly `SameSite=Strict` cookie, or a short-lived token is
held in memory via `setToken()`. The only thing persisted is the theme.

## Known gaps

- Five routes are honest stubs: `/policies`, `/running`, `/assurance`,
  `/settings` state what they will absorb and render nothing else.
- No diff-before-apply flow yet, so nothing in the console mutates policy.
  `DiffView` and `ConfirmDialog` exist; the `/v1/overrides/diff` wiring does not.
- `src/lib/api.ts` types are hand-written and will drift from the Rust structs.
  The durable fix is generating them (`ts-rs`, or `schemars` → OpenAPI).
- Severity is derived in `src/lib/severity.ts` from confidence + category +
  validator state. The bands are a first cut and should be calibrated against
  analyst verdicts once those accumulate.

## Fonts

`tokens.css` names Inter and JetBrains Mono, and nothing loads them — the
console falls back to the system sans and mono stacks. That is deliberate:
pulling webfonts from a CDN would put a third-party network dependency in the
critical path of a security tool that is expected to run in restricted and
air-gapped environments. If the brand faces matter, self-host the woff2 files
under `public/assets/` and add the `@font-face` rules to `src/app.css`.
