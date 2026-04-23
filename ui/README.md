# Siphon UI

Next.js 15 App Router SPA for the Siphon analyst console. Static-
exported and served by Nginx under `/ui/` alongside the Rust
services at `/api/` and `/fs/`.

## Stack

- **Next.js 15** (App Router, React 19, static export)
- **TypeScript 5** strict mode
- **Tailwind CSS 4** (CSS-first config — see `app/globals.css`)
- **shadcn/ui** component conventions (primitives live in
  `components/ui/`, copy-paste from upstream)
- **lucide-react** for icons

## Layout

```
ui/
├── app/                    # App Router routes
│   ├── layout.tsx          # root shell (Header + <Shell>)
│   ├── globals.css         # Tailwind + design tokens
│   ├── page.tsx            # /
│   ├── findings/           # /findings
│   └── scan/               # /scan
├── components/
│   ├── layout/             # Header, SubHeader, Shell
│   └── ui/                 # shadcn primitives (Button, Card, …)
└── lib/
    ├── api.ts              # fetch wrapper → /api/v1/*
    └── utils.ts            # cn() helper
```

## Local dev

```sh
pnpm install
pnpm dev            # dev server on http://localhost:3000/ui/
pnpm typecheck
pnpm lint
pnpm build          # emits static export to ./out
```

To drop the `/ui` basePath during local dev (e.g. to hit the root
of `localhost:3000`):

```sh
BASE_PATH= pnpm dev
```

The fetch wrapper in `lib/api.ts` reads
`NEXT_PUBLIC_SIPHON_API_BASE`, defaulting to `/api`. Set it in
`.env.local` when pointing at a remote siphon-api:

```
NEXT_PUBLIC_SIPHON_API_BASE=https://siphon.example.com/api
```

## Production build

The reverse-proxy Docker image at `deploy/nginx/Dockerfile` runs
`pnpm build` in a Node stage and copies the static output into
`/srv/ui/` in the runtime stage. Bring the full auth stack up with:

```sh
docker compose -f deploy/docker-compose.yml --profile auth up --build
# → http://localhost:8080/ui/
```

## Conventions

- **Single source of design tokens** — edit `app/globals.css`; the
  component variants and layout defaults derive from the
  `@theme` block.
- **Fixed-height primary header** — `h-14` (56 px) on
  `components/layout/header.tsx`. Route changes shouldn't reflow
  it; the sub-header below is the flex layer.
- **Sub-header box** — every route-level page renders a
  `<SubHeader>` for title, detection chips, event metadata, and
  actions. Keeps the primary header clean and prevents the
  "jumping" UX the roadmap Phase 0 item called out.
- **No client-side data fetching in layout** — pages fetch; the
  shell stays static so First Load JS stays under ~115 KB.
