# Siphon-C2 — design handoff

Everything Claude Code needs to build the console. Four files matter.

## Start here

1. **`kit/COMPONENTS.md`** — the build contract. Read the four hard rules
   first; they are the reason the console is legible and each is cheap to
   break by accident. Then the route table, then the component signatures.
2. **`Siphon-C2 Kit.html`** — the rendered companion. Open it in a browser
   beside the contract: every component, variant and state described in the
   markdown is shown live, with its TSX signature under each "Signature"
   disclosure. Toggle light/dark in the top right.

## Files

```
Siphon-C2 Kit.html     rendered spec — open in a browser, no build step
kit/COMPONENTS.md      the build contract: rules, routes, prop signatures
kit/tokens.css         Tailwind v4 @theme block — drop into the real app as-is
kit/kit.css            plain-CSS mirror of the tokens; powers the gallery only
assets/logo-mark.png   Polygon Cyber mark, 1304×1462 transparent
assets/octopus-64.png  pre-scaled 64px copy
ENGINE-NOTES.md        engine defects the console deliberately surfaces
```

`kit/tokens.css` is production code. `kit/kit.css` is not — it exists so the
gallery renders without a toolchain, and the real app uses Tailwind utilities
against the same token names.

## Wiring it up

```
npm create vite@latest console -- --template react-ts
```

Then in the entry stylesheet:

```css
@import "tailwindcss";
@import "./tokens.css";
```

Set `data-theme="light"` or `"dark"` on `<html>`. That is the whole theming
story — no provider, no context, and **no `dark:` variant anywhere in
component code**. `tokens.css` unsets Tailwind's default palettes, so
`bg-blue-500` will not compile; if a color is not in the token list it is not
in the system.

Stack, dependency justifications, and the deliberate exclusions are in
`COMPONENTS.md`. Serve the built bundle from the Rust binary via `rust-embed`
so there is one artifact and Node never reaches production.

## Two things to know before writing code

**Every value in the gallery is a fixture.** They were chosen to represent
real states, including the awkward ones, and they document the shape each
screen needs — but they are hardcoded and must be replaced with real API
calls.

**`ENGINE-NOTES.md` describes defects, not design fiction.** CONFIG absent
from audit event types, `context_required` always NULL, `proximity_chars`
parsed then ignored, extractor coverage gaps. The console makes them visible
on purpose. Several should be fixed in the engine rather than papered over in
the UI — decide which before building the surfaces that display them.
