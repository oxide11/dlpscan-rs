# IR vs C2 — what lives where

The Siphon stack ships two browser consoles, each tuned for a
different role. They share data but serve opposite mental models.
This doc is the source of truth for which surfaces belong in which
console, and why. Use it as the gating reference when adding a new
surface or moving an existing one.

The doc is **opinionated**: everything here is a call we made, not
a discovery. Push back on any of it that's wrong for your workflow
— the open-questions section at the bottom captures the calls
that aren't yet settled.

## Personas

| Console | Persona | What they do all day |
|---|---|---|
| **siphon-c2** (Command & Center) | Security engineers · detection authors · platform analysts | **Operate** Siphon — tune patterns, watch throughput, manage policies, run adversarial tests, review the FP queue, configure integrations, manage RBAC. |
| **siphon-ir** (Incident Response) | Incident responders · forensic analysts · IR consultants | **Investigate** Siphon's *findings* — triage the queue, drill into a single finding, run forensics, link cases together, export evidence with chain-of-custody. |

The split is **operate vs. investigate**. Same data, opposite verbs.

## The split (today's surfaces)

| Surface | C2 | IR | Why |
|---|---|---|---|
| **Dashboard** | ✓ (Operate) | ✓ (Respond) | Same name, different lens. C2 = throughput/health/policy SLOs. IR = MTTR/queue depth/case counts. |
| **Findings** | ✓ (Operate · "Findings" stream) | ✓ (Respond · "Findings Queue") | Same underlying data; C2 sees *flow*, IR sees *backlog*. |
| **Investigations** | ✓ | ✓ | Both today. See open question #1 below — leaning canonical-in-IR. |
| **Pods** | ✓ | — | Cluster operations belong in C2. |
| **Pod Logs** | ✓ | — | Same. |
| **Alerts** | ✓ | ✓ | C2 = *operational* alerts (Siphon health, throughput thresholds). IR = *response* alerts (a finding crossed an escalation rule). Today they share a surface name and that's confusing. See open question #5. |
| **Handoffs** | — | ✓ | Tickets / SOAR escalations are an IR workflow. |
| **Detect overview / Policies / Patterns / Models / Fingerprints / Masking Profiles / Match Lists / Tokenization** | ✓ | — | Detection authoring is a C2 concern. Responders consume the rules; engineers write them. |
| **Adversarial Tests / Test Corpora / Compliance / Audit Log / Assurance Overview** | ✓ | — | Quality assurance lives with the people who tune patterns. |
| **Integrations** | ✓ | ✓ today | Should collapse to C2-only. See open question #2. |
| **Users & Roles** | ✓ (canonical) | — | Architectural call already made. The current `ir-users` surface has a "moving to C2" banner since the previous PR. The actual code move is queued. |
| **Authentication** (password / SAML / passkeys backend config) | ✓ | — (today: `ir-auth` exists) | Backend auth config is admin-level. Move `ir-auth` to C2 in this PR. |
| **API Keys** | ✓ | — | Issuing keys is a C2 admin job. |
| **Agents** | ✓ | — | C2-side ops surface. |
| **Pod Registry** | ✓ | — (today: `ir-deployment` exists) | Today's `ir-deployment` is literally subtitled "shared with admin console" — it's a duplicate. Move to C2-only. |
| **Settings (system)** | ✓ | — | Global Siphon config = C2. |
| **My Profile** (per-user prefs) | needed but missing today | ✓ (`ir-settings`) | Every signed-in user needs a profile/prefs/change-my-password page. Today only IR has it. Add it to C2 too — one profile per user, both consoles read the same store. |
| **Engineering** (Live Scan / Corpus Runner / Scan Diff / API Explorer / Process State / FP Troubleshooter / FP Queue) | ✓ | — (today: `ir-engineering` exists) | Detection engineering belongs in C2. The current `ir-engineering` surface is "demo data · dev toggles" — that's a small subset that should move to C2's Engineering workspace. |
| **Crypto Workbench** | — | ✓ (Analyze) | Investigative tool: crack a password-protected attachment that came in with a finding. |
| **File Extractor** | — | ✓ (Analyze) | Pull text out of an arbitrary file format mid-investigation. |
| **Forensics** | — | ✓ (Analyze) | Authorship + file-metadata analysis. |
| **Timeline** | — | ✓ (Analyze, but should move to Correlate per existing backlog item) | Reconstruct a sequence of events. |
| **Pivots** | — | ✓ (Correlate) | Same-document / same-source linking. |
| **IOC Lookup** | — | ✓ (Correlate) | Cross-reference indicators across findings. |
| **Chain of Custody / Exhibits / Export Bundle** | — | ✓ (Evidence) | Case packaging for handoff. |
| **Docs** | ✓ | (HelpIcon popovers reach into the same docs) | C2 hosts the "Browse" surface; IR uses contextual `HelpIcon` popovers that link into the same content. Don't duplicate. |

## Required moves (this PR's follow-up)

These are the concrete code changes the audit produces. Each is
small in isolation; sequence them so any one can be reverted
cleanly without unwinding the next.

| # | Move | From | To | Notes |
|---|---|---|---|---|
| M1 | `ir-users` | IR | C2 (already declared) | Heavy code move queued separately (the three-commit `claude/c2-owns-user-management` plan). |
| M2 | `ir-auth` (auth backend config) | IR | C2 | Single-surface move. C2 doesn't have an auth-backend surface today; create `auth` under the Settings workspace. |
| M3 | `ir-deployment` (Pod Registry) | IR | C2 | Surface already says "shared with admin console" — drop it from IR, point IR users to C2's Pods workspace. |
| M4 | `ir-engineering` (demo data + dev toggles) | IR | C2 | Slot under C2's Engineering workspace as a new surface (e.g. `'demotoggles'`). Single new surface in C2, delete `ir-engineering`. |
| M5 | "My Profile" parity | IR-only today | also in C2 | C2 doesn't have a per-user profile. Add `'profile'` to C2's Settings workspace, reading the same store as IR's `ProfileSurface`. |
| M6 | Timeline workspace | IR Analyze | IR Correlate | Already on the backlog as a separate item — listed here for completeness. |

After M1–M5, IR's `Settings` workspace shrinks to `Integrations`
(open question #2) + `My Profile`. We may rename it to "My
Account" once `Integrations` resolves, since "settings" implies
system config that no longer lives there.

## Status

| ID | Move | Status |
|---|---|---|
| M1 | `ir-users` → C2 (heavy code move) | Intent shipped (banners + disabled affordances). Code move queued for its own session. |
| M2 | `ir-auth` → C2 | ✅ Shipped. C2's new `'auth'` surface is a stub today; full auth status board ports across in a follow-up. |
| M3 | `ir-deployment` → C2 (Pods) | ✅ Shipped. IR redirects via `MovedToC2` helper. |
| M4 | `ir-engineering` → C2 (Engineering) | ✅ Shipped. IR redirects via `MovedToC2` helper. |
| M5 | Add `profile` to C2 | ✅ Shipped. Stub today; full impl arrives with the M1 code move (shared per-user store). |
| M6 | Timeline Analyze → Correlate (IR) | ✅ Shipped. |

## Resolved questions

| ID | Decision | Implementation |
|---|---|---|
| Q1 | Investigations: canonical case-file UI in IR; C2 keeps a summary view that deep-links per-case to IR | ✅ C2's Investigations surface reframed as "operate lens" with deep-link banner, click-row → IR jump, and "+ New (in IR)" affordance |
| Q2 | Integrations collapse to C2-only; IR uses Handoffs to surface XSOAR/Splunk | ✅ Shipped together with M3/M4 |
| Q5 | Alerts: rename IR's surface to `triggers` (escalation rules) | ✅ Shipped. C2 keeps operational `alerts`. |
| Q6 | Docs in IR nav: popover-only is sufficient | ✅ Decision recorded — no code change. Adding a Docs entry to IR's nav would pull focus from the response workflow; the contextual `HelpIcon` popovers already reach the same content. |

## Still open

| ID | Question | Status |
|---|---|---|
| Q3 | My Profile shared store across consoles | M5 stub ships first; the shared store requires hoisting per-user helpers to `siphon-shared.js`, which is M1 territory. Resolves once M1 lands. |
| Q4 | "Flag as FP" action on IR findings posting to the C2 FP Queue store | Recommended **(a)**: add the action. Scope: ~150 LoC — IR finding-detail action + a shared `c2:fpqueue` localStorage write. Standalone PR; doesn't block anything else. |

## After this PR

The remaining work is M1 (heavy user-management code move) plus
the open questions above. M1 is the last big lift; once it lands,
IR's Settings workspace shrinks to one entry (`My Profile`) and
the per-user / per-role helpers live in `siphon-shared.js` where
both consoles inherit them.
