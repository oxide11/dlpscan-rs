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

## Open questions

These are the calls that need a decision before M1–M5 ship. None
of them block the planning doc itself; they block the code-move PR.

1. **Investigations.** Today the surface exists in both. Proposal: canonical case-file UI lives in IR (where the work happens), C2 keeps a *summary* view (count of open cases, time-to-close trend, top assignees) that deep-links into IR for full case work. Yes/no?

2. **Integrations.** Today `'integrations'` exists in both consoles. Three plausible shapes:
   - **a)** C2 owns *all* integrations (SIEM, SOAR, webhooks, JIRA, Splunk HEC, XSOAR). IR keeps no integrations surface; XSOAR/Splunk show up in IR's Handoffs surface as escalation targets only.
   - **b)** C2 owns global integrations; IR has a stripped surface listing *only* the ones it can act on (XSOAR escalate, Splunk HEC search).
   - **c)** Same surface, both consoles, identical UI (status quo).
   Recommendation: **(a)** — collapse to C2-only and surface XSOAR/Splunk in IR's Handoffs. Yes/no?

3. **My Profile in C2.** Confirms M5: C2 needs a "My Profile" surface so engineers/analysts have a place to set their own theme/timezone/notifications. Yes/no — and does it share the same backing store as IR's profile (so a user's prefs follow them between consoles)?

4. **FP Queue from IR.** Engineers tune patterns by working the FP queue in C2's Engineering workspace. Responders are the people most likely to *spot* a FP (they're in the findings all day). Today there's no path from a finding in IR to "flag as FP". Two shapes:
   - **a)** Add a "Flag as false positive" action on each IR finding that posts to the same backing store the C2 FP Queue reads.
   - **b)** Just deep-link "Discuss this with detection engineering →" out to C2's FP Queue.
   Recommendation: **(a)** — closes the loop without requiring console-switching for the responder. Yes/no?

5. **Alerts.** Both consoles have an `'alerts'` surface today. Different intent (C2 = ops; IR = response triggers) but same name. Three shapes:
   - **a)** Rename one. C2 keeps `'alerts'` (operational), IR's becomes `'triggers'` or `'rules'` (escalation rules that fire when a finding matches).
   - **b)** Keep both `'alerts'`, accept the name collision; users learn it from context.
   - **c)** Collapse to one surface in C2 and surface fired-alert *records* in IR's Findings Queue as a filter.
   Recommendation: **(a)**.

6. **Docs.** Today docs are reachable via C2's `'docs'` surface and IR's `HelpIcon` popovers. Do we want a top-level Docs entry in IR's nav too, or is the popover sufficient? Recommendation: **popover sufficient** — adding a top-level Docs entry in IR pulls focus from the response workflow.

## After this PR

When the open questions resolve, the next PR (`claude/wireframes-ir-vs-c2-execute`)
implements M2–M5 (M1 is already underway as its own multi-commit
PR; M6 is on the backlog). Each move is small in isolation:

- Add the C2 surface entry + a stub component
- Remove the IR surface entry from `IR_SURFACES` + `SURFACE_COMPONENTS`
- Delete the IR component definition
- Add a one-time deep-link redirect on IR for users who land on the
  old hash route (`siphon-ir.html#surface=ir-deployment` →
  `siphon-c2.html#surface=pods`)

Total expected diff for M2 + M3 + M4 + M5: ~600 LoC across the two
HTML files, no shared code involved (each move is console-local).
