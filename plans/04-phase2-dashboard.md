# Phase 2C — Hosted dashboard and tenancy

> **v6.** The Phase 1 "dashboard" is the single-file HTML report from `insidia report`, not this app. This file is the **paid hosted dashboard** (Phase 2C). Uploading a CLI run to view history is free. Launching or scheduling a scan from the dashboard is paid, because it runs on our hardware. The UI names engines. The v5 trial (3 model-free scans, no bring-your-own model) is replaced by Cloud credits on new accounts. Typeface is Sora, from the brand kit.

Depends on: the Cloud scan API from [03-phase1-vertical-slices.md](03-phase1-vertical-slices.md) (Phase 2C connection modes) and the model service ([19-model-hosting.md](19-model-hosting.md)).
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A team can sign up, upload a CLI run for free, and then pay to launch and schedule scans, enroll a runner for internal targets, watch a scan live, and triage findings together. One brain, many users, many scans. Every finding shows the engine that produced it.

## Exit
- New user signs up, verifies email, lands in an org.
- They enroll a runner (token shown once), see it healthy, run validate, launch a scan from a profile, and open a finding transcript.
- They add a public target with no runner, verify it by DNS TXT, launch a direct scan, and see which test families were skipped because they need a runner.
- Every screen passes the apple-design review checklist and the accessibility checks below.
- A second user in another org cannot open those URLs (403, not 404 with a leak).
- Usage (attempts, tokens, tunnel bytes) is visible per org.
- Live progress updates over WebSocket without refreshing.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## Out of scope
SSO/SAML (Phase 4), agent attack-path graphs (Phase 3), and the payment-provider integration itself (this phase records the plan, shows usage, and routes to checkout; the provider is a billing milestone).

## Free account and Cloud credits
The CLI is free forever and needs no account. A Cloud account exists so a team can keep history and, when they pay, launch scans on our hardware.

**Free Cloud account**
- Upload CLI run directories and view them in history, with the same HTML report.
- No scan launched from the dashboard, no schedule, no hosted model, no runner.

**New paid accounts start with credits** (a settings-registry amount, so staff can grant more). Credits pay for hosted model tokens and for scans launched on our workers. When credits run out, uploaded history stays readable and "Launch scan" asks for a plan.

**Paid plan unlocks** (visible before purchase): launching and scheduling scans, the hosted attacker and judge, Thorough coverage on our GPUs, the pentest agent, runners for internal targets, team triage, and compliance exports.

**Enforcement is server-side.** Entitlements come from the plan's entry in the settings registry (see [20-admin-console.md](20-admin-console.md#per-customer-settings)), resolved at scan launch into the scan's `config_snapshot`. The API rejects a launch the plan does not allow (HTTP 402). The disabled UI is only a convenience.

## Admin console, first version
Ships in this phase, before the first design partner, as a separate internal app (`admin/` + `engine/admin_api/`). Full plan: [20-admin-console.md](20-admin-console.md#delivery-by-phase).
- Customers list and org detail, plan-and-limits settings and feature flags, scan debugger, runner fleet, platform health with kill switches, staff audit.
- The customer side of staff access: a dashboard banner where an owner or admin approves or revokes a staff grant request, and staff decryptions in the org's activity log.
- Customer settings pages read their bounds from the same settings registry, so a customer can change only what their plan allows.

## Identity and tenancy
- Org, project, membership (`owner`, `member`, `viewer`).
- Email + password to start, plus one OAuth provider (Google) if it stays small. Session cookies are httpOnly, Secure, SameSite=Lax.
- Org-scoped API keys in the form `ins_api_<public_id>_<secret>`: shown once, stored only as an HMAC, identified in the UI by the public id, revocable. Used by the runner enroll flow and later CI.
- Every API route resolves `org_id` from the session or key, then sets the RLS GUC. No `org_id` query parameter that the client can switch.
- Invite by email. Viewer cannot launch scans or read raw transcripts (metadata only).

## Design system: apple-design skill
All dashboard work follows the **apple-design** skill, installed in the repo at `.agents/skills/apple-design/SKILL.md` (source: `npx skills add https://github.com/emilkowalski/skills --skill apple-design`). Anyone building or reviewing UI, human or agent, reads it first. The skill is written for general interfaces; these are the rules it turns into for a security dashboard, where users spend long sessions triaging and must trust what they see.

**Foundations (skill section 16)**
- **Purpose and simplicity.** The common path comes first: add target, launch scan, triage findings. Advanced settings (custom coverage per attack family, request templates, rate limits) sit one level deeper.
- **Agency with forgiveness.** Finding status changes, dismissals, and filters are undoable with a toast. Confirmation dialogs are only for irreversible actions: deleting a target, revoking a runner, deleting an org, stopping a running scan.
- **Responsibility.** Evidence and secrets are shown only when asked for (click to reveal, logged). Direct-mode scans show exactly which hosts will be hit and from which IPs before launch.
- **Familiarity and specific labels.** Navigation items are named for their contents: "Targets", "Scans", "Findings", "Runners", "Reports". Never "Home" or "Overview".
- **Wayfinding.** Every screen answers where am I (breadcrumb: org, project, target), where can I go, and how do I get out.
- **Feedback in four kinds:** status (live scan progress), completion (scan done, with a summary), warning (budget at 80%, verification expiring), error (runner offline, with the fix). Forms validate inline, never on submit.

**Motion (skill sections 1-11)**
- One motion library: Motion (MIT). Default spring is critically damped (`bounce: 0`, `duration: 0.3-0.4`). Bounce only on momentum gestures, such as flicking the finding drawer closed.
- Press feedback on pointer-down (`scale(0.97)`, 100 ms). No artificial delays or debounces on the input path.
- The finding detail drawer and the scan-launch sheet track the pointer 1:1, can be grabbed mid-animation, hand off release velocity, and rubber-band at their bounds.
- Popovers and menus scale from their trigger (`transform-origin` at the trigger). Panels leave the way they came.
- Only `transform` and `opacity` animate. Live scan progress uses springs on counters and bars, so updates arriving over the WebSocket never jump.

**Materials and typography (skill sections 12, 15)**
- The sidebar uses a heavier material; the top bar and the scan-launch sheet use light translucent material (`backdrop-filter`) with content scrolling under it. Translucent layers are never stacked.
- Modal tasks (launch scan, add credential) dim the background. Parallel panels (finding drawer) do not, so triage flow is not broken.
- Severity colors sit on solid badges, never on translucent surfaces, and are always paired with a text label, never color alone.
- Font: Sora 400 and 600, self-hosted from `brand/fonts/`, with size-specific tracking (headings `-0.02em`, body `0`, small labels slightly positive), spacing in `rem`, and dense but legible leading in tables. Evidence and payloads use a monospace face. Buttons use navy text on orange.
- Light and dark themes, with a smooth crossfade between them.

**Accessibility (skill section 14, plus WCAG 2.2 AA)**
- `prefers-reduced-motion`: springs and slides become short crossfades. `prefers-reduced-transparency`: materials become solid. `prefers-contrast: more`: solid backgrounds with defined borders.
- Every flow works by keyboard, and every drag gesture has a button alternative.

**Process (skill section 17)**
- Each screen starts as an interactive prototype that is reviewed before it is wired to the API. Motion is reviewed at slow speed.
- Shared tokens and primitives live in `dashboard/src/design/`: spring presets, materials, type scale, severity palette. Screens never define their own timing or colors.
- The UI review checklist in pull requests is the skill's Quick Reference table plus the four-kinds-of-feedback rule.

## Screens (`dashboard/`)
React, Vite, TypeScript, Tailwind, shadcn/ui (restyled to the design system above), Motion, TanStack Query.
1. **Sign up / sign in / org switcher.**
2. **Runners.** List, status (connected, last heartbeat, version, modes), create enrollment token, revoke. Copy-paste install snippet for the Go binary. No mention of internal components.
3. **Targets.** The wizard starts with one question: **"Is this target reachable from the internet?"**
   - **Yes: connect directly (no install).** The customer enters the URL and hosts, then proves ownership with a DNS TXT record, a `/.well-known/insidia-verify.txt` file, or a meta tag. The wizard shows our fixed egress IPs to allowlist. Credentials go in through the [secrets flow](14-database-schema.md#customer-secrets): cloud secret manager reference, OAuth client, or a stored write-only value. After saving, only the kind, label, date, and fingerprint are shown.
   - **No, or I want deeper tests: use a runner.** The customer picks or enrolls a runner, a mode (relay or tunnel), and a secret reference name that the runner resolves locally.
   - Both paths then set transport, request template, response selector, and rate limit. **Validate** calls Phase 1 `ValidateTarget` and shows latency and a redacted sample.
   - A side panel lists which test families are available in the chosen mode and which need a runner (from `probes.requires_runner`), with a "why use a runner" explanation.
4. **Scans.** Pick target and profile ("AI chat baseline", "Web baseline"), then coverage: **Standard** (one engine per attack family), **Thorough** (every engine that covers the family, results cross-validated), or **Custom** (per family). The launch sheet shows estimated attempts, cost, and duration, and which engines will run. Show state, budget, and progress counts; cancel and pause. A free account sees the sheet and is sent to upgrade; the launch call is refused server-side.
5. **Live view.** WebSocket fed by the Valkey pub/sub events the workers already emit (`scan.progress`, `finding.created`). Progress is shown per attack family and per engine name. Reconnect resumes from the scan row, not from socket memory.
6. **Findings.** Filters: severity, track (AI vs web), engine, status (`open`, `accepted`, `fixed`, `false_positive`), cross-validated. Detail drawer: attack, redacted response, evidence hash, the engine and probe, taxonomy ids. Exposed secrets appear only as masked tokens (`[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`) with a "match against my key" helper that computes the fingerprint in the browser.
7. **Usage.** Charts of attempts and tokens per day per project.
8. **Settings.** Org name, members, API keys, default redaction rules (regex list stored per org and pushed to the runner on next heartbeat).
9. **Plan and billing.** Current plan, credits remaining, usage (attempts, tokens, GPU time), what the paid plan unlocks, and the **Upgrade** button.

## API additions
- Auth routes, membership CRUD, API keys.
- Pagination and cursor on findings.
- Explicit response models. `engine` and the upstream probe id are public fields. A test fails if a secret or another org's data appears.
- Audit of who launched and who changed finding status (table `audit_events`, see [14-database-schema.md](14-database-schema.md); full actor model in Phase 10).
- Direct-mode routes: start verification, check verification, list egress IPs. A direct scan is refused unless every host is verified and unexpired.
- Credential routes are write-only: create, replace, delete. No read route exists.
- Plan routes: read entitlements, credits, and usage; `POST /upgrade` records intent and (later milestone) starts checkout. Scan-launch returns 402 with an upgrade link when the plan or the credits do not allow it. A free account can `POST` a CLI run upload.
- Every page links to the matching section of the customer docs ([15-customer-docs.md](15-customer-docs.md)), so help is in context.

## Realtime
API process subscribes to `progress:{org_id}:{scan_id}` and forwards to sockets for members of that org only. Do not multiplex orgs on one channel.

## Tests
- Browser or component tests for the wizard (both direct and runner paths) and the finding drawer.
- Design checks: reduced-motion, reduced-transparency, and high-contrast snapshots for every screen; keyboard-only run through the full launch-and-triage flow; axe accessibility scan with zero serious issues.
- No secret is ever rendered: the component test plants credential canaries and asserts they never appear in the DOM.
- API tests: viewer cannot launch; cross-org id in the path returns 403; WebSocket subscription to another org's scan fails.
- Plan tests: a free account can upload a CLI run and cannot launch a scan (402); a credit balance of zero refuses a hosted-model scan with 402; after the plan changes to paid, the next launch runs.
- Validate flow against the Phase 1 fixtures.

## Risks
- Template editors are an injection footgun (the runner sends whatever the template says). Validate only sends a fixed benign prompt. Document that the template is customer-authored and scoped by the allowlist.
- Email delivery needs a provider. Dev uses Mailpit in compose. Production choice can wait, but the interface (send verify, send invite) is fixed here.
