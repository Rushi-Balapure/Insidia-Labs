# Phase 2 — Web dashboard and tenancy

Depends on: Phase 1 API (scans, findings, runners). Blocks: a non-engineer using the product.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A customer can sign up, create an org, enroll a runner, define a target, launch an AI or web scan, watch it live, and triage findings. One brain, many users, many scans. The UI never shows upstream engine names.

## Exit
- New user signs up, verifies email, lands in an org.
- They enroll a runner (token shown once), see it healthy, run validate, launch a scan from a profile, and open a finding transcript.
- They add a public target with no runner, verify it by DNS TXT, launch a direct scan, and see which test families were skipped because they need a runner.
- Every screen passes the apple-design review checklist and the accessibility checks below.
- A second user in another org cannot open those URLs (403, not 404 with a leak).
- Usage (attempts, tokens, tunnel bytes) is visible per org.
- Live progress updates over WebSocket without refreshing.

## Out of scope
SSO/SAML (Phase 10), compliance PDFs (Phase 3), agent graphs (Phase 7), billing charges (metering only).

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
- Font: `system-ui` stack with size-specific tracking (headings `-0.02em`, body `0`, small labels slightly positive), spacing in `rem`, and dense but legible leading in tables. Evidence and payloads use a monospace face.
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
4. **Scans.** Pick target and profile ("AI chat baseline", "Web baseline"), then coverage: **Standard** (fastest, one Insidia Engine module per attack family), **Thorough** (every module that covers the family, results cross-validated), or **Custom** (per family). The launch sheet shows estimated attempts, cost, and duration for the chosen coverage. Show state, budget, and progress counts; cancel and pause.
5. **Live view.** WebSocket fed by the Valkey pub/sub events the workers already emit (`scan.progress`, `finding.created`). Progress is shown per attack family and per "Insidia Engine module N", never by real engine name. Reconnect resumes from the scan row, not from socket memory.
6. **Findings.** Filters: severity, track (AI vs web), status (`open`, `accepted`, `fixed`, `false_positive`), cross-validated. Detail drawer: attack, redacted response, evidence hash, taxonomy ids if present (labels can be raw ids until Phase 3). Exposed secrets appear only as masked tokens (`[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`) with a "match against my key" helper that computes the fingerprint in the browser. No engine field.
7. **Usage.** Charts of attempts and tokens per day per project.
8. **Settings.** Org name, members, API keys, default redaction rules (regex list stored per org and pushed to the runner on next heartbeat).

## API additions
- Auth routes, membership CRUD, API keys.
- Pagination and cursor on findings.
- Explicit response models so `engine` cannot leak by accident. A test unmarshals the public schema and fails if `engine` or known upstream names appear.
- Audit of who launched and who changed finding status (table `audit_events`, see [14-database-schema.md](14-database-schema.md); full actor model in Phase 10).
- Direct-mode routes: start verification, check verification, list egress IPs. A direct scan is refused unless every host is verified and unexpired.
- Credential routes are write-only: create, replace, delete. No read route exists.
- Every page links to the matching section of the customer docs ([15-customer-docs.md](15-customer-docs.md)), so help is in context.

## Realtime
API process subscribes to `progress:{org_id}:{scan_id}` and forwards to sockets for members of that org only. Do not multiplex orgs on one channel.

## Tests
- Browser or component tests for the wizard (both direct and runner paths) and the finding drawer.
- Design checks: reduced-motion, reduced-transparency, and high-contrast snapshots for every screen; keyboard-only run through the full launch-and-triage flow; axe accessibility scan with zero serious issues.
- No secret is ever rendered: the component test plants credential canaries and asserts they never appear in the DOM.
- API tests: viewer cannot launch; cross-org id in the path returns 403; WebSocket subscription to another org's scan fails.
- Validate flow against the Phase 1 fixtures.

## Risks
- Template editors are an injection footgun (the runner sends whatever the template says). Validate only sends a fixed benign prompt. Document that the template is customer-authored and scoped by the allowlist.
- Email delivery needs a provider. Dev uses Mailpit in compose. Production choice can wait, but the interface (send verify, send invite) is fixed here.
