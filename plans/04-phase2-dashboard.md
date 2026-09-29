# Phase 2 — Web dashboard and tenancy

Depends on: Phase 1 API (scans, findings, runners). Blocks: a non-engineer using the product.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A customer can sign up, create an org, enroll a runner, define a target, launch an AI or web scan, watch it live, and triage findings. One brain, many users, many scans. The UI never shows upstream engine names.

## Exit
- New user signs up, verifies email, lands in an org.
- They enroll a runner (token shown once), see it healthy, run validate, launch a scan from a profile, and open a finding transcript.
- A second user in another org cannot open those URLs (403, not 404 with a leak).
- Usage (attempts, tokens, tunnel bytes) is visible per org.
- Live progress updates over WebSocket without refreshing.

## Out of scope
SSO/SAML (Phase 10), compliance PDFs (Phase 3), agent graphs (Phase 7), billing charges (metering only).

## Identity and tenancy
- Org, project, membership (`owner`, `member`, `viewer`).
- Email + password to start, plus one OAuth provider (Google) if it stays small. Session cookies are httpOnly, Secure, SameSite=Lax.
- Org-scoped API keys (hashed, prefix shown, revoke). Used by the runner enroll flow and later CI.
- Every API route resolves `org_id` from the session or key, then sets the RLS GUC. No `org_id` query parameter that the client can switch.
- Invite by email. Viewer cannot launch scans or read raw transcripts (metadata only).

## Screens (`dashboard/`)
React, Vite, TypeScript, Tailwind, shadcn/ui, TanStack Query.
1. **Sign up / sign in / org switcher.**
2. **Runners.** List, status (connected, last heartbeat, version, modes), create enrollment token, revoke. Copy-paste install snippet for the Go binary. No mention of internal components.
3. **Targets.** Wizard: name, runner, mode (relay or tunnel), transport, request template, response selector, secret ref name, allowlist hosts, rate limit. **Validate** button calls Phase 1 `ValidateTarget` and shows latency and a redacted sample.
4. **Scans.** Pick target and profile (the two Phase 1 profiles are enough: "AI chat baseline", "Web baseline"). Show state, budget, progress counts. Cancel and pause.
5. **Live view.** WebSocket fed by Redis pub/sub events the workers already emit (`scan.progress`, `finding.created`). Reconnect resumes from the scan row, not from socket memory.
6. **Findings.** Filters: severity, track (AI vs web), status (`open`, `accepted`, `fixed`, `false_positive`). Detail drawer: attack, redacted response, evidence hash, taxonomy ids if present (labels can be raw ids until Phase 3). No engine field.
7. **Usage.** Charts of attempts and tokens per day per project.
8. **Settings.** Org name, members, API keys, default redaction rules (regex list stored per org and pushed to the runner on next heartbeat).

## API additions
- Auth routes, membership CRUD, API keys.
- Pagination and cursor on findings.
- Explicit response models so `engine` cannot leak by accident. A test unmarshals the public schema and fails if `engine` or known upstream names appear.
- Audit of who launched and who changed finding status (table `audit_log`, full actor model in Phase 10).

## Realtime
API process subscribes to `progress:{org_id}:{scan_id}` and forwards to sockets for members of that org only. Do not multiplex orgs on one channel.

## Tests
- Browser or component tests for the wizard and finding drawer.
- API tests: viewer cannot launch; cross-org id in the path returns 403; WebSocket subscription to another org's scan fails.
- Validate flow against the Phase 1 fixtures.

## Risks
- Template editors are an injection footgun (the runner sends whatever the template says). Validate only sends a fixed benign prompt. Document that the template is customer-authored and scoped by the allowlist.
- Email delivery needs a provider. Dev uses Mailpit in compose. Production choice can wait, but the interface (send verify, send invite) is fixed here.
