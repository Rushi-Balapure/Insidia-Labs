# Phase 2C — Admin console (staff only)

> **v6.** The console stays staff-only, on an internal hostname. Engine names are no longer a reason for that: customers see them in the product. The console stays private because it sees every org's operations, grants, and health. The v5 trial fields below become Cloud credits and plan entitlements. It ships with the hosted dashboard, before the first design partner.

Parent: [00-master-plan.md](00-master-plan.md). Tables: [14-database-schema.md](14-database-schema.md). Engine registry: [08-phase6-engine-registry.md](08-phase6-engine-registry.md). Models: [19-model-hosting.md](19-model-hosting.md).

## Goal
One internal app where Insidia Labs staff can:
1. **See** the state of the platform and of each customer: health, usage, scans, runners, errors.
2. **Debug** a scan, runner, engine, or model call without reading customer data they have not been granted.
3. **Customize** each customer within safe bounds: plan limits, feature flags, coverage defaults, rate limits, model budget, retention, worker priority.

It replaces the "staff-only engine console" from the earlier plan; the engine registry becomes one section of it.

## Not in scope
- **No impersonation.** Staff cannot log in as a customer. "View as customer" renders metadata only; content needs a grant (below).
- **No way around encryption.** Customer content stays encrypted. The console decrypts only what a role and an active grant allow, through the key service, and every decryption is audited.
- **Not for customer admins.** Customers change their own settings in the customer dashboard. Some of those settings have bounds that staff set here (for example, retention can be 30 to 365 days on this plan).

## Access and isolation
- **Separate app and service.** Web app in `admin/` (React, Vite, TypeScript; same component library and apple-design rules as the dashboard, tuned for density). API in `engine/admin_api/`, a separate FastAPI deployment. The customer API has no admin routes, and the admin API is not on the customer ingress.
- **Separate network path.** Hostname on our internal domain, reachable only through the zero-trust proxy or VPN. Not on the public load balancer.
- **Separate identity.** Staff accounts live in `staff_users`, not `users`. Login is our staff SSO (OIDC), then a 6-digit code from an authenticator app (TOTP, RFC 6238: Google Authenticator, Microsoft Authenticator, 1Password, Authy, or similar).
  - Enrollment: a QR code shown once at first login, confirmed by entering a valid code. The TOTP secret is stored encrypted as C3 with the platform secrets key and is never shown again.
  - Ten single-use recovery codes, stored only as HMACs. Reset after losing a phone needs a second staff `admin` (two-person rule).
  - Each code is accepted once (replay blocked), with a ±1 step clock window. Five wrong codes lock the account for 15 minutes and alert `security`.
  - Sessions last 8 hours. Every write and every decryption asks for a fresh code (step-up), valid for 10 minutes.
  - TOTP codes can be phished, so the internal-only network path (zero-trust proxy or VPN) is a required control, not an extra.
- **Staff roles** (a staff user can hold several; only `support` is standing, the rest are elevated just in time, see "Security hardening"):

| Role | Can |
|---|---|
| `support` | Read metadata for every org; see org name and owner contact; request grants |
| `ops` | Everything `support` can, plus queues, retries, cancel, pause, kill switches, runner disconnect and cert revoke |
| `engineer` | Everything `support` can, plus the scan debugger internals, engine and model panels, registry change proposals |
| `admin` | Customer settings, plans, feature flags, staff role management |
| `security` | Grant and audit review, crypto-shred execution |

- **Two-person rule** for actions that are hard to undo or weaken safety: raising a limit above the plan maximum, turning off a safety control for an org (target verification, the rate-limit floor), suspending or deleting an org, crypto-shred, and granting staff roles. One staff user proposes; a second approves within 24 hours, or the proposal expires.
- **Database roles:**
  - `app_admin_read`: reads plaintext-safe (C0) columns across orgs only through `v_admin_*` views. Bypasses tenant RLS only via an explicit admin policy on those views; it cannot select base tables.
  - `app_admin_write`: writes `org_settings`, `org_feature_flags`, `feature_flags`, `staff_*`, and scan control commands. Nothing else.
  - Content decryption goes through the key service, which checks the staff role and any required grant.

## What staff can see
| Data | Example | Rule |
|---|---|---|
| C0 | ids, states, counts, durations, enums, error codes, engine and model names, versions | Always, for every staff role |
| Account contact | Org name, owner email, billing contact | `support` and above. Decrypted through the key service; every read logged to `staff_audit_events` |
| Other C1 | Project and target names, hostnames, URLs, member emails | Active `metadata` grant from the customer |
| C2 | Findings content, transcripts, requests and responses, evidence | Active `evidence` grant from the customer |
| C3 | Credentials, tokens, keys | Never, for anyone. Fingerprints only |

Grants come from the customer: a customer owner or admin approves a staff request in the dashboard ("Insidia Labs support requests evidence access for scan X, 24 hours"). Maximum 72 hours, revocable, and every staff decryption appears in the customer's audit log. Phase 2 ships the approve and revoke flow; Phase 10 adds self-service grant policies.

## Security hardening
The admin console sees every org, so it gets stronger controls than the customer dashboard. Each layer below assumes the one before it has failed. All of it ships in Phase 2, because the console holds real data from its first day.

### 1. Network: only reachable from where it should be
- **Identity-aware proxy in front of everything.** Staff reach the console only through a zero-trust proxy (Pomerium, Apache-2.0, self-hosted; or the cloud provider's identity-aware proxy) that checks SSO identity and device certificate before any packet reaches the admin app. A VPN alone is not enough.
- **No public address.** The admin web app and API have no public IP, no public DNS record, and no route from the customer load balancer. The internal DNS name resolves only inside the proxy's network.
- **Separate runtime.** Own Kubernetes namespace and node pool, with network policies: the admin API may reach Postgres (admin roles only), the key service, the RabbitMQ control exchange, Valkey (read-only), and the telemetry backend. No internet egress. Customer API and worker pods cannot open connections to it.
- **mTLS** between the proxy and the admin API, and between the admin API and the key service. The admin API rejects any request that did not come through the proxy (signed proxy header plus the mTLS client cert).

### 2. Devices: only managed staff laptops
- Access needs a **device certificate** issued only to company-managed laptops (disk encryption, screen lock, automatic OS updates, endpoint protection). No personal devices, no phones.
- The proxy checks the device certificate and posture on every request. A lost or stolen laptop is revoked centrally within minutes.
- Without hardware security keys, the device certificate is our strongest "something you have": a phished SSO password plus a phished TOTP code still fails from an unmanaged machine.

### 3. Accounts and sessions
- **Sign-in:** staff SSO (OIDC) plus authenticator-app TOTP (above). The SSO tenant itself enforces MFA and blocks legacy protocols.
- **Server-side sessions** in `staff_sessions`, bound to the staff user, device certificate fingerprint, and client IP. A change in device or IP ends the session.
- **Short sessions:** 30-minute idle timeout, 8-hour absolute limit, one active session per staff user. A new login ends the old one.
- **Cookies:** `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`; CSRF token on every write.
- **Instant revoke:** `security` can end any session, or all staff sessions at once (the console's own kill switch), effective on the next request.
- **Offboarding:** staff accounts are provisioned from the identity provider (SCIM). Disabling a person there removes console access within 15 minutes; a nightly job checks that every `staff_users` row matches an active IdP account.

### 4. Authorization: least privilege, just in time
- **Only `support` is standing.** `ops`, `engineer`, `admin`, and `security` are *eligible* roles. A staff user elevates for up to 4 hours with a reason and a ticket id; the elevation expires on its own. Elevating to `admin` or `security` needs a second staff approval (two-person rule).
- **Deny by default.** Every admin API route declares its required role and whether it needs step-up; a CI test fails on any route without a declaration. The UI hides what a role cannot do, but the API enforces it.
- **Two-person rule** applies from Phase 2 to every guarded action listed above, not only some.
- **Break-glass account:** one offline emergency account whose credentials are split between two founders and stored sealed. Using it pages everyone in `security`, and it is reviewed after every use.

### 5. Customer content is hostile
Insidia Labs stores attack transcripts, injected payloads, and responses from targets we were attacking. Anything customer-derived that reaches the console (org and target names, error text, transcripts) can contain a working XSS or prompt-injection payload aimed at staff.
- **Text only.** The console renders customer-derived strings as plain text. No HTML, no Markdown, no rich previews, no auto-linked URLs.
- **Transcripts and evidence** open in a sandboxed iframe on a separate origin (`sandbox` without `allow-scripts`, its own CSP), so even a perfect payload has no script context and no access to the console's cookies.
- **Strict Content Security Policy:** nonce-based scripts only, no inline scripts, no `eval`, Trusted Types enforced, `frame-ancestors 'none'`, `connect-src` limited to the admin API. HSTS with preload, COOP/COEP, `Referrer-Policy: no-referrer`.
- **No third-party code in the browser:** no analytics, no CDNs, no external fonts. Every asset is self-hosted with Subresource Integrity.
- **No outbound fetches.** The console never fetches a URL from customer data (no link previews, no favicons), so it cannot be turned into an SSRF.
- **Uploaded logos** (report branding) are decoded and re-encoded server-side to PNG, with size limits. SVG is rejected.
- **Tested:** the Phase T XSS and prompt-injection payload corpus is planted into a fixture org's names, errors, and transcripts, and the console is checked for script execution.

### 6. Limiting what one compromised account can take
- **No bulk export of customer data.** Lists are paginated with caps. There is no "export all orgs" or "export all contacts"; SOC 2 exports contain staff activity, not customer data.
- **Decryption budgets.** Each staff user has a per-hour limit on decryptions (contact fields and grant-based content), enforced in the key service. Hitting it blocks further decryption and alerts `security`.
- **The key service does not trust the admin API.** It re-checks the staff session token (signed by the auth service), the role, the elevation, and the grant on every decryption call. A compromised admin API alone cannot decrypt anything.
- **Watermarked views:** decrypted content shows the staff user's id and a timestamp as a visible overlay, to deter screenshots and trace leaks.
- **No caching:** `Cache-Control: no-store` on every admin API response; the browser keeps nothing on disk.
- **Short-lived database credentials** for the admin API, issued per pod by the secret store (dynamic credentials or cloud IAM database auth). No static passwords.

### 7. Detection
- Every `staff_audit_events` row streams to the SIEM in real time, and a daily hash of the chain goes to write-once storage, so a staff member with database access cannot erase their tracks.
- **Alerts** to `security` on: login from a new device, after-hours elevation to `admin` or `security`, decryption volume above baseline, many orgs viewed in a short time, failed TOTP bursts, use of a recovery code, break-glass use, any change to staff roles.
- **Canary org and honeytokens.** A fake customer org with realistic data exists in production. Any staff view or decryption of it is a high-severity alert, because no legitimate task touches it. Planted fake credentials in it alert if ever used anywhere.
- Monthly review of every staff decryption, signed off by `security`.

### 8. Supply chain and change control
- `admin/` and `engine/admin_api/` are protected by code owners; a change needs two reviewers, one from `security`.
- Minimal dependencies, pinned with lockfiles, scanned in CI (osv-scanner, Trivy). New dependencies need review.
- Images are built in CI, signed (Sigstore cosign), and an admission controller runs only signed images in the admin namespace.
- Deploys to the admin namespace need two approvals and run from CI only; no one has `kubectl exec` there in production.

### 9. Testing the console itself
- The console's threat model is a section of `internal/threat-model.md`, reviewed before each phase that changes it.
- Insidia Labs scans its own admin console in staging (web DAST, access control differ M-C3, XSS corpus) on every release.
- An external penetration test before the first design partner and yearly after, scoped to the console, proxy, and key service.
- Incident runbook: end all staff sessions, freeze elevations, rotate the admin API's credentials, preserve audit, notify affected customers per their contracts.

## Sections

### Customers
- List of orgs: id, plan, region, status, created, last scan, connected runners, usage this month against limits, scan failure rate, and a health flag (failing scans, offline runners, budget exhausted, expiring target verification).
- Search by org id, or by exact owner email through its blind index (no substring search over encrypted data).
- Org detail: overview, members (counts and roles; emails need a grant), runners, targets (kind, connection mode, verification status; names need a grant), scans, usage and cost, settings, staff activity, grants.

### Per-customer settings
The "customizability per customer". Every setting comes from a typed registry in code (`engine/admin_api/settings_registry.py`) with a type, bounds, a default per plan, and whether the customer can change it themselves within those bounds.

| Group | Examples |
|---|---|
| Plan and limits | Plan tier (free upload, credits, paid); credit balance; max concurrent scans; max targets and runners; attempts, tokens, and wall-clock per scan; monthly model-token and GPU-second budget |
| Entitlements | What each plan unlocks, as typed flags: hosted attacker, scans launched from the dashboard, Thorough coverage on our GPUs, pentest agent, scheduled scans, integrations, exports. Staff can grant credits (audited) |
| Features | Feature flags per org: direct mode, Thorough coverage, pentest agent, white box, beta Insidia Labs modules |
| Coverage | Default coverage mode; attack families or modules disabled for this org (for example, a module that breaks their target); Standard-mode pin per family |
| Safety | Per-target rate-limit ceiling, scan windows (hours scans may run), destructive-check opt-in. A floor exists that only the two-person rule can lower |
| Scheduling | Priority tier on the RabbitMQ queues; pin to a dedicated worker pool (Phase 9 and 10) |
| Models | Per-org model budget; judge confidence threshold within a bounded range; model tier (Stage 0 or Stage 1) during the migration |
| Data | Retention days within the plan's range; region is read-only after creation |
| Reports | Default frameworks for reports; report branding (logo and company name are customer data, so encrypted) |

How settings resolve:
- **Effective config = built-in default, then plan default, then org override**, validated against the registry's bounds.
- Resolved **once at scan launch** and stored on the scan as a snapshot with a hash, so a running scan never changes mid-way and every scan is reproducible.
- A setting change affects new scans only.
- Every change records who, what, before and after, and why, in `staff_audit_events`. A change that affects the customer also writes a customer-visible `audit_events` row ("Insidia Labs changed your concurrent scan limit from 2 to 5").
- Settings that name engines are stored by engine id internally. The customer dashboard shows them as module labels.

### Scan debugger
- Timeline of one scan: the Celery canvas as a tree (chord, groups, tasks), each task's state, queue, worker, engine (real name), retries, durations, and Insidia Labs error code.
- Internal error detail: stack traces and engine stderr, scrubbed by the secret redactor and stripped of payloads before they are stored. They are keyed by OpenTelemetry trace id, which links API, dispatcher, worker, hub or egress proxy, and model service spans.
- Relay and tunnel stats per scan: request count, latency percentiles, timeouts, bytes.
- Model calls per scan: role, model, tokens, latency, GPU-seconds. No prompts or completions.
- Budget consumption against the scan's limits, and the fairness gate's decisions for this org.
- Actions (`ops`): retry a failed task, cancel or pause a scan, resume a budget-paused scan with a one-time budget raise (two-person above the plan maximum).
- **Debug capture** (needs an evidence grant): for one scan, store full request and response detail for failing tasks, encrypted with the org key, auto-deleted after 7 days.

### Runners
- Fleet view: version, OS, mode (relay, tunnel), last heartbeat, connection history, latency, reconnect count, last errors, cert expiry.
- Outdated or vulnerable runner versions are flagged across all orgs.
- Actions (`ops`): force disconnect, revoke cert (customer is notified), mark a version as blocked.

### Platform health
- Queues: RabbitMQ depth and age per queue, consumers, redeliveries.
- Workers: pools, autoscaler state, busy and idle counts, OOM and crash counts per engine image.
- Fairness: per-org leases and token buckets in Valkey, top orgs by queued work.
- Egress proxy: requests, blocked requests by reason (unverified host, private range, redirect to metadata), fixed-IP health.
- OOB server: callbacks per scan.
- Kill switches (`ops`): global, per org, per target, per engine. A kill switch stops dispatch immediately and cancels in-flight tasks.

### Engines and modules
Built in Phase 6 ([08-phase6-engine-registry.md](08-phase6-engine-registry.md)):
- Real engine and module names, pinned versions and image digests, licenses.
- Benchmark results per (engine or module, attack family) from the Phase T suite, and production precision from customer triage (aggregated, never raw evidence).
- Error and timeout rates per engine version.
- Registry change proposals: staff draft a change; it ships as a reviewed migration, never as a direct write.

### Models
- Current stage per role, pinned model and SHA-256, runtime (llama.cpp or vLLM).
- Tokens per second, p95 latency, queue wait, GPU use and memory, and the Stage 0 to Stage 1 trigger metrics from [19-model-hosting.md](19-model-hosting.md).
- Benchmark results: attack success, judge precision and recall, refusal rate.
- Cost per scan, per org, per month.

### Test matrix
- Status of the Phase T permutation suite ([17-test-suite.md](17-test-suite.md)): green, red, xfail, and N/A cells per phase, from the latest nightly run.

### Staff activity
- Every staff action and decryption from `staff_audit_events`, filterable by staff user, org, action.
- Pending two-person approvals.
- Monthly access review export for SOC 2.

## Data model
New tables are in [14-database-schema.md](14-database-schema.md#admin-console-tables): `staff_users`, `staff_role_assignments`, `staff_role_elevations`, `staff_sessions`, `org_settings`, `feature_flags`, `org_feature_flags`, `staff_approvals`, `staff_audit_events`, and the `scans.config_snapshot` columns. `staff_access_grants.staff_user_id` now references `staff_users`.

## Delivery by phase
| Phase | Admin console scope |
|---|---|
| 2 | First version, needed before the first design partner: customers list and org detail, settings for plan and limits plus feature flags, scan debugger (timeline, states, errors, trace links), runner fleet, platform health with kill switches, grant request and approval flow, staff audit, and every control in "Security hardening" (proxy, device certs, sessions, just-in-time roles, two-person rule, hostile-content rendering, decryption budgets, alerts, canary org, signed images, external pentest) |
| 4 | Models section; debug capture; coverage and model settings groups |
| 6 | Engines and modules section; registry change proposals |
| 9 | Scheduling settings group with dedicated pools; schedule and CI-scan views |
| 10 | SOC 2 access review export; on-prem operator console |

**Self-hosted and private tenants:** the customer's operators get a reduced operator console (platform health, queues, runners, kill switches, settings, engines named). The full staff console stays in our SaaS.

## Tests
- Isolation: no customer session, API key, or runner cert can reach any admin route, and the admin hostname does not resolve or route from the public internet.
- Bundles: the customer dashboard bundle contains no admin routes or admin API URLs; the admin bundle is not served from a customer hostname.
- Data rules: `app_admin_read` cannot select base tables; C1 and C2 decryption fails without the matching grant; C3 is never returned by any admin route (planted-canary contract test).
- Settings: an out-of-bounds value is rejected; effective config is resolved at launch and stored on the scan; changing a setting mid-scan does not change the running scan.
- Two-person rule: the same staff user cannot approve their own proposal; an unapproved proposal expires.
- TOTP: a reused code is rejected; a write without a fresh step-up code is rejected; five wrong codes lock the account; the TOTP secret is absent from API responses, logs, and a database dump in plaintext.
- Audit: every write and every decryption produces a `staff_audit_events` row; customer-affecting changes also produce a customer-visible `audit_events` row.
- Kill switch: dispatch stops and in-flight tasks cancel within 10 seconds.
- Redaction: a forced engine error that includes a planted secret and payload stores neither in the error detail.
- Network: a request to the admin API that skips the proxy (no signed header or no mTLS cert) is rejected; an admin pod cannot reach the internet; a customer API pod cannot connect to the admin API.
- Device and session: a valid SSO login plus TOTP from a device without a staff certificate is refused; a session reused from another device or IP is ended; idle and absolute timeouts fire; "end all staff sessions" takes effect on the next request.
- Just-in-time roles: an expired elevation loses its permissions immediately; elevation to `admin` or `security` without a second approver fails; every route has a declared role (CI).
- Hostile content: the XSS and prompt-injection corpus planted in a fixture org executes nothing in the console; transcripts render only in the sandboxed origin; the CSP report endpoint receives no violations during the test run.
- Blast radius: the per-hour decryption budget blocks and alerts; the key service refuses a decryption call that has a valid admin API identity but no valid staff session token.
- Detection: viewing the canary org raises a high-severity alert; a break-glass login pages `security`.

## Risks
- **The admin console is the most valuable target we run.** It sees every org. Mitigations are layered in "Security hardening": identity-aware proxy, managed-device certificates, short device-bound sessions, just-in-time roles, two-person rule, hostile-content rendering, decryption budgets enforced by the key service, real-time alerts and a canary org.
- **TOTP is phishable.** Without hardware keys, the device certificate at the proxy is what stops a phished password plus code. If device certificates slip (for example, contractors on unmanaged machines), this risk reopens; do not make exceptions.
- **Stored XSS from scan data.** We hold attack payloads by design. Text-only rendering and the sandboxed evidence origin are mandatory, and the corpus test blocks release.
- **Insider misuse.** Grants are customer-approved and visible to the customer; staff decryptions are reviewed monthly.
- **Settings sprawl.** Every setting must be in the typed registry with bounds and a default; no free-form per-org JSON.
- **Debugging pressure to log payloads.** The scan debugger works from ids, codes, and traces. When that is not enough, debug capture asks for a grant; it never turns on plaintext logging.
