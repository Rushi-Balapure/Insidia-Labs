# Phase 1 — Vertical slices (AI relay + classic tunnel)

Depends on: Phase 0. Blocks: Phase 2 and everything that scans.
Parent: [00-master-plan.md](00-master-plan.md). Coverage: layers 1 and the start of classic DAST in [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md).

## Goal
One shared brain can run many customers' scans at once. A Go runner either relays chat attempts (track A) or tunnels raw HTTP (track B), or, for public targets, the brain connects directly with no runner (track C). Findings come back through the API with tenant isolation, encrypted at rest, and without upstream engine names.

Tracks 1A, 1B, and 1C are parallel after the shared contracts land. Fair scheduling and capability registry v1 are part of this phase, not a follow-up.

## Exit
- **1A.** Runner enrolled to org A relays a scan of a localhost OpenAI-compatible chatbot. Findings are stored and readable only by org A. A second org's scan runs at the same time and cannot see org A's data or steal its runner.
- **1B.** Same runner (tunnel mode) lets a cloud worker reach a localhost web app. At least one SQLi or XSS-class finding is produced from our own fixture app, confirmed with the hosted callback server when the bug is blind.
- **Fairness.** With org A queued for 1,000 tasks and org B for 10, org B's tasks start before org A finishes. Per-org concurrency cap is enforced.
- **1C.** A verified public fixture (chatbot and web app) is scanned for AI and web findings with no runner installed. An unverified host and a redirect to `169.254.169.254` are both refused by the egress proxy.
- **Registry.** The same AI family runs in Standard mode (one engine) and Thorough mode (two engines), and Thorough merges duplicates into one cross-validated finding.
- Customer-visible JSON uses Insidia Labs probe ids only. The engine link lives only in internal tables (`scan_tasks.engine_id`, `finding_sources`) and never in API responses.
- A `pg_dump` after the exit scans contains no planted canary value: target names, URLs, hosts, payloads, responses, or credentials.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## Out of scope
Dashboard UX (Phase 2), full OWASP catalogs (Phase 3), multi-turn adaptive attacks (Phase 4), the pentest agent (Phase 5).

## Shared contracts (do these first)

### Protobuf (`shared/proto/relay.proto`)
Version the package `insidia.relay.v1`.
- `RunnerHello`: `runner_id`, `org_id`, `version`, `target_ids`, `allowlist_hosts`, `modes` (`RELAY`, `TUNNEL`).
- `AttemptRequest` / `AttemptResponse` as in the master plan, plus `org_id` on every message so the hub can reject a mismatch.
- `Heartbeat`, `KillSwitch`, `ValidateTarget` (one benign request, return status and latency).

Generate Go (runner + hub) and Python (workers). Contract test: a golden binary payload decodes the same in both.

### Data model (Alembic, forced RLS on every tenant table)
The tables, columns, and encryption rules are defined in [14-database-schema.md](14-database-schema.md); Phase 1 implements the Phase 1 tables from it. Highlights:
- `users` minimal (encrypted email plus blind index). Real login is Phase 2. Phase 1 authenticates API calls with an org-scoped service token stored only as an HMAC.
- `runners`, `runner_enrollment_tokens` (single use, short TTL, HMAC only), `runner_certs`.
- `targets` with `connection` (`direct` or `runner`); names, URLs, hosts, templates, selectors, and secret references are all encrypted. `target_verifications` and write-only `target_credentials` for direct mode.
- `engines`, `attack_families`, `capability_map`, `probes`, `probe_upstream_map` (registry v1).
- `scans` (with `coverage_mode`), `scan_tasks` (internal `engine_id`).
- `findings` with encrypted evidence, `evidence_bidx` for cross-engine dedup, `cross_validated`, and no engine column; `finding_sources` (internal); `evidence_objects`.
- `usage_events`: org, scan, kind (`attempt`, `model_token`, `tunnel_byte`, `egress_byte`), amount.
- Object storage keys: `org/{org_id}/scans/{scan_id}/{uuid}`, with every object encrypted by the org data key before upload.

### Secret redaction before storage
Before any evidence is persisted, the redactor in `engine/api/crypto/` replaces detected secrets with masked tokens (type, length, fingerprint), drops `Authorization`, `Cookie`, and similar headers from stored HTTP pairs, and masks PII by default. See [14-database-schema.md](14-database-schema.md#secrets-found-in-evidence).

### Hub (`engine/hub`)
Long-lived process. Runners connect outbound (mTLS). Dev compose may use a shared CA minted by the hub.
- Connection registry in Valkey: `runner_id -> hub instance`, last heartbeat, org_id. Ids only; the allowlist is loaded from Postgres (decrypted in the hub's memory), never cached in Valkey.
- **Relay RPC:** worker calls hub `POST /internal/attempts`. Hub forwards to the runner and waits up to `timeout_ms`. Unknown runner, wrong org, or host outside the allowlist returns an error. No cross-org routing.
- **Tunnel:** userspace WireGuard terminated at the hub. Cloud side does not give every scanner its own WG interface. The hub exposes an HTTP CONNECT proxy bound to a scan. The proxy's dials go through that scan's runner, and the runner enforces the host allowlist again.
- Backpressure: per-runner in-flight cap. Excess attempts get `429` so the Celery task retries with backoff.
- Kill switch: control plane sets `scans.kill_switch` and publishes on Valkey; the hub and the egress proxy drop in-flight work for that scan.

### Celery shape
A scan is not one long task.
1. `control.plan_scan` loads the profile, asks the capability registry which engines cover each attack family, applies the coverage mode (Standard or Thorough) and the connection mode (skipping runner-only probes for direct targets, and recording the skip), then enqueues a chord on RabbitMQ.
2. Group members are small: one probe or one batch of attempts (`ai.heavy` for garak/promptfoo, `classic.dast` for ZAP/Nuclei/Dalfox).
3. Finalizer `control.finalize_scan` marks the scan complete and rolls up counts.
Task time limit 10 minutes, soft limit 8. Retries on runner disconnect (max 3). The worker never opens a DB session without the envelope middleware from Phase 0.

### Fairness
Celery will drain whichever queue is hottest. Do not rely on that.
- Before a worker executes, `engine/workers/common/fairness.py` takes a Valkey token-bucket lease keyed by `org_id` and queue. No lease: retry the task after a jittered delay (`countdown`), do not busy-loop.
- Caps: default 4 concurrent tasks per org per queue, overridable per org.
- RabbitMQ priorities (`x-max-priority`): interactive dashboard scans outrank scheduled and CI scans.
- Dispatcher on `control`: round-robin across orgs that have queued scan work when fanning out the chord, so a 1,000-task org does not occupy the broker head-of-line alone.
- Budgets on the scan row: `max_attempts`, `max_tokens`, `max_wall_clock`. The lease check pauses the scan (state `paused_budget`) instead of killing the worker.

## Track 1A — AI relay

### Runner commands that must work
- `enroll --token` exchanges a one-time token for a client cert, stores it in the OS user config dir (not the cloud).
- `run` maintains the outbound mTLS stream, reconnects with backoff, heartbeats every 15s.
- `validate --target` sends one benign prompt through the template.

### Relay transports (minimum for exit)
HTTP JSON template + response JSONPath, and OpenAI-compatible chat completions. Session modes: stateless, cookie jar per `session_id`, and a body field for a conversation id. Anthropic, Bedrock, and Azure adapters are stubs with tests skipped, filled in Phase 4 if not needed sooner.

### Secrets
`secret_ref: env:SUPPORT_BOT_TOKEN` resolves in the runner process environment. The cloud stores the ref string only. Tests assert the token never appears in hub logs or the Celery result.

### Redaction
A small regex pack (API keys, emails) runs on the response before it is returned. The response flag `redacted=true` is stored. Customer-editable rules come in Phase 2 settings; Phase 1 ships defaults.

### Workers (own images, not Python 3.14 if the upstream package is not ready)
- **garak image.** Custom generator `RelayGenerator` calls the hub instead of an HTTP model. Point detectors at our judge endpoint only if garak's built-in detectors are enough for the slice; otherwise a simple string/canary detector is acceptable for exit. Raise generator parallelism so relay RTT is hidden.
- **promptfoo image (Node).** Provider `callApi` does the same hub call. Env: `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`, `PROMPTFOO_DISABLE_TELEMETRY=1`, `PROMPTFOO_DISABLE_SHARING=1`, `PROMPTFOO_DISABLE_UPDATE=1`. Attacker and grader models are our cloud model service, even if Phase 1 uses one commercial judge key we operate (not the customer's).

### Normalizer
Map raw results to `Finding`. Translate upstream probe names through `probe_upstream_map` (`dan.Dan_11_0` -> `insidia.llm.jailbreak.dan`). An unmapped upstream probe is a configuration error: its output is rejected and alerted to staff, never stored under an upstream name. Normalize the evidence, run the secret redactor, compute `evidence_bidx`, and merge on `(org_id, target_id, attack_family_id, evidence_bidx)`. A merge across two engines sets `cross_validated`.

### Canary oracle (module M-A3, first slice)
Every AI probe in the Phase 1 profiles carries a per-attempt canary. A finding needs the canary to appear (leak) or be obeyed (injection), so Phase 1 findings are deterministic, not judged. See [16-coverage-gaps.md](16-coverage-gaps.md).

### Fixture
A 50-line OpenAI-compatible Python app that leaks a canary if the user says "ignore previous instructions". CI runs the scan against it through the runner on localhost.

## Track 1B — classic tunnel

### Runner
Tunnel mode uses wireguard-go (userspace, no root). On hello, the runner advertises allowlist hosts. Dial to any other host is refused and audited locally.

### Scanners (own images)
- **ZAP** headless, proxy set to the hub CONNECT proxy for this scan. Parse alerts JSON.
- **Nuclei** and **Dalfox** CLIs, HTTP proxy pointed at the same CONNECT proxy. Parse JSON.
- Templates and rules are pinned in the image. Update by rebuilding the image, not by runners pulling from the internet.

### Callback server
Host interactsh (MIT) in our cloud, one correlation id per scan. Blind hits attach to that scan's finding. The runner does not embed interactsh.

### Fixture
A tiny app we own (planted SQLi and reflected XSS). Do not depend on a GPL scanner. CI must not scan third-party sites.

### Fingerprints
User-Agent and Server banners from scanners are rewritten at the CONNECT proxy to `Insidia LabsLabs`. Nuclei template ids are mapped to `insidia.web.*` through `probe_upstream_map` before the finding is saved, same as 1A.

## Track 1C — direct mode (no runner)

### Ownership verification
- Methods: DNS TXT record, `/.well-known/insidia-verify.txt`, or an HTML meta tag. The challenge token is shown once and stored only as an HMAC.
- Every host in the target's host list must be verified. Verification expires after 30 days and is re-checked before each scan.
- Unverified targets cannot run active tests.

### Egress proxy (`engine/egress/`)
- A fixed set of public egress IPs, published in the dashboard and docs so customers can allowlist them.
- Allows only hosts that are verified targets of the scan's org. Resolves DNS itself and refuses private, loopback, link-local, and IPv6 ULA addresses, including after redirects and DNS rebinding (the resolved IP is pinned for the connection).
- Applies the target's rate limit, the kill switch, and User-Agent rewriting to `Insidia LabsLabs`.
- Acts as the direct relay transport for AI targets, so engines use the same RelayTarget plugins as runner mode, and as the HTTP proxy for classic scanners.
- The only process that decrypts direct-mode credentials, for the running scan only.

### Credentials
Direct targets use the [customer secrets](14-database-schema.md#customer-secrets) options: cloud secret manager reference, OAuth client with per-scan minted tokens, or a stored write-only value. Phase 1 ships stored write-only values and OAuth client credentials; the cloud secret manager reference lands in Phase 2.

### Fixture
Public fixtures we host on a domain we own (chatbot and web app), verified by DNS TXT in CI.

## Capability registry v1
- Seed `engines`, `attack_families`, `capability_map`, and `probe_upstream_map` for the Phase 1 engines.
- Standard mode picks priority 1 per family; Thorough runs every enabled entry.
- The planner records which entries ran for each family, so the dashboard can show "2 Insidia Labs Engine modules ran".

## Engine isolation
Engine containers get no internet egress except the hub, the egress proxy, and our model service. A CI test runs each engine image behind a sniffing proxy and fails on any other outbound connection (telemetry, update checks, remote generation).

## Tests
- Two orgs, two runners, concurrent scans, cross-read fails (API and direct SQL as the app role).
- Direct mode: unverified host refused; expired verification refused; redirect and DNS-rebinding to private or metadata IPs refused.
- Stored credential never appears in API responses, logs, RabbitMQ messages, or Valkey.
- Planted secrets in a fixture response are stored only as masked tokens.
- Standard vs Thorough on the fixture: Thorough runs both engines and produces one cross-validated finding for the shared canary.
- Engine images make no unexpected outbound connections.
- Hub rejects an attempt whose `org_id` does not match the runner's org.
- Runner refuses a tunnel dial to a host not on the allowlist.
- Fairness test: org B makes progress while org A holds a large backlog.
- API finding payload snapshot has no upstream product names.
- Token from `secret_ref` is absent from hub and worker logs.

## Risks
- WG-in-userspace plus CONNECT proxy is the riskiest new code. Build the CONNECT proxy and allowlist first; add WireGuard once relay mode is green. Do not ship a raw L3 route into the customer LAN.
- Long probes will blow the 10-minute task limit. Split by probe in the planner; do not raise the limit to "however long garak takes".
- Commercial judge APIs refuse attack prompts. Phase 1 uses a deterministic canary detector for the fixture. Stand up the Stage 0 model service ([19-model-hosting.md](19-model-hosting.md): one 20 GB GPU, llama.cpp + GGUF) in this phase for garak/promptfoo generators that need a model, but do not block 1A on it; Phase 4A moves to Stage 1.
