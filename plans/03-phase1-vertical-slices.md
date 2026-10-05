# Vertical slices — local engines (Phase 1B) and Cloud connections (Phase 2C)

> **v6.** This file splits. The engine adapters, the normalizer, the capability registry, and the fixtures are **Phase 1A and 1B**: they run as local subprocesses inside the `insidia` CLI, on the user's machine, with no account. The hub, relay, tunnel, egress proxy, ownership verification, fairness, and encrypted Cloud storage are **Phase 2C**: they exist so Insidia Cloud can scan public and internal targets. Findings name the engine (`garak`, `ZAP`, or an Insidia module id). Secret masking stays. Probe ids stay stable (`insidia.llm.jailbreak.dan`) and the report also shows the upstream probe name.

Depends on: Phase 0 for the Cloud half. The CLI half depends on Phase 1.0 (the `core/` package).
Parent: [00-master-plan.md](00-master-plan.md). Coverage: layers 1 and the start of classic DAST in [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md).

## Goal
The CLI runs an AI probe and a web probe against a local fixture and writes findings that name the engine. Insidia Cloud, later, runs the same `core` package for many orgs at once: a Go runner relays chat (track A) or tunnels raw HTTP (track B), and public targets are scanned directly (track C). Cloud findings are tenant-isolated and encrypted at rest.

## Exit
- **Phase 1B, local.** `insidia scan` on Linux, macOS, and Windows runs garak (or promptfoo) and ZAP (or Nuclei) against the sandbox fixtures, with engines named in `findings.json`. Standard runs one engine per family; Thorough runs two and merges a cross-validated finding. No model is required for the canary cells.
- **Phase 2C, relay.** A runner enrolled to org A relays a scan of a localhost OpenAI-compatible chatbot. Findings are readable only by org A. A second org's scan runs at the same time and cannot see org A's data or steal its runner.
- **Phase 2C, tunnel.** The same runner lets a Cloud worker reach a localhost web app. A planted SQLi or XSS is confirmed with the hosted callback server when the bug is blind.
- **Fairness (2C).** With org A queued for 1,000 tasks and org B for 10, org B's tasks start before org A finishes.
- **Phase 2C, direct.** A verified public fixture is scanned with no runner. An unverified host and a redirect to `169.254.169.254` are refused by the egress proxy.
- A `pg_dump` of the Cloud database after the exit scans contains no planted canary value.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## Out of scope
The hosted dashboard (Phase 2C, [04-phase2-dashboard.md](04-phase2-dashboard.md)), the benchmark report format (Phase 1D), multi-turn adaptive attacks (Phase 2B), the pentest agent (Phase 2B).

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
- `findings` with encrypted evidence, `evidence_bidx` for cross-engine dedup, and `cross_validated`. `finding_sources` records the engine and upstream probe, and both are public. `evidence_objects` holds raw output, encrypted.
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

## Relay — AI targets through the runner

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
- **promptfoo image (Node).** Provider `callApi` does the same hub call. Env: `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`, `PROMPTFOO_DISABLE_TELEMETRY=1`, `PROMPTFOO_DISABLE_SHARING=1`, `PROMPTFOO_DISABLE_UPDATE=1`. Attacker and grader models are whatever the user configured (local, any API, or Insidia Cloud). With no model configured, the probe runs its static corpus and the canary detector only.

### Normalizer
Map raw results to `Finding`. Keep the upstream probe name (`garak`, `dan.Dan_11_0`) on the finding and also store the stable Insidia probe id (`insidia.llm.jailbreak.dan`) from `probe_upstream_map`. An unmapped upstream probe is stored with its upstream name and flagged `unmapped` so the registry can be updated; it is not dropped and not relabeled. Normalize the evidence, run the secret redactor, compute `evidence_bidx`, and merge on `(org_id, target_id, attack_family_id, evidence_bidx)`. A merge across two engines sets `cross_validated`.

### Canary oracle (module M-A3, first slice)
Every AI probe in the Phase 1 profiles carries a per-attempt canary. A finding needs the canary to appear (leak) or be obeyed (injection), so Phase 1 findings are deterministic, not judged. See [16-coverage-gaps.md](16-coverage-gaps.md).

### Fixture
A 50-line OpenAI-compatible Python app that leaks a canary if the user says "ignore previous instructions". CI runs the scan against it through the runner on localhost.

## Tunnel — raw HTTP through the runner

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
User-Agent is `Insidia Labs` plus the engine name and version, so a target owner can see what scanned them. Nuclei template ids are stored as-is and also mapped to `insidia.web.*` through `probe_upstream_map`.

## Direct — public targets, no runner

### Ownership verification
- Methods: DNS TXT record, `/.well-known/insidia-verify.txt`, or an HTML meta tag. The challenge token is shown once and stored only as an HMAC.
- Every host in the target's host list must be verified. Verification expires after 30 days and is re-checked before each scan.
- Unverified targets cannot run active tests.

### Egress proxy (`engine/egress/`)
- A fixed set of public egress IPs, published in the dashboard and docs so customers can allowlist them.
- Allows only hosts that are verified targets of the scan's org. Resolves DNS itself and refuses private, loopback, link-local, and IPv6 ULA addresses, including after redirects and DNS rebinding (the resolved IP is pinned for the connection).
- Applies the target's rate limit, the kill switch, and a User-Agent of `Insidia Labs` plus the engine name and version.
- Acts as the direct relay transport for AI targets, so engines use the same RelayTarget plugins as runner mode, and as the HTTP proxy for classic scanners.
- The only process that decrypts direct-mode credentials, for the running scan only.

### Credentials
Direct targets use the [customer secrets](14-database-schema.md#customer-secrets) options: cloud secret manager reference, OAuth client with per-scan minted tokens, or a stored write-only value. Phase 1 ships stored write-only values and OAuth client credentials; the cloud secret manager reference lands in Phase 2.

### Fixture
Public fixtures we host on a domain we own (chatbot and web app), verified by DNS TXT in CI.

## Capability registry v1
- Seed `engines`, `attack_families`, `capability_map`, and `probe_upstream_map` for the Phase 1 engines.
- Standard mode picks priority 1 per family; Thorough runs every enabled entry.
- The planner records which engines ran for each family, and the report names them.

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
- API finding payload names the engine and the upstream probe.
- Token from `secret_ref` is absent from hub and worker logs.

## Risks
- WG-in-userspace plus CONNECT proxy is the riskiest new code. Build the CONNECT proxy and allowlist first; add WireGuard once relay mode is green. Do not ship a raw L3 route into the customer LAN.
- Long probes will blow the 10-minute task limit. Split by probe in the planner; do not raise the limit to "however long garak takes".
- Commercial judge APIs often refuse attack prompts. The CLI uses a deterministic canary detector for the fixture and does not block on a model. The Stage 0 model service ([19-model-hosting.md](19-model-hosting.md): one 20 GB GPU, llama.cpp + GGUF) is Phase 2A, and it does not block the relay track. Phase 2B moves that service to Stage 1.
