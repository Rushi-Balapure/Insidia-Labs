# Phase 1 — Vertical slices (AI relay + classic tunnel)

Depends on: Phase 0. Blocks: Phase 2 and everything that scans.
Parent: [00-master-plan.md](00-master-plan.md). Coverage: layers 1 and the start of classic DAST in [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md).

## Goal
One shared brain can run many customers' scans at once. A Go runner either relays chat attempts (track A) or tunnels raw HTTP (track B). Findings come back through the API with tenant isolation and without upstream engine names.

Tracks 1A and 1B are parallel after the shared contracts land. Fair scheduling is part of this phase, not a follow-up.

## Exit
- **1A.** Runner enrolled to org A relays a scan of a localhost OpenAI-compatible chatbot. Findings are stored and readable only by org A. A second org's scan runs at the same time and cannot see org A's data or steal its runner.
- **1B.** Same runner (tunnel mode) lets a cloud worker reach a localhost web app. At least one SQLi or XSS-class finding is produced from our own fixture app, confirmed with the hosted callback server when the bug is blind.
- **Fairness.** With org A queued for 1,000 tasks and org B for 10, org B's tasks start before org A finishes. Per-org concurrency cap is enforced.
- Customer-visible JSON uses Insidia probe ids only. `Finding.engine` exists in the database and is absent from API responses.

## Out of scope
Dashboard UX (Phase 2), full OWASP catalogs (Phase 3), multi-turn adaptive attacks (Phase 4), the pentest agent (Phase 5).

## Shared contracts (do these first)

### Protobuf (`shared/proto/relay.proto`)
Version the package `insidia.relay.v1`.
- `RunnerHello`: `runner_id`, `org_id`, `version`, `target_ids`, `allowlist_hosts`, `modes` (`RELAY`, `TUNNEL`).
- `AttemptRequest` / `AttemptResponse` as in the master plan, plus `org_id` on every message so the hub can reject a mismatch.
- `Heartbeat`, `KillSwitch`, `ValidateTarget` (one benign request, return status and latency).

Generate Go (runner + hub) and Python (workers). Contract test: a golden binary payload decodes the same in both.

### Data model (Alembic, RLS on every tenant table)
- `users` (minimal: id, email, org_id). Real login is Phase 2. Phase 1 authenticates API calls with an org-scoped service token stored hashed.
- `runners`, `enrollment_tokens` (single use, short TTL), `runner_certs`.
- `targets`: org, project, runner_id, mode, transport, request template, response selector, secret_ref (a name, never a value), session mode, rate limit.
- `scans`, `scan_tasks` (one row per Celery task: state, queue, attempt counts).
- `findings`: internal `engine` column; API schema omits it. External `probe_id` is ours (`insidia.llm.direct_injection`, `insidia.web.xss`).
- `usage_events`: org, scan, kind (`attempt`, `token`, `tunnel_byte`), amount.
- Object storage keys: `org/{org_id}/scans/{scan_id}/...`.

### Hub (`engine/hub`)
Long-lived process. Runners connect outbound (mTLS). Dev compose may use a shared CA minted by the hub.
- Registry in Redis: `runner_id -> connection`, last heartbeat, allowlist, org_id.
- **Relay RPC:** worker calls hub `POST /internal/attempts`. Hub forwards to the runner and waits up to `timeout_ms`. Unknown runner, wrong org, or host outside the allowlist returns an error. No cross-org routing.
- **Tunnel:** userspace WireGuard terminated at the hub. Cloud side does not give every scanner its own WG interface. The hub exposes an HTTP CONNECT proxy bound to a scan. The proxy's dials go through that scan's runner, and the runner enforces the host allowlist again.
- Backpressure: per-runner in-flight cap. Excess attempts get `429` so the Celery task retries with backoff.
- Kill switch: control plane sets a Redis flag; hub drops in-flight work for that scan.

### Celery shape
A scan is not one long task.
1. `control.plan_scan` loads the profile and enqueues a chord.
2. Group members are small: one probe or one batch of attempts (`ai.heavy` for garak/promptfoo, `classic.dast` for ZAP/Nuclei/Dalfox).
3. Finalizer `control.finalize_scan` marks the scan complete and rolls up counts.
Task time limit 10 minutes, soft limit 8. Retries on runner disconnect (max 3). The worker never opens a DB session without the envelope middleware from Phase 0.

### Fairness
Celery will drain whichever queue is hottest. Do not rely on that.
- Before a worker executes, `engine/workers/common/fairness.py` takes a Redis token-bucket lease keyed by `org_id` and queue. No lease: retry the task after a jittered delay (`countdown`), do not busy-loop.
- Caps: default 4 concurrent tasks per org per queue, overridable per org.
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
Map raw results to `Finding`. Translate upstream probe names through an internal map (`garak.probe.dan.Dan_11_0` -> `insidia.llm.jailbreak.dan`). Unmapped probes still store under `insidia.unmapped.<hash>` and never echo the upstream string. Dedup key: `(org_id, target_id, probe_id, evidence_hash)`.

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
User-Agent and Server banners from scanners are rewritten at the CONNECT proxy to `InsidiaScanner`. Nuclei template ids are mapped to `insidia.web.*` before the finding is saved, same as 1A.

## Tests
- Two orgs, two runners, concurrent scans, cross-read fails (API and direct SQL as the app role).
- Hub rejects an attempt whose `org_id` does not match the runner's org.
- Runner refuses a tunnel dial to a host not on the allowlist.
- Fairness test: org B makes progress while org A holds a large backlog.
- API finding payload snapshot has no upstream product names.
- Token from `secret_ref` is absent from hub and worker logs.

## Risks
- WG-in-userspace plus CONNECT proxy is the riskiest new code. Build the CONNECT proxy and allowlist first; add WireGuard once relay mode is green. Do not ship a raw L3 route into the customer LAN.
- Long probes will blow the 10-minute task limit. Split by probe in the planner; do not raise the limit to "however long garak takes".
- Commercial judge APIs may refuse attack prompts. Phase 1 can use a deterministic canary detector for the fixture, and Phase 4 brings self-hosted attacker models. Do not block 1A on vLLM.
