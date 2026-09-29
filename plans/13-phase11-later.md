# Phase 11 — Later (desktop and runtime)

Depends on: a shipped runner (Phase 1+) and a dashboard (Phase 2+). Runtime guardrails depend on Phase 6 detectors.
Parent: [00-master-plan.md](00-master-plan.md).
This phase is not on the critical path. Do not start it before a design partner is using Phases 1–3.

## Goal
Two optional products on the same brain: a desktop tray that makes the runner visible to a non-CLI user, and a runtime guardrail that reuses detectors on live traffic. Neither changes the "cloud brain, thin edge" decision.

## Desktop app
- Not the place scans are planned. It enrolls and supervises the Go runner, shows connection status, last heartbeat, local audit of requests the runner sent, and a link to the web dashboard.
- Shell: Tauri. UI can reuse dashboard components only if that stays a thin status view. Do not duplicate findings triage.
- The runner remains a separate Go process the shell starts. No attack logic in the shell.
- Updates: signed runner binary. The shell does not embed engine images.
- Exit when started: a user can enroll, see "connected", and open the scan they launched on the web.

## Runtime guardrails
A proxy the customer places in front of their model or agent. It is a forwarder with policies, not a second scanner brain.
- Policies are the Phase 6 detectors and oracles that can run on a single request: canary already-seen, secret regex, tool allowlist, token budget.
- Actions: allow, redact, block. Log the decision to the org's scan-like event stream (a new `runtime_events` table) without storing full prompts unless opted in.
- Ideas may be taken from LLM Guard (MIT), NeMo Guardrails (Apache), and Pipelock (Apache). Reimplement the policy hooks. Do not ship their UIs.
- Fail closed or fail open is a per-policy switch, default fail open for latency, fail closed for the secret-redaction policy.
- Exit when started: a fixture request containing a canary is redacted, and the dashboard shows the event.

## Out of scope until a customer asks
Offline desktop scanning, a local brain, marketplace of third-party policies, blocking production traffic by default.

## Risks
- Runtime inline latency. Measure p95 before calling it a product.
- Desktop scope creep back into a local engine. If a feature needs attack generation, it belongs in the cloud brain.
