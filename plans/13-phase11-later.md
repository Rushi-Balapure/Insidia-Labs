# Phase 11 — Later (runtime guardrails)

Depends on: a shipped runner (Phase 1+) and a dashboard (Phase 2+). Runtime guardrails depend on the Phase 4 oracles and the Phase 6 registry.
Parent: [00-master-plan.md](00-master-plan.md).
This phase is not on the critical path. Do not start it before a design partner is using Phases 1–3.

## Goal
An optional runtime guardrail on the same brain that reuses the scan-time detectors on live traffic. It does not change the "cloud brain, thin edge" decision. (The runner stays command-line and dashboard-managed; there is no desktop app.)

## Runtime guardrails
A proxy the customer places in front of their model or agent. It is a forwarder with policies, not a second scanner brain.
- Policies are the Phase 4 oracles and detectors that can run on a single request: canary already-seen, secret redaction, tool allowlist, token budget.
- Actions: allow, redact, block. Log the decision to the org's event stream (a new `runtime_events` table, following [14-database-schema.md](14-database-schema.md): request metadata encrypted, prompts never stored unless opted in, and then as C2).
- Ideas may be taken from LLM Guard (MIT), NeMo Guardrails (Apache), and Pipelock (Apache). Reimplement the policy hooks. Do not ship their UIs.
- Fail closed or fail open is a per-policy switch, default fail open for latency, fail closed for the secret-redaction policy.
- Exit when started: a fixture request containing a canary is redacted, and the dashboard shows the event.

## Gap-filling Insidia Labs modules (later)
From [16-coverage-gaps.md](16-coverage-gaps.md):
- **M-A15 predictive-ML pack:** adopt ART and TextAttack (both MIT) for evasion, membership inference, inversion, and model stealing on classifiers, recommenders, and vision or audio models (spec 3.11). Needs model access through the runner or SDK.
- **M-C6 smuggling and cache pack:** HTTP request smuggling, web cache poisoning, and cache deception.
- **M-C8 client-side pack:** prototype pollution, postMessage handlers, CSP and clickjacking weaknesses.

## Out of scope until a customer asks
A local brain, a marketplace of third-party policies, blocking production traffic by default, and any desktop or tray app (dropped: the runner stays CLI/dashboard-managed).

## Risks
- Runtime inline latency. Measure p95 before calling it a product.
- Guardrail scope creep back into a local engine. If a feature needs attack generation, it belongs in the cloud brain.
