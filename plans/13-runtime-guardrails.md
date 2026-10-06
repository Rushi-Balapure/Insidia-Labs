# Runtime guardrails (Phase 4)

> This file covers runtime guardrails, which are part of Phase 4. They reuse the Phase 1B and 1C detectors as inline policies. Scanning is a local CLI command, and attack generation lives in the CLI or in Cloud. A guardrail that needs our GPUs is paid; a policy file the user runs in their own proxy is free. Start this after a design partner is using the CLI (Phase 1) and Cloud (Phase 2).

Depends on: the oracles from [06-depth-checks.md](06-depth-checks.md) and the registry from [08-engine-registry.md](08-engine-registry.md).
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
An optional runtime guardrail reuses the scan-time detectors on live traffic. It is a forwarder that applies policies.

## Runtime guardrails
A proxy the customer places in front of their model or agent. It forwards traffic and applies policies.
- Policies are the Phase 1B and 1C oracles and detectors that can run on a single request: canary already-seen, secret redaction, tool allowlist, token budget.
- Actions: allow, redact, block. Log the decision to the org's event stream (a new `runtime_events` table, following [14-database-schema.md](14-database-schema.md): request metadata encrypted, prompts never stored unless opted in, and then as C2).
- Ideas may be taken from LLM Guard (MIT), NeMo Guardrails (Apache), and Pipelock (Apache). Reimplement the policy hooks. Do not ship their UIs.
- Fail closed or fail open is a per-policy switch, default fail open for latency, fail closed for the secret-redaction policy.
- Exit when started: a fixture request containing a canary is redacted, and the dashboard shows the event. Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## Gap-filling Insidia Labs modules (Phase 3)
From [16-coverage-gaps.md](16-coverage-gaps.md):
- **M-A15 predictive-ML pack:** adopt ART and TextAttack (both MIT) for evasion, membership inference, inversion, and model stealing on classifiers, recommenders, and vision or audio models (spec 3.11). Needs model access through the runner or SDK.
- **M-C6 smuggling and cache pack:** HTTP request smuggling, web cache poisoning, and cache deception.
- **M-C8 client-side pack:** prototype pollution, postMessage handlers, CSP and clickjacking weaknesses.

## Out of scope until a customer asks
A marketplace of third-party policies, blocking production traffic by default, and any desktop or tray app. The CLI is the local scanner, and the guardrail stays a forwarder with policies.

## Risks
- Runtime inline latency. Measure p95 before calling it a product.
- Guardrail scope creep into a second scanner. A feature that needs attack generation belongs in the CLI or in Insidia Cloud.
