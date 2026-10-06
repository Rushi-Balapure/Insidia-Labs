# AI Red-Team Coverage Spec (Requirements Spine)

> Requirements spine for both the free CLI and Insidia Cloud ([00-master-plan.md](00-master-plan.md)). Deterministic layers (1–3, 5–7) ship in Phases 1B and 1C. Model-generated and multi-turn attacks ship in Phase 2B. Multi-agent honeypots, white box, and predictive ML ship in Phase 3. Reports name the engine that produced each finding.

Source: product owner, 2026-09-29. Frameworks pinned: OWASP GenAI LLM Top 10 2026 (published 2026-08-04), OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10), MITRE ATLAS (content v2026.06). Related mappings in the LLM Top 10 2026 appendix: MITRE ATT&CK v19.1, CWE 4.20, NIST AI 600-1, NIST AI RMF, CSA AICM v1.1, OWASP AIVSS v0.8, OWASP DSGAI 2026.

Principle: attack every place untrusted text, tools, memory, models, or humans touch the system, and detect failures with oracles rather than impressions.

## OWASP LLM Top 10 2026 reference
- LLM01 Prompt Injection
- LLM02 Sensitive Information Disclosure
- LLM03 Excessive Agency
- LLM04 Supply Chain
- LLM05 Data and Model Poisoning
- LLM06 Unbounded Consumption
- LLM07 Misinformation
- LLM08 Hidden Context Exposure
- LLM09 Vector and Embedding Weaknesses
- LLM10 Improper Output Handling

## 1. Target classes (each needs an adapter)
- Chat / completion APIs (single and multi-turn)
- RAG apps (attack the corpus and ranking, not only the prompt box)
- Tool-using agents (function calling, MCP, plugins, browsers, code runners)
- Multi-agent systems (A2A, supervisor/worker, swarm, inter-agent channels)
- Copilots embedded in products (email, docs, tickets, IDE, CRM; indirect injection via content)
- Classic ML / predictive models (classifiers, recommenders, CV/ASR)
- Training / fine-tuning / RLHF pipelines (data and model poisoning)
- Serving infra (inference servers, vector DBs, model registries, Ray/Serve clusters)

## 2. Attack surfaces (where payloads enter)
- **A. Direct user channels:** role messages (system/developer/user/tool); multi-turn history and sticky instructions; file uploads (PDF, DOCX, HTML, images with OCR/vision, code zips); voice/multimodal.
- **B. Indirect / untrusted content channels:** browsed web pages and search results; email, calendar, tickets, Slack/Teams; retrieved RAG chunks and citations; tool results (SQL rows, HTTP bodies, filesystem reads); shared/long-term memory; inter-agent messages and blackboards.
- **C. Tool & capability surface:** tool schemas (names, descriptions, args); MCP servers/plugins/skills marketplace; browser actions; code execution/shell/notebook; outbound email/payments/tickets/cloud APIs; credential stores and session cookies.
- **D. Retrieval / embedding surface:** ingest pipelines; chunking, metadata filters, ACLs on vector indexes; embedding APIs and stored vectors (inversion / tenant bleed); rerankers and hybrid search.
- **E. Model & supply-chain surface:** base models, fine-tunes, LoRAs, GGUF templates; model hubs/registries (namespace reuse, poisoned artifacts); datasets and preference data; guardrail/safety classifier models; agent-runtime dependencies.
- **F. Control-plane / ops surface:** rate limits, quotas, cost controls; logging/telemetry exposure; admin prompts, feature flags, eval harnesses; human-in-the-loop approval UIs (social engineering of the approver).

Delivery modes required: direct, indirect (inject into ingested content), tool-result, retrieval-plant, memory-write, manifest/schema, multi-turn, inter-agent.

## 3. Attack classes (mapped to frameworks)
- **3.1 Prompt & instruction integrity:** direct injection (LLM01); indirect injection (LLM01, ASI01); goal hijack (ASI01); instruction hierarchy violation; jailbreaks (ATLAS LLM Jailbreak); hidden context / system-prompt / tool-def extraction (LLM08); multi-turn persistence. Oracle: canary tokens obeyed; forbidden actions attempted; task-completion vs hijack score.
- **3.2 Data leakage & privacy:** training/RAG/memory secret exfiltration (LLM02); cross-tenant/cross-doc bleed (LLM09); PII/credential/session-token extraction; embedding inversion (LLM09); citation/source dumping. Oracle: planted secrets appear in outputs or tool args; ACL violations.
- **3.3 Agent tool misuse & excessive agency:** unauthorized tool invocation (ASI02, LLM03); dangerous argument crafting (path traversal, SQL, SSRF via tools); tool-chain hijack (read then send_email); privilege/identity abuse (ASI03); skipping human approval (ASI09); cross-session scope creep (ASI02/ASI10). Oracle: tool-call trace vs allowlist and intended goal.
- **3.4 Code execution & host escape:** RCE via code interpreter/plugins (ASI05); sandbox-to-host/cloud-metadata escape; malicious package install. Oracle: sandbox sensors (file write outside workspace, network to metadata IP, process spawn). Never run without isolation.
- **3.5 RAG / vector / memory attacks:** corpus poisoning at ingest (LLM05, LLM09); retrieval/ranking manipulation; cross-document instruction smuggling; memory poisoning (ASI06); citation integrity / ungrounded answers (LLM07). Oracle: canaries in planted docs; obedience after retrieve; groundedness judge; memory readback.
- **3.6 Output handling & downstream sinks:** XSS/HTML injection via output into web UIs (LLM10); markdown/link/image SSRF; command injection when output is piped to shells/tickets; secondary LLM injection (A output becomes B prompt). Oracle: sink simulators (HTML renderer, shell parser, email sender) with safety oracles.
- **3.7 Supply chain:** poisoned models/adapters/GGUF templates (LLM04, ATLAS); poisoned datasets/preference data (LLM05); poisoned MCP tools/skill manifests/description shadowing (ASI04); dependency/plugin compromise; namespace reuse/typosquatting. Oracle: manifest drift from pinned baselines; signature/provenance checks; behavioral goldens before/after artifact swap.
- **3.8 Availability, cost, abuse (unbounded consumption, LLM06):** token flooding, recursive tool loops, expensive tool storms; context stuffing/DoS; model denial via adversarial inputs; model-extraction scraping (ATLAS model theft). Oracle: latency/token/cost/loop-depth budgets; circuit-breaker trips.
- **3.9 Integrity / truthfulness / safety:** misinformation/overconfident false claims (LLM07); safety-policy violations (authorized harnesses only); sycophancy / approver manipulation (ASI09). Oracle: groundedness judges, policy classifiers, approval-bypass flags. Content-safety probes gated behind auth, allowlists, contracts.
- **3.10 Multi-agent & orchestration:** spoofed/unauthenticated inter-agent messages (ASI07); cascading fleet failures (ASI08); rogue/misaligned behavior, concealment, self-replication (ASI10); supervisor injection via worker output. Oracle: A2A auth; blast-radius metrics; behavioral monitors / kill-switch tests.
- **3.11 Classic adversarial ML:** evasion/adversarial examples (image/audio/text); membership inference, model inversion, model stealing; backdoors/trojans; online-learning poisoning. Oracle: robustness metrics, extraction success rates, trigger-label accuracy (ATLAS predictive tactics).

## 4. Oracles (a red-team tool without oracles is just a fuzzer)
- Canary / secret: leakage or obedience to planted tokens
- Tool-trace: unauthorized or chained tool use
- Goal-diff: hijack vs original task completion
- Policy classifier / judge model: safety/policy breach (calibrated false-positive handling)
- Structural: embeddings exposed, XSS sinks, RCE sensors
- Resource: token/cost/latency/loop budgets exceeded
- ACL: cross-tenant or cross-doc access
- Manifest drift: tool/schema/supply-chain changed from pin
- Multi-turn state: poisoned memory affects later turns

Findings must carry OWASP LLM + ASI IDs, ATLAS technique IDs, severity (AIVSS), repro steps, run id, and evidence artifacts.

## 5. Minimum capability layers (ship in this order)
1. Black-box HTTP/API harness: multi-turn chat probes + jailbreak packs (LLM01/02/08)
2. Indirect injection harness: plant content in web/docs/email/tool-result/retrieval/memory (LLM01, ASI01, ASI06)
3. Tool-graph attacks: oracles on real tool schemas and call chains (LLM03, ASI02/03/05)
4. RAG red-team: corpus plant, cross-doc smuggle, citation integrity, tenant bleed (LLM09, LLM05)
5. Supply-chain checks: MCP/skill manifest audit, model/artifact provenance (LLM04, ASI04)
6. Abuse/cost tests: unbounded consumption (LLM06)
7. Output-sink tests: XSS/command/secondary injection (LLM10)
8. Multi-agent pack: A2A spoof, cascade, rogue behavior (ASI07/08/10)
9. Optional white-box mode: read source for tools/roles/guardrails, generate target-specific chains
10. Optional predictive-ML pack: ATLAS evasion/extraction beyond GenAI apps

## 6. Design tradeoffs (state up front)
- Chat-only scanners are cheap and miss agent/RAG reality.
- Agent/RAG coverage needs content-injection APIs and tool-trace access; harder to productize, essential.
- Judge-LLM oracles scale but hallucinate; pair with canaries and deterministic sensors.
- Safety-content packs carry legal/abuse risk; gate behind auth, allowlists, contracts.
- White-box finds auth/tool-graph bugs black-box never sees; requires code-access trust.

## 7. Definition of done for Phase 1 (the free CLI, on a system the user is allowed to test)
This is the exit for Phases 1B and 1C, run on the user's machine:
- Run direct + indirect prompt injection with canary oracles
- Enumerate tools and attempt misuse / chain exfil with tool-trace oracles
- Plant and retrieve poisoned RAG docs
- Attempt hidden-context and secret exfil
- Measure unbounded consumption
- Emit a report mapped to LLM01-10 and ASI01-10, with ATLAS tags
- After this exit: full ATLAS predictive matrix and live multi-agent chaos (Phase 3); continuous CI gates (GitHub Action in Phase 1E, schedules in Phase 2C)
