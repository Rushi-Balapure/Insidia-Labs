# Coverage Gap Analysis and Insidia-Built Modules

**INTERNAL ONLY.** This file names upstream engines. It must never be copied into customer docs, the website, or sales material. Customer-facing coverage pages are generated from the capability registry, which shows only "Insidia Engine modules".
Parent: [00-master-plan.md](00-master-plan.md). Requirements: [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md). Registry: [08-phase6-engine-registry.md](08-phase6-engine-registry.md).

## Method
1. Take every requirement from the AI coverage spec (attack classes 3.1 to 3.11, surfaces A to F, oracles, target classes) and the classic AppSec scope in the master plan.
2. For each, record which engine covers it **in the way we run it**: in our cloud, with remote generation and telemetry off, through the relay or tunnel, with our own attacker and judge models.
3. Rate it: **Covered** (an engine does it well enough to ship), **Partial** (some variants, weak oracle, or only in some connection modes), or **Gap** (nothing we can use).
4. For every Partial or Gap, decide: **adopt** another permissively licensed tool, **build** an Insidia module, or **defer**.

Ratings come from each tool's documentation and our knowledge of it. They are hypotheses until the Phase 6 benchmark measures them (see [Validating this analysis](#validating-this-analysis)). Built modules plug into the same capability registry and appear to customers exactly like any other Insidia Engine module.

## Constraints that create gaps
- **promptfoo without remote generation.** We must keep `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`; otherwise customer prompts go to promptfoo's servers, and our use of it becomes visible to them. Per promptfoo's own data-handling docs, this disables:
  - plugins: all `harmful:*`, all `bias:*`, domain packs (medical, financial, insurance, pharmacy, ecommerce), `ssrf`, `bola`, `bfla`, `indirect-prompt-injection`, `ascii-smuggling`, `competitors`, `hijacking`, `off-topic`, `system-prompt-override`
  - strategies: `goat`, `gcg`, `citation`, `audio`, `jailbreak:composite`, `jailbreak:goblin`, `jailbreak:hydra`, `jailbreak:likert`, `jailbreak:meta`

  Plugins that still work locally include `prompt-extraction`, `excessive-agency`, `pii`, `rbac`, `debug-access`, `shell-injection`, `sql-injection`, `hallucination`, `overreliance`, `imitation`, `contracts`, `policy`, `intent`, and the RAG, memory, and MCP plugins that use our configured provider. promptfoo also warns that local-generation quality depends heavily on the model, so our attacker models matter.
- **Disabling remote generation is not network isolation.** promptfoo says it does not turn off telemetry, license checks, or sharing. We set `PROMPTFOO_DISABLE_TELEMETRY=1` and `PROMPTFOO_DISABLE_SHARING=1` as well, and engine containers get **no internet egress** except to the target path (relay, tunnel, or direct egress proxy) and our model service. A CI test runs each engine image with a sniffing proxy and fails on any other outbound connection.
- **Licenses exclude the usual classic tools:** sqlmap (GPLv2), commix, tplmap, Nikto, Wapiti, testssl.sh (GPL), nmap (NPSL), Semgrep registry rules, CodeQL (not licensed for commercial scanning of third-party code), trufflehog (AGPL). Each leaves a hole.
- **Commercial model APIs refuse attack generation.** Iterative attacks (TAP, PAIR, Crescendo, GOAT-style) need our self-hosted attacker models on vLLM.
- **Direct mode reaches only public endpoints.** Anything needing the customer's internal network, tool traces, or code needs the runner or the SDK.

## AI and agent coverage (spec section 3)
Engines: garak (G), promptfoo local-only (PF), PyRIT (PY), DeepTeam (DT), Strix-based agent (AG, Phase 5), mcp-scanner (MS), SkillSpector (SS), ModelScan (MO). Module ids refer to [Modules to build](#modules-to-build).

| Spec | Requirement | Today | Rating | Fill with |
| --- | --- | --- | --- | --- |
| 3.1 | Direct prompt injection | G, PF, DT, PY | Covered | Registry overlap only |
| 3.1 | Jailbreaks, single-turn | G, PF, DT | Covered | - |
| 3.1 | Jailbreaks, iterative and multi-turn (TAP, PAIR, Crescendo) | PY, DT; PF `goat` and meta jailbreaks lost | Partial | PY on our attacker models; M-A11 |
| 3.1 | Indirect injection (web, docs, email, tool results) | PY cross-domain attacks; PF plugin lost | Partial | M-A1, M-A2 |
| 3.1 | Hidden-context, system-prompt, and tool-definition extraction (LLM08) | PF `prompt-extraction`, G, DT | Partial: no canary proof | M-A3 |
| 3.1 | Instruction-hierarchy violation (system vs developer vs tool role) | Scattered | Gap | M-A3 |
| 3.1 | Multi-turn persistence and sticky instructions | PY | Partial | M-A11 |
| 3.1 | Multimodal injection (images, audio, OCR, file uploads) | G and PY converters (image, audio); PF `audio` lost | Partial | M-A2 |
| 3.1 | Invisible-character and encoding smuggling | G encoding probes; PF `ascii-smuggling` lost | Partial | M-A2 converters |
| 3.2 | Training, RAG, or memory secret exfiltration | PF `pii`, DT, G leak probes | Partial: needs planted canaries | M-A3, M-A5 |
| 3.2 | Cross-tenant and cross-document bleed | none | Gap | M-A6 |
| 3.2 | Embedding inversion | none | Gap | Defer to white box (M-A12) |
| 3.3 | Unauthorized tool calls, excessive agency (LLM03, ASI02) | PF `excessive-agency`, `rbac`, MCP plugin; DT agentic | Partial: judged on text, no tool trace | M-A4 |
| 3.3 | Dangerous tool arguments (SQLi, SSRF, path traversal through tools) | PF `sql-injection`, `shell-injection`; PF `ssrf` lost | Partial | M-A4 + AG |
| 3.3 | Tool-chain hijack (read then send) | none with a deterministic oracle | Gap | M-A4, M-A7 |
| 3.3 | Privilege and identity abuse (ASI03), BOLA/BFLA through agents | PF `bola`/`bfla` lost | Gap | M-A6 |
| 3.3 | Skipping human approval, approver manipulation (ASI09) | none | Gap | M-A9 |
| 3.4 | Code execution and sandbox escape (ASI05) | AG partially | Gap: no sensors | M-A8 |
| 3.5 | RAG corpus poisoning and retrieval manipulation | PF RAG poisoning plugins (local) | Partial: no ingest access | M-A5 |
| 3.5 | Memory poisoning (ASI06) | PF memory-poisoning (local) | Partial: single session only | M-A5 |
| 3.5 | Citation integrity and groundedness (LLM07) | PF `hallucination`, `overreliance`; PF `citation` lost | Partial | M-A5 judge |
| 3.6 | Output to sinks: XSS, markdown and image exfiltration, command injection (LLM10) | G web-injection probes | Partial: no rendering | M-A10 |
| 3.6 | Secondary LLM injection (A's output becomes B's prompt) | none | Gap | M-A7 |
| 3.7 | Malicious model files (pickle and similar) | MO | Covered | - |
| 3.7 | GGUF chat-template and adapter poisoning, model provenance | none | Gap | M-A13 |
| 3.7 | MCP and skill manifest poisoning, description shadowing, rug-pull (ASI04) | MS, SS | Partial: no hash pinning or drift | Phase 7 tool-hash pinning, M-A13 |
| 3.7 | Namespace reuse and typosquatting of models and packages | none | Gap | M-A13 |
| 3.8 | Unbounded consumption: token floods, reasoning DoS, repetition (LLM06) | PF `reasoning-dos`, `divergent-repetition`; G | Partial: no cost oracle | M-A14 |
| 3.8 | Recursive tool loops and tool storms | none | Gap | M-A14 + M-A4 |
| 3.8 | Model extraction by scraping | none | Gap | M-A15 (defer) |
| 3.9 | Harmful content and policy violations | G, DT; PF `harmful:*` lost | Partial | G + DT on our attacker models; M-A11 for customer policies |
| 3.9 | Bias and fairness | DT; PF `bias:*` lost | Partial | DT; M-A11 |
| 3.9 | Off-topic use, hijacking, competitor mentions | PF plugins lost; PF `policy` and `intent` local | Partial | PF `policy`/`intent` with our generators; M-A11 |
| 3.10 | Spoofed inter-agent messages, A2A abuse (ASI07) | none | Gap | M-A7 |
| 3.10 | Cascading failures, rogue behavior (ASI08, ASI10) | DT agentic partly | Gap: no multi-agent harness | M-A7 |
| 3.11 | Evasion, membership inference, inversion, stealing, backdoors (predictive ML) | none | Gap | Adopt ART and TextAttack (M-A15) |

**Surface coverage (spec section 2).** Surface A (direct channels) is mostly covered. Surfaces B (indirect content) and D (retrieval) are the largest gaps, because every engine we have attacks through the prompt box. Surface C (tools) is covered for text but not for traces. Surface E (supply chain) is covered only for model-file scanning. Surface F (control plane, approval UIs) is almost entirely missing.

**Oracles (spec section 4).** Engines ship detectors and LLM graders, but not a shared oracle layer. Canary, tool-trace, goal-diff, ACL, resource, manifest-drift, and multi-turn-state oracles all need to be built once and used by every engine and module (M-A3 and the Phase 4A oracle framework).

## Classic AppSec coverage
Engines: ZAP (Z), Nuclei (N), Dalfox (D), katana/httpx/subfinder/ffuf (PD), interactsh (OOB), Trivy (T), osv-scanner (OSV), gitleaks (GL), Bandit (B), gosec (GS).

| Area | Requirement | Today | Rating | Fill with |
| --- | --- | --- | --- | --- |
| Discovery | Crawling, including JavaScript-heavy single-page apps | Z spider and AJAX spider, PD katana headless | Covered | - |
| Discovery | Authenticated crawling with real login flows (SSO, MFA test accounts, CSRF tokens) | Z contexts (brittle) | Partial | M-C1 |
| Discovery | API discovery from OpenAPI, GraphQL schemas, and traffic | Z OpenAPI and GraphQL add-ons | Partial | M-C1 |
| Injection | Reflected, stored, and DOM XSS | D, Z, N | Covered | Registry overlap only |
| Injection | SQL injection: error, boolean, time, out-of-band, second-order | Z basic active rules, N CVE templates; sqlmap excluded | Gap for depth | M-C2 |
| Injection | OS command injection | Z basic; commix excluded | Partial | M-C2 |
| Injection | Server-side template injection | Z rule; tplmap excluded | Partial | M-C2 |
| Injection | NoSQL, LDAP, XPath, header, and CRLF injection | Z partial, N some | Partial | M-C2 |
| Injection | XXE | Z | Covered | - |
| Server-side | SSRF, including cloud-metadata chains and blind SSRF | Z, N, OOB | Partial | M-C2 with OOB |
| Server-side | Insecure deserialization | N (known CVEs only) | Partial | M-C2 (gadget probes) |
| Server-side | Path traversal, local file inclusion | Z, N, PD ffuf | Covered | - |
| Server-side | HTTP request smuggling, web cache poisoning and deception | none reliable | Gap | M-C6 (later) |
| Access control | BOLA/IDOR, BFLA, mass assignment, tenant isolation | none | Gap | M-C3 |
| Auth | JWT flaws (`alg:none`, weak keys, `kid` injection), OAuth and OIDC misconfiguration, session fixation | Z partial, N some | Partial | M-C4 |
| Logic | Race conditions (limit overrun, double spend) | none | Gap | M-C5 |
| Logic | Business-logic abuse | AG (Phase 5) | Partial | AG with M-C3 identities |
| API | GraphQL: introspection, batching, depth and alias DoS, field authorization | Z add-on, N some | Partial | M-C3, M-C7 |
| API | gRPC and WebSocket APIs | none | Gap | M-C7 |
| API | Rate-limit and resource-consumption tests | none | Gap | M-C7 |
| Client-side | Prototype pollution, postMessage, CSP weaknesses, clickjacking | Z passive rules, N headless | Partial | M-C8 (later) |
| Client-side | Unsafe file upload (type bypass, polyglots, path) | none | Gap | M-C2 |
| Known CVEs | Web and infra CVEs, exposed panels, default credentials, takeovers | N, Z | Covered | Template freshness pipeline |
| Infra | Port and service discovery | none (nmap excluded) | Gap | Adopt naabu (MIT) |
| Infra | TLS configuration | none (testssl.sh excluded) | Gap | Adopt tlsx (MIT) + our cipher policy rules |
| Infra | AI infrastructure exposure: unauthenticated vector DBs, inference servers, MLflow, Ray, notebooks | N some templates | Partial | M-A16 |
| Infra | Cloud account posture (CSPM) | none | Out of scope for v1 | Defer; revisit after Phase 10 |
| Static | SAST for Python and Go | B, GS | Partial | M-C9 |
| Static | SAST for JavaScript/TypeScript, Java, C#, PHP, Ruby | none (Semgrep rules and CodeQL excluded) | Gap | M-C9 |
| Static | Secrets in code and history | GL | Covered | - |
| Static | Secret liveness (is the leaked key still valid?) | none (trufflehog excluded) | Gap | M-C10 (opt-in) |
| Static | Dependencies (SCA), container images, IaC misconfiguration, licenses | T, OSV | Covered | - |
| Static | SBOM generation | T | Covered | - |

## Adopt before building
These close gaps with little work. All are permissively licensed, run in the cloud as-is, and go through the same license gate and masking as the other engines.

| Tool | License | Fills |
| --- | --- | --- |
| naabu | MIT | Port and service discovery (replaces nmap) |
| tlsx | MIT | TLS versions, ciphers, and certificate checks; we add our own policy rules on top |
| Adversarial Robustness Toolbox (ART) | MIT | Predictive-ML evasion, membership inference, extraction, poisoning (spec 3.11) |
| TextAttack | MIT | Adversarial text attacks against classifiers (spec 3.11) |
| OpenSSF model-signing (`model-transparency`) | Apache-2.0 | Model signature and provenance verification (spec 3.7) |
| Playwright | Apache-2.0 | Browser for the login recorder (M-C1) and the output-sink renderer (M-A10) |

Open decision: **opengrep** (the community fork of the Semgrep engine) is LGPL-2.1. Run unmodified as a separate process in our cloud, it may be acceptable, and it would shorten M-C9 a lot. It is not on the current allowlist, so legal review decides before Phase 8. Semgrep's registry rules stay excluded either way; all rules would be ours.

## Modules to build
Each module is Insidia's own code in `engine/workers/insidia/<module>/`, registered in the capability registry like any engine, and shown to customers as an Insidia Engine module. Size: S is up to 2 engineer-weeks, M is 2 to 6, L is more than 6.

**Clean-room rule.** For gaps left by GPL tools (sqlmap, commix, tplmap, testssl.sh, trufflehog), engineers must not copy their code or their payload and rule files. We write modules from public specifications, papers, and our own research. Reviewers check this on every pull request in these modules.

### AI and agent modules
| Id | Module | What it does | Connection | Phase | Size |
| --- | --- | --- | --- | --- | --- |
| M-A1 | Indirect content forge | Generates poisoned web pages, documents, emails, tickets, calendar invites, and tool results, each carrying a canary instruction. Hosts them on our honeypot domains or delivers them through the customer's ingest endpoint. | Direct or runner | 4A (honeypot hosting in 7) | M |
| M-A2 | Payload converters | Turns any probe into other carriers: PDF, DOCX, and HTML with hidden text; images with rendered or OCR text; audio (text-to-speech); Unicode tag characters, homoglyphs, and zero-width smuggling. Applied as a strategy to every engine's probes. | Both | 4A | M |
| M-A3 | Canary and hidden-context oracle | Plants unique canaries in system prompts, tool definitions, and documents (gray box), then proves extraction or obedience deterministically. Black-box variant scores reconstruction of hidden instructions. Includes the instruction-hierarchy suite (system vs developer vs user vs tool roles). | Both | Canaries 1; full suite 4A | M |
| M-A4 | Tool-trace oracle | Collects the agent's actual tool calls (SDK, OpenTelemetry GenAI traces, or our honeypot tools) and checks them against a per-target policy: allowed tools, allowed arguments, forbidden chains such as read-then-send. Turns text-judged findings into proven ones. | Runner or SDK; honeypot tools in direct | 4A foundation, 7 full | L |
| M-A5 | RAG and memory harness | Plants documents through a customer-provided ingest path (upload API, test bucket, test index), tests retrieval-rank manipulation and cross-document smuggling, writes to memory in one session and reads it back in another, and judges groundedness and citations. | Both; gray box needs ingest access | 4A | L |
| M-A6 | Two-identity access harness | Runs the same attack as identity A, identity B, and an admin. An ACL oracle detects cross-tenant and cross-document bleed, and BOLA/BFLA through an agent. Shares its identity model with M-C3. | Both | 4A | M |
| M-A7 | Multi-agent and A2A harness | Spoofs agent cards and inter-agent messages, injects the supervisor through worker output, tests secondary injection (agent A's output becomes agent B's prompt), and measures blast radius across a fleet. | Runner or SDK | 7 | L |
| M-A8 | Sandbox sensor kit | Canary files, a fake cloud-metadata endpoint, out-of-band callbacks, and process and file-write sensors for code interpreters, plus the escape payload set. Proves code execution instead of inferring it. | Runner, or honeypot in direct | 7 | M |
| M-A9 | Approval-bypass suite | Tests whether the agent acts without the required human approval, and whether the approval request shown to the human matches the action actually executed (a misleading summary is a finding). | Runner or SDK | 7 | M |
| M-A10 | Output-sink simulator | Renders model output in a headless browser to detect script execution and image- or link-based exfiltration to our out-of-band server; parses output as shell, SQL, and ticket or email content to detect injection into downstream systems. | Both | 4A | M |
| M-A11 | Insidia attack generator | Our attacker-model generation that replaces the promptfoo remote-only plugins and strategies: harmful-content and bias categories, hijacking, off-topic, competitor, system-prompt override, domain packs, and a GOAT-style adaptive multi-turn attacker. Also turns a customer's stated purpose and policies into a custom attack set. | Both | 4A | L |
| M-A12 | White-box AI analysis | Prompt and tool-graph analysis from extracted code, embedding and vector-store exposure checks, over-privileged tool detection. Already planned in Phase 8; listed here because it closes 3.2 embedding inversion. | Runner `extract` or upload | 8 | L |
| M-A13 | AI supply-chain checks | GGUF chat-template diffing against known-good, behavioral goldens before and after swapping an adapter, model-signature verification, model-hub namespace reuse and typosquatting checks, and MCP tool-hash drift (rug-pull). | Both (static) | 7 and 8 | M |
| M-A14 | Consumption and resource oracle | Measures tokens, cost, latency, and tool-loop depth per attempt; runs token-flood, reasoning-DoS, and tool-storm probes under a strict budget so the test itself cannot run up the customer's bill. | Both | 4A | S |
| M-A15 | Predictive-ML pack | Wraps ART and TextAttack for classifiers, recommenders, and vision or audio models; adds model-extraction-by-scraping tests. Needs model access through the runner or SDK. | Runner or SDK | 11 (optional per spec) | M |
| M-A16 | AI infrastructure exposure | Our own detection templates for unauthenticated vector databases, inference servers, model registries, MLflow, Ray dashboards, and notebooks. Runs on the existing template engine. | Both | 4B | S |

### Classic AppSec modules
| Id | Module | What it does | Connection | Phase | Size |
| --- | --- | --- | --- | --- | --- |
| M-C1 | Login recorder and API discovery | The customer records a login once in the dashboard (or with the runner); we replay it with Playwright to keep sessions alive, including CSRF tokens and test-account MFA. Also imports OpenAPI, GraphQL schemas, Postman collections, and HAR files to find endpoints a crawler misses. | Both | 4B | M |
| M-C2 | Injection depth engine | SQL injection (error, boolean, time, out-of-band, second-order, with database fingerprinting), OS command injection, template injection with engine fingerprinting, NoSQL, LDAP, XPath, CRLF, deserialization gadget probes, and unsafe file upload. Confirms blind cases through the out-of-band server. Clean-room. | Both | 4B | L |
| M-C3 | Access-control differ | Replays every discovered request as identity A, identity B, admin, and anonymous, then diffs the responses to find BOLA/IDOR, BFLA, tenant-isolation breaks, and mass assignment, including GraphQL field-level authorization. The highest-value classic module: no engine we use does it. | Both | 4B | L |
| M-C4 | Token and session analyzer | JWT checks (`alg:none`, weak HMAC keys, `kid` and `jku` injection, expiry), OAuth and OIDC flow checks (redirect URI, state, PKCE), session fixation and logout invalidation. | Both | 4B | M |
| M-C5 | Race-condition tester | Single-packet HTTP/2 bursts for limit-overrun and double-spend bugs on endpoints the customer marks as sensitive (checkout, redeem, transfer). Opt-in per endpoint because it changes state. | Runner tunnel preferred | 9 | M |
| M-C6 | Smuggling and cache pack | HTTP request smuggling, web cache poisoning, and cache deception. | Both | 11 | M |
| M-C7 | Protocol coverage | gRPC (via server reflection or uploaded protos), WebSocket message fuzzing, and rate-limit and resource-consumption tests for APIs. | Both | 4B (gRPC, rate limits), 9 (WebSocket) | M |
| M-C8 | Client-side pack | Prototype pollution, postMessage handlers, CSP and clickjacking weaknesses, found by instrumenting the page in a headless browser. | Both | 11 | M |
| M-C9 | Insidia SAST | Tree-sitter parsing with our own taint rules for JavaScript/TypeScript, Python, Go, Java, C#, PHP, and Ruby, plus AI-specific sinks: prompt concatenation of untrusted input, LLM output passed to `eval`, SQL, shell, or HTML, and tools with no authorization check. Replaces Bandit and gosec as the primary static engine. | Runner `extract` or upload | 4B (Python, JS/TS), 8 (the rest) | L |
| M-C10 | Secret liveness verifier | For leaked secrets, calls each provider's read-only identity endpoint (for example "who am I") to say whether the key is still live, rate-limited and opt-in. Stores only a live or dead flag and the fingerprint, never the secret. | Cloud, opt-in per org | 8 | S |

## Build order
The order follows the spec's minimum capability layers (section 5) and what customers ask about first.

| Order | Modules | Why first |
| --- | --- | --- |
| 1 | M-A3 canaries, M-A14 | Deterministic proof for the Phase 1 slice; cheap |
| 2 | M-A11, M-A2 | Recover the promptfoo coverage lost to local-only mode; every probe benefits from the converters |
| 3 | M-C3, M-C1, M-C2 | The biggest classic gaps (access control, authenticated scanning, injection depth) and what buyers compare against Burp |
| 4 | M-A1, M-A5, M-A6, M-A10 | Indirect injection, RAG, tenant bleed, output sinks: spec layers 2, 4, and 7 |
| 5 | M-A4, M-C4, M-C9 (first languages), M-A16, M-C7 (gRPC, rate limits) | Tool-trace proof and the rest of Phase 4 |
| 6 | M-A7, M-A8, M-A9, M-A13 | Agent security (Phase 7): multi-agent, sandbox, approval, supply chain |
| 7 | M-A12, M-C9 (remaining languages), M-C10 | White box (Phase 8) |
| 8 | M-C5, M-C7 (WebSocket) | Continuous and developer workflow (Phase 9) |
| 9 | M-A15, M-C6, M-C8 | Later (Phase 11) |

**Where coverage stands.** Of the 36 AI rows in the table above, 3 are Covered today, 18 are Partial, and 15 are Gaps. Every Partial and Gap row has an assigned module or adopted tool, so the plan covers every row once steps 1 to 9 ship. Only the benchmark below can say how well each one is covered.

## Where each module lands in the phase plans
- **Phase 1** ([03-phase1-vertical-slices.md](03-phase1-vertical-slices.md)): M-A3 canary oracle, used by the first AI findings.
- **Phase 4A** ([06-phase4-depth.md](06-phase4-depth.md)): M-A1, M-A2, M-A3 full, M-A4 foundation, M-A5, M-A6, M-A10, M-A11, M-A14.
- **Phase 4B**: M-A16, M-C1, M-C2, M-C3, M-C4, M-C7 (gRPC, rate limits), M-C9 (Python, JS/TS); adopt naabu and tlsx.
- **Phase 5** ([07-phase5-pentest-agent.md](07-phase5-pentest-agent.md)): the pentest agent uses M-C3 identities, M-C2 payloads, and M-A10 sinks as tools.
- **Phase 6** ([08-phase6-engine-registry.md](08-phase6-engine-registry.md)): measures every module against the engines in the benchmark and sets Standard-mode priorities.
- **Phase 7** ([09-phase7-agent-security.md](09-phase7-agent-security.md)): M-A4 full, M-A7, M-A8, M-A9, M-A13; honeypot hosting for M-A1.
- **Phase 8** ([10-phase8-whitebox.md](10-phase8-whitebox.md)): M-A12, M-C9 (remaining languages), M-C10; adopt model-signing.
- **Phase 9** ([11-phase9-continuous.md](11-phase9-continuous.md)): M-C5, M-C7 (WebSocket).
- **Phase 11** ([13-phase11-later.md](13-phase11-later.md)): M-A15 (adopt ART and TextAttack), M-C6, M-C8.

## Validating this analysis
The ratings above are hypotheses. The Phase T permutation suite ([17-test-suite.md](17-test-suite.md)) and the Phase 6 benchmark turn them into measurements. Both read the same targets and ground truth from `tests/`, so there is one source of truth.
- **Benchmark targets** (permissively licensed, self-hosted, sandboxed with no egress; defined in [17-test-suite.md](17-test-suite.md)): OWASP Juice Shop (MIT), crAPI (Apache-2.0), VAmPI (MIT), Damn Vulnerable GraphQL Application (MIT), AgentDojo tasks (MIT), and our own fixtures: a vulnerable chatbot, a RAG app with a plantable corpus, an MCP agent with dangerous tools, and a two-agent A2A system. Each has a `ground_truth.yaml` list of planted vulnerabilities.
- **Per engine and per module**, we measure recall against ground truth, precision (confirmed findings over all findings), cost per attempt, and runtime. These numbers fill `capability_map.precision_measured` and drive Standard-mode priorities.
- A row moves from Partial to Covered only when the benchmark shows at least 80% recall on that row's planted vulnerabilities with at least 90% precision.
- The benchmark runs weekly in CI and on every engine version bump, so a regression in an upstream engine shows up as a coverage drop before a customer sees it.

## Keeping this current
- Re-run this analysis when an engine releases a major version, when OWASP or MITRE publish a new framework version, or every quarter, whichever comes first.
- Every new customer request for a test we do not have becomes a row here before it becomes a ticket.
- Customer-facing coverage pages ([15-customer-docs.md](15-customer-docs.md)) are generated from the registry and this gap list, so we never promise coverage we do not have.