# Phase 1F — Insidia reliability, evidence, and productization

Status: **in progress**. F00–F05 are started. F06–F22 are not finished.

Inputs: [review and evidence](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/plans/2026-10-10-product-review.md), [product brief](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/plans/PRODUCT-BRIEF.md), and [master plan](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/plans/00-master-plan.md).

This is the execution contract for resolving the review. It supersedes the earlier assumption that green Phase 1B–1E matrix cells alone establish readiness. It preserves the combined AI security and AppSec product direction. Every task below is open until its acceptance evidence is recorded.

## 1. Capability and completion target

An application developer or AppSec engineer can install a supported release, explicitly scope an AI-enabled application and its surrounding application assets, run named checks through credited engines, understand exactly what ran, inspect reproducible redacted findings, and compare a fix against a comparable rerun. Independent benchmark results describe the released CLI's measured capabilities and limitations.

There are two delivery gates, not one ambiguous definition of “done”:

- **Scoped public beta:** all correctness, evidence, onboarding, and presentation gates pass for an explicitly published subset spanning AI, web/API, and repository checks. Every other current capability is accounted for as experimental, fixture-only, or unsupported; it contributes no assurance score.
- **Catalog completion:** every retained integration and family has a verified implementation. All 17 current integrations and every current family must be accounted for. A documented removal changes the supported catalog; a deferred item remains open, with a replacement path and owner. Broad coverage claims require verified implementations. Merely relabeling missing capabilities does not complete this second gate.

Initial beta integration candidates are garak, Nuclei, and gitleaks, plus a genuinely validated Insidia SSTI detector. These are planning choices based on the existing adapters, not claims they already meet the gates. F00/F09 may select a different named AI engine if a bounded integration assessment demonstrates a better supported path; record the reason before implementation.

## 2. Fixed constraints and defaults

### Fixed repository policy

- Keep the CLI free, local, and usable without an account. Credit upstream engines in findings and documentation.
- Localhost remains the default. Non-local target authorization must be explicit; never infer it from engine availability. Model endpoints and target endpoints have distinct allowed purposes even when both are configured.
- No `.env` edits, credentials in logs, raw tokens, or customer prompts in logs. Evidence must follow the repository's masking format. Use synthetic data for public examples.
- Follow existing dependency-license rules and trademark treatment. Preserve customer runs; do not rewrite old reports in place.
- Core remains Python 3.12+. Use typed, small functions; read affected code/tests first. Use `git mv` for moved tracked files.

### Architecture defaults selected for this plan

- Evolve the existing package. Add small domain modules; do not introduce a new service or orchestration framework for the CLI.
- One typed result model drives terminal, JSON, HTML, SARIF, MCP, and the GitHub Action.
- One capability registry drives selection, compatibility, support documentation, and benchmark requirements.
- L1 becomes a versioned deterministic baseline. Until separately validated, L2/L3 requests fail with an actionable unsupported-profile error rather than silently executing L1. Existing configuration is never silently rewritten.
- Standard coverage selects the registry's explicit verified primary implementation; thorough coverage adds verified alternatives with visible extra cost. Neither selects a fixture-only probe for a normal user scan.
- Core support is tested on Linux, macOS, and Windows. Native engine support is declared per engine/OS/architecture. The first container gate is Linux amd64, matching the existing release path; other architectures require their own evidence.
- No account or telemetry is needed to measure local scan duration. Pilot usage observations are consented and separate from product telemetry.

### Not part of this implementation milestone

Hosted GPU operations, billing, autonomous pentesting, enterprise SSO, and a large hosted dashboard remain later phases. F22 defines their entry criteria. This defers those investments, not the AI + AppSec scope.

## 3. Required execution and data contracts

### 3.1 Separate execution, findings, and policy

Each requested check/target pair has one execution record. Define these independently:

| Field | Allowed values / meaning |
| --- | --- |
| Execution state | `queued`, `running`, `complete`, `error`, `unsupported`, `not_applicable`, `cancelled` |
| Observations | Zero or more attributable findings; preserve them even if the engine later errors |
| Policy verdict | `pass`, `fail`, `inconclusive` |
| Run execution status | `complete`, `incomplete`, `cancelled` |
| Artifact state | `staging`, `finalized`; independent of execution success |

Transitions: queued → running → complete/error/cancelled; queued → unsupported/not_applicable after planning. Every terminal state records a reason and timestamps. A parser may emit findings plus an execution error. Empty output is not evidence that execution completed.

For Phase 1F, every explicitly selected applicable check is required. Exclusions happen before execution and appear in the scan plan. `not_applicable` requires a registry applicability rule; missing authentication, runtime, schema, model, or permissions is not “not applicable.” There is no runtime mechanism for silently making a failed check optional.

Evaluation order:

1. If any valid finding crosses the configured policy threshold, verdict is `fail`.
2. Otherwise, if any required check did not complete, or no applicable checks ran, verdict is `inconclusive`.
3. Otherwise, verdict is `pass`, meaning only the named checks completed without a threshold violation.

The baseline default fails on any validated non-informational security finding, preserving the existing fail-on-finding intent. Explicit thresholds are versioned profile settings, never inferred from display colors. Unresolved detector evidence must produce an inconclusive check outcome rather than a clean negative; safety/fairness evaluations use separately documented rubrics and do not inherit a technical-vulnerability severity automatically.

Execution can therefore be incomplete while the policy already fails. Display both. The aggregate never discards findings to simplify the status.

| CLI exit | Contract |
| --- | --- |
| `0` | Execution complete and policy pass |
| `1` | Execution complete and policy fail |
| `2` | Configuration/readiness/execution incomplete or error, including an incomplete run that also contains findings |
| `130` | User cancellation; preserve a finalized partial report when possible |

Keep the legacy JSON `passed` field temporarily, true only for exit-0 semantics. Use schema version `2.0` for new run/scan documents and add `execution_status` and `policy_verdict`; documents with no schema version are legacy. Document this as a behavior change and update the Action/MCP clients in the same release.

### 3.2 Data model

Suggested new modules are proposals, not existing files: `core/insidia/results.py`, `core/insidia/manifest.py`, and `core/insidia/capabilities.py`. Keep protocol-specific parsing out of these modules.

| Entity | Minimum required fields |
| --- | --- |
| Capability | Stable ID, version, family, role (detector/discovery), readiness, target requirements, engine/probe/version, profile membership, applicability rule, evidence contract, primary/alternative selection |
| Execution record | Target and capability IDs, actual engine/version, state/reason code, start/end/duration, request/token usage where known, validated report reference, observations |
| Finding | Stable ID, affected asset/location, family, normalized severity with rationale, confidence/evidence basis, taxonomy edition, remediation, observation IDs |
| Observation | Engine/rule/detector lineage, upstream severity, safe reproduction parameters, bounded redacted matched evidence and context, source/URL location, evidence digest |
| Run manifest | Schema/CLI version, run ID, artifact state, execution status, policy verdict/version, effective non-secret config digest, target revision or explicit unknown, engine/corpus/model versions, start/end, seed where relevant, budgets, exclusions, artifact paths/digests |

Never hash resolved credentials into a public config identity; record credential reference names with redacted values. A rerun with unknown target/model revision is labeled as such. Different profile/engine/corpus/config versions require a visible comparison warning. Store no invented precision when a provider cannot guarantee model revision or determinism.

Finding identity must include the affected asset and stable location plus canonical rule/family identity. Different files with the same rule remain separate findings. Multiple engine observations can attach to one finding without erasing original rules/severity. Two tools using the same detector are not independent corroboration.

Redacted evidence is separate from operational logs. Retain the matched span rather than blindly retaining the first 500 characters. Do not persist full customer/system prompts or resolved credentials. Synthetic attack template ID/seed and safe parameters can reconstruct a probe without retaining sensitive input.

### 3.3 Storage and compatibility

Write to a hidden staging directory under the same runs filesystem; publish the directory only after every required artifact and digest is validated. Finalizing an incomplete scan is valid and yields an explicitly incomplete report. A crash during writing leaves recoverable staging state, not a report that looks complete.

`report` validates the requested run and files before returning success. Latest means latest finalized run, including failed/incomplete scans; do not hide them by selecting the last passing scan. Preserve legacy runs read-only, show “legacy: execution completeness unknown,” and disable unsupported comparisons. Never infer complete execution from an old `passed: true` flag.

## 4. Work packages and merge sequence

IDs are stable issue/PR references. F00–F05 are started. F06–F22 are **not finished**. A package may need multiple focused PRs. The listed dependencies are prerequisites for marking it complete, not a ban on preparing independent documents/tests.

| ID | Deliverable | Depends on | Release gate |
| --- | --- | --- | --- |
| F00 | Capability/claim inventory and regression fixtures | — | Beta |
| F01 | Typed execution and policy result contract | F00 | Beta |
| F02 | Target preflight, strict transport/parser handling | F01 | Beta |
| F03 | Shared scope, rate, concurrency and cancellation | F01 | Beta |
| F04 | Central redaction and bounded evidence handling | F01 | Beta |
| F05 | Versioned manifests and atomic report storage | F01, F04 | Beta |
| F06 | Lossless observations, identity, SARIF and rerun | F02, F04, F05 | Beta |
| F07 | Capability registry, engine selection, profile semantics | F00, F01 | Beta |
| F08 | Genuine built-in detectors; quarantine fixture checks | F02, F03, F06, F07 | Beta subset; catalog expansion |
| F09 | External-engine integration contracts and repairs | F02, F03, F06, F07 | Beta subset; full catalog later |
| F10 | Independent benchmark runner and scorer | F01, F05, F07 | Beta; expands with F08/F09 |
| F11 | Versioned mappings and honest coverage summaries | F01, F07 | Beta |
| F12 | MCP, agent skill and CI consumer compatibility | F02, F03, F05, F06 | Beta |
| F13 | Verified installers, runtimes and platform matrix | F07, F09 subset | Beta subset; full catalog later |
| F14 | Doctor, configuration UX and reproducible demo | F02, F07, F08/F09 subset, F13 | Beta |
| F15 | Actionable offline report and comparison UX | F05, F06, F11 | Beta |
| F16 | README, built docs, privacy and support content | F07, F11–F15 | Beta |
| F17 | Homepage, real preview, accessibility and lead form | F15, F16 | Beta |
| F18 | Real recorded demo and public sample artifacts | F10, F14–F17 | Beta |
| F19 | Artifact release, provenance and license gates | F10, F12, F13, F16–F18 | Beta |
| F20 | Pilot adoption and public-beta decision | F19 | Beta |
| F21 | Complete remaining catalog/families and real L2/L3 | F08–F10, F20 | Broad-coverage release |
| F22 | Cloud readiness specification and investment gate | F20 | Before Phase 2 implementation |

### F00 — Inventory and tests that challenge the current claims

**Work:** enumerate every policy family, target kind, transport, provider, engine, framework, platform, and public claim. Record implemented path, independent evidence, current readiness, and owning package. Correct unsupported/confirmed/level claims in README/site/docs early; preserve historical implementation notes but qualify readiness. Add regression fixtures using synthetic data for the findings below before changing behavior. Label expected failures with linked issue IDs until fixed; none may remain xfailed at the beta gate for supported features.

**Existing files:** [policy](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/policy.py), [catalog](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/catalog.py), [core tests](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/tests), [matrix](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/matrix), README and site/docs capability content.

**Acceptance:** every review item R1–R12 has a regression, an inspection gate, or a named implementation requirement; no current capability disappears without a recorded disposition. Preserve all six existing sample runs unchanged. Do not copy their raw responses into public fixtures.

### F01 — Result integrity first

**Work:** implement section 3 contracts; replace lists-of-findings-as-success with typed adapter results. Use a compatibility adapter only if it explicitly checks execution/report validity. Update terminal/JSON/basic HTML status together so intermediate PRs do not present contradictory verdicts.

**Files:** [scan](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py), [errors](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/errors.py), [CLI](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/cli.py), [UI](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/ui.py), proposed results module. Extend `test_scan.py`, `test_cli.py`, `test_ui.py`, `test_report.py`.

**Acceptance:** one clean engine plus one failed selected engine yields incomplete execution/exit 2; findings survive partial failure; zero applicable controls yields inconclusive; all surfaces agree; unknown parser errors cannot become an empty successful result.

### F02 — Establish that the intended target/check actually ran

**Work:** preserve HTTP status, headers, selected response and transport diagnostics. Preflight the configured authenticated application route and schema. Enforce selectors instead of silently using raw bodies. Let capability contracts specify valid response semantics—401 is not globally a vulnerability or globally success. Validate every engine report against its supported format; distinguish no findings from absent/truncated/malformed output and interrupted processes. Convert YAML/config errors to actionable CLI errors with field paths, not secret-bearing tracebacks. Reject unknown/misspelled config fields.

**Files:** [transport](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py), [config](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/config.py), [process](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/process.py), [upstream](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py), existing scan/adapter/target tests.

**Acceptance:** permanent 401/403/500, HTML login page, wrong selector, invalid JSON, timeout, empty report and malformed report all produce the specified incomplete/error outcome. A legitimate blocked attack can be counted only after its baseline/prerequisites succeed. A nonzero engine exit is interpreted through that engine's documented exit contract, never simply accepted because a file exists.

### F03 — Enforce runtime scope and budgets

**Work:** create one execution context per target with a shared limiter, semaphore, timeout, request budget and cancellation token. Pass it through built-in, relay, and external-engine paths. Preserve method, headers, body/auth and response shape across adapters. Require a tested scoped relay or equivalent container/network enforcement for engines that can make additional requests; an initial URL check is insufficient. Disable unsupported safe execution modes explicitly. Separate target/model egress purposes. Terminate child process groups on cancellation and timeout.

**Files:** [scope](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scope.py), transport, process, probes, upstream, providers, config; scope/scan tests and [egress tests](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/test_egress_guard.py).

**Acceptance:** fake-clock scheduling proves aggregate RPS; a concurrency recorder proves the configured maximum across simultaneous engines. Scoped test servers prove denied redirects/secondary hosts/ports are never contacted, including model relays. Native engines unable to honor guarantees remain unsupported. Cancellation leaves no owned child processes and preserves partial observations. Avoid flaky timing assertions as the primary rate-limit test.

### F04 — Redaction at every output boundary

**Work:** centrally redact exact configured credential values, supported credential patterns, auth headers, sensitive query/body fields and engine stderr. Preserve the required `[TYPE len=N fp=xxxxxxxx]` format. Add an explicit privacy mode for personal identifiers; do not claim all PII is automatically detected. Bound output/evidence sizes and sanitize terminal control characters. Use private temporary files and restrictive run permissions where supported. Inventory upstream caches, downloads and services; clean temporary credentials on success/error/cancel.

**Files:** [mask](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mask.py), process, providers, findings, runstore, CLI/MCP error paths, `test_mask.py` and adapter tests.

**Acceptance:** synthetic generic bearer, supported GitHub/OpenAI-style credentials, known configured secret values, multiline stderr and encoded structured fields do not appear raw in terminal/JSON/HTML/SARIF/logs/staged artifacts. Test evidence containing markup and terminal escapes. Redaction failure cannot fall back to writing the original text. Document limits; no promise of universal secret discovery.

### F05 — Run storage and migration

**Work:** implement section 3.3; persist versioned manifests and artifact digests; use safe run-ID validation and resolved-path containment. Add explicit legacy reading, incomplete-run listing, and report validation. Provide retention/list/delete commands with exact run selection and a preview/dry-run for bulk deletion; never delete user samples automatically.

**Files:** [runstore](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/runstore.py), CLI, proposed manifest module, `test_report.py`, `test_cli.py`, `test_packaging.py`.

**Acceptance:** interrupt each write stage and prove no half-written run is published as finalized; latest finalized failed/incomplete run remains visible; missing report produces exit 2; legacy runs are not mutated; path traversal and symlink escapes are rejected. Retention respects explicit selection and preserves unrelated files.

### F06 — Evidence, identity and exports

**Work:** retain per-engine observations, original rules/severity, source/URL locations, package/version/fix data, matched evidence context, and safe reproduction parameters. Explain any normalized severity/confidence. Replace automatic cross-validation with “reported by N engines”; reserve stronger verification for a versioned evidence rule. Generate SARIF locations, stable fingerprints, help/remediation and provenance. Add a manifest-based rerun command that validates scope and current secret references; never embed credentials or replay untrusted shell strings.

**Files:** [findings](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/findings.py), [probes](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py), upstream, runstore, CLI, adapter/report tests.

**Acceptance:** a match after character 500 is visible; same rule at two files yields two findings; duplicate observations of the same location retain both engine records; malformed severity is explicit; emitted SARIF validates and contains usable source locations where supplied by the engine. A rerun uses recorded profile/config/engine context and flags unavailable versions or changed configuration instead of silently substituting them.

### F07 — One capability registry and truthful policies

**Work:** implement registry/schema validation and generated support views. Replace priority-only selection with explicit verified primary/alternative mappings. Check every selectable family has a policy path and every advertised engine has a runnable purpose. Add a machine-readable scan-plan/dry-run view showing selections, prerequisites, exclusions, expected budget, readiness and unsupported settings. Keep L1 deterministic; reject L2/L3 until F21 gates are met. Preserve standard/thorough as execution breadth, not assurance levels.

**Files:** catalog, [registry](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/registry.py), policy, adapters, CLI, config, `test_registry.py`, `test_adapters.py`.

**Acceptance:** available external engines are selected when they own a verified primary check; an unavailable primary does not silently fall back to a weaker fixture; all five currently unscheduled catalog families receive a verified path or explicit unsupported status. Installing an engine alone does not change a capability to verified. Generated docs and scan selection agree.

### F08 — Replace fixture oracles with actual detector contracts

**Work:** classify every built-in family using section 5. Move fixture-only helpers into clearly designated test support or leave them unavailable to production selection. Start with randomized paired SSTI challenges and a baseline; build further checks only when target prerequisites and evidence can be specified. Keep protocol/auth/tenant traces explicit. Do not implement race detection by matching a string, or TLS checks via an application response.

**Files:** adapters, probes, policy/registry, [fixture targets](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/targets/insidia), core adapter/scan tests, independent cases from F10.

**Acceptance per promoted detector:** vulnerable and fixed independent targets, benign lookalike responses, refusal/error response, missing prerequisite, evidence reconstruction, and repeated-run behavior all have outcomes. The price-49 false positive disappears. No fixed fixture canary is interpreted as universal detection coverage. Engine evidence may be used instead of reimplementing a mature detector.

### F09 — Repair engine integrations one at a time

**Work:** follow section 6. For each engine, pin the supported upstream release/format, verify its official interface during implementation, define allowed execution and exit/report contracts, preserve native evidence, and run it through the released CLI. Split generated runner scripts into small reviewed adapters as needed; avoid a simultaneous rewrite of every engine.

**Files:** catalog, upstream, process, probes, engines, registry, core adapter/engine tests; add sanitized parser fixtures per engine and live integration tests.

**Acceptance per engine:** installation → selection → actual nontrivial native check → valid report parsing → finding/negative control → timeout/error → evidence/export. A process that ran `test.Blank` or printed a report is insufficient. Discovery tools contribute discovered assets, not fictitious vulnerability passes. Full engine support cannot be claimed from the beta subset.

### F10 — Independent benchmark

**Work:** divide fixture-integrity, adapter-contract and release-evaluation suites. Preserve useful old tests under truthful names. The evaluation harness installs the built wheel/container and invokes the public CLI; it cannot import detector internals or return expected plant IDs in place of observations. Pin target commits/images, dependencies, corpus and configuration. Hold out variants from detector development; maintain separate ground truth with affected location/family match rules.

**Files:** [run_cell](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/run_cell.py), [benchmark score](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/score.py), [gate](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/gate.py), upstream/live/suite harnesses, golden expectations, matrix ownership and CI.

**Acceptance:** injecting an extra emitted finding worsens precision; withholding a known finding worsens recall; wrong asset/location does not match merely because a family matches; engine failure is counted as incomplete, not a true negative. Publish all raw redacted observations and TP/FP/FN match decisions. Precision with no predictions and recall with no positives are N/A, not 100%. Report per-family counts and completion; show unique cases separately from matrix permutations. AI measurements include model/version, seed where possible, repeats and uncertainty. AgentDojo “attack success” requires an actual agent workflow and independent outcome observation; direct tool calls remain fixture tests.

For the small deterministic beta acceptance suite, require all declared vulnerable/fixed cases to match their expected outcomes and every requested check to complete. Publish its limited sample size; this is not a population-wide 100% accuracy claim. Predeclare larger/stochastic evaluation case counts, repetition protocol and release thresholds before running the held-out set. Do not tune a threshold after seeing held-out results or remove failures from the denominator.

### F11 — Framework mapping and coverage accounting

**Work:** verify each supported edition against authoritative OWASP/ATLAS sources during implementation. Store edition/source/date and reviewed mapping rationale; update both packaged and benchmark copies or generate one from the other. Use `git mv` when renaming misleading files. Preserve original editions in legacy reports. Map observed findings without claiming a whole category is secure. Aggregate requested/completed/error/unsupported/not-applicable counts by target and family.

**Files:** [packaged mappings](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mappings), [benchmark mappings](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/mappings), [score](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/score.py), policy, report and packaging tests.

**Acceptance:** IDs/titles match the pinned edition; category output says “mapped checks completed,” not full-category assurance. One passing target cannot hide another target's incomplete check. No ATLAS claim without reviewed mappings. Unknown editions/IDs fail validation. Publish source references and comparison warnings when editions change.

### F12 — Agent, MCP and CI contracts

**Work:** adopt correct MCP stdio framing/lifecycle using a compatible SDK or narrowly tested implementation. Ensure stdout contains protocol only. Test a genuine client; distinguish Insidia's MCP server from support for scanning an MCP target. Align the agent skill, JSON outputs, exit semantics and Action. Bound MCP tool calls and preserve scope/cancellation; never let tool arguments broaden configured scope implicitly.

**Files:** [MCP](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mcp.py), `test_mcp_server.py`, `test_mcp.py`, [agent skill](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/skills/insidia/SKILL.md), [Action](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/actions/scan/action.yml), [llms.txt](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/public/llms.txt).

**Acceptance:** real initialize/tools-list/safe-call/cancel/error exchange succeeds; newline-delimited requests receive responses. CI uploads incomplete-run evidence without treating it as a pass; no `continue-on-error` hides the result. The skill follows the human quickstart and reports limits instead of broadening scope to make a scan succeed.

### F13 — Installation, runtimes and platform support

**Work:** make bare `engines install` fail with usage/explicit engine choices, not a success/no-op. Document named installation. Separate container execution from installation; remove misleading Docker success messages. Implement an OS/architecture asset table, ZAP launcher selection and runtime preflight. Check checksums against reviewed expected values and signatures where available. Lock transitive environments where feasible and record resolved versions; never imply top-level pins alone ensure reproducibility. Test uv and pipx entry paths and offline/no-network failures.

**Files:** [engines](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/engines.py), doctor, catalog, [Dockerfile](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/Dockerfile), packaging, `test_engines.py`, `test_packaging.py`, CI.

**Acceptance:** supported native platform rows install and run their smoke test on actual runners; unsupported rows fail before downloading the wrong binary. Digest mismatch fails closed. Interrupted installs leave the previous valid toolchain usable. Python/uv/Node/Java prerequisites are explicit. Container runs use a non-root user where compatible, support mounted output permissions and record immutable image digest. Engine platform support is not inferred from core's OS test matrix.

### F14 — Configuration, doctor and first valid run

**Work:** add a local example directory and a documented start/stop/reset workflow with vulnerable/fixed variants. Include both an AI endpoint and an AppSec target, plus a small repository example. Clearly distinguish a synthetic deterministic AI fixture from a real-model evaluation; the latter uses an explicitly configured model and measured costs. Doctor reports runtime, engine, scope, target-auth/schema and profile readiness with blocking/warning states. Any network preflight follows scope and budget rules.

**Files:** config, doctor, CLI, existing CLI/target tests; proposed `examples/product-demo/`; installation and quickstart docs.

**Acceptance:** a clean supported environment reaches an expected finding and comparable fixed rerun using copied documentation commands. No nonexistent default chat service is assumed. Config syntax/unknown fields/missing env references have useful messages without values. Demo binds to loopback, does not send external email or use real credentials, and cleans up its own resources.

### F15 — Report and comparison experience

**Work:** preserve the offline single-file format. Order content: execution/verdict/scope → priority findings → evidence/fix/retest → omissions → mappings/exports. Add responsive finding cards, expandable evidence, engine provenance, reasons for incomplete checks, run metadata and print styles. Add filters for severity/asset/engine/status if warranted. Comparison uses stable finding IDs and manifest compatibility checks; “resolved” requires the corresponding check to have completed on the comparable rerun.

**Files:** runstore, findings, score, report tests, existing brand assets; proposed separate template module to avoid mixing domain logic and markup. Apply the repository's design guidance during implementation.

**Acceptance:** one, zero, many, incomplete and legacy finding states are readable; decisive evidence is visible; hidden/filtered findings remain counted. At 360px and desktop widths, navigation/content remain usable, with horizontal scrolling confined to code where necessary. Keyboard and print flows work; report makes no network request. Browser tests use synthetic generated reports. A skipped rerun cannot mark a finding resolved. HTML/JSON/SARIF carry consistent findings/statuses.

### F16 — README and documentation repair

**Work:** rewrite README around purpose, real report, readiness, pinned install, working demo, own-target configuration, interpretation, support and contribution. Fix generated routes/anchors, fonts and favicon; crawl built output, not only source paths. Generate CLI/config/capability references from their contracts. Add auth examples, target/provider/transport support tables, exit codes, troubleshooting, scope, retention/privacy, upstream downloads, CI setup and reproducibility methodology. Remove obsolete skill/gRPC/level claims.

**Files:** [README](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/README.md), [docs content](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/src/content/docs), [link checker](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/scripts/links.mjs), [docs config](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/astro.config.mjs), docs package scripts and llms.txt.

**Acceptance:** zero broken internal built routes/anchors; Quickstart → Report/Scope works in the browser. Commands are copied into a clean test environment. Production and dev assets load. No fabricated report metrics or unsupported privacy/coverage claims. Explain the distinction between running checks on an app and independently benchmarking the scanner itself.

### F17 — Product website and conversion

**Work:** retain the existing identity; shorten the hero and use two actions: Install CLI / View sample report. Put the real outcome above abstract animations. Organize AI/agents, web/API and repository tasks around implemented support. Show configure → scan → inspect/fix. Reduce simultaneous motion; make Cloud secondary and clearly planned. Link engine credit to verified capabilities. Fix lead-form state: network success only after acknowledgement; mailto fallback says the client opened and preserves input. Announce validation/error states accessibly.

**Files:** [homepage](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/pages/index.astro), [hero](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/components/DataFlowHero.tsx), [demos](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/components/ScriptedDemos.astro), [lead form](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/components/LeadForm.tsx), header/footer/layout, benchmark/pricing/launch pages.

**Acceptance:** install/report/docs navigation works on narrow and desktop layouts. Keyboard order, focus, text contrast, reduced motion and error announcements are checked. The report preview references a generated sanitized artifact; no “confirmed” animation implies an unrecorded scan. Verify canonical URLs, sitemap, share preview and production DNS/TLS from a deployment check. Measure load behavior before adding decorative JavaScript; record the measurement environment rather than inventing performance scores.

### F18 — Demo and launch evidence

**Work:** produce one real 45–60 second recording using F14/F15. Storyboard: 0–5s outcome; 5–12s scope/config; 12–25s actual execution; 25–40s evidence/fix; 40–55s comparable rerun; 55–60s install/report links. Label time compression. Supply captions, transcript, poster and pause controls. Replace outdated mock UI statements. Publish a sanitized failed run, its fixed rerun and an incomplete-run example with version provenance.

**Files:** [video plan](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/plans/22-website-video-scripts.md), site demo/content/public assets, README media. Actual video recording is a deliverable, not satisfied by an animated mock.

**Acceptance:** anyone can reproduce the displayed scenario with the tagged release. Terminal/evidence text is readable; no synthetic numbers are presented as measurements. AI-to-AppSec chains appear only after a real chain is independently verified. Public artifacts contain only synthetic/redacted data and functioning links.

### F19 — Publish the artifact that was tested

**Work:** add release validation dependencies: build candidate once → test wheel and container → benchmark claimed capabilities → artifact/license/secret checks → sign → publish. Exercise the exact candidate digest, not a source checkout substituted for the package. Keep the release draft until all artifacts succeed; update `latest` only after the complete gate. Pin target source commits as well as images; generate SBOMs/notices for bundled Python/Node/native/container dependencies and review license exceptions explicitly.

Implement the candidate-build portion early enough to supply F18's recording and F20's pilots. F19 completion makes a signed release candidate available for pilots; it does not move the stable/latest channel. F20 authorizes the public-beta readiness decision, after which the same tested artifacts can be promoted through the normal publication process. This avoids a dependency cycle between recording, release validation and pilot testing.

**Files:** [CI](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/.github/workflows/ci.yml), [release](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/.github/workflows/release.yml), Dockerfile, [license checker](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/scripts/check_licenses.py), [notices](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/THIRD_PARTY_NOTICES.md), core packaging, Action.

**Acceptance:** failed image/engine/benchmark/license stage cannot yield a public successful release or move `latest`. Wheel/image provenance, checksums, support table and migration notes are attached. New dependency or engine updates rerun affected contracts. A documented rollback restores a known good release without rewriting history. Test deployment URLs and content after publishing; local DNS failure alone is not evidence of a global outage.

### F20 — Pilot and beta acceptance

**Work:** recruit three to five consenting teams using authorized test apps. Observe installation, setup, first valid scan, interpretation, fix and rerun. Record machine/platform, blockers, elapsed time, reproducibility, false-positive reports and repeat use without collecting secrets or full prompts. Maintain issues, a support process, security disclosure link and release notes.

**Acceptance:** at least three teams complete a valid combined workflow and comparable rerun. All beta release blockers are closed; any omitted capability is explicit. Publish measured benchmark counts and limitations, not generalized “secure” claims. A team failing onboarding becomes a tracked issue, not an excluded success metric. Pilot success supports a beta decision; it is not proof of product-market fit.

### F21 — Catalog expansion and real assurance profiles

**Work:** use sections 5/6 as the remaining backlog. Promote each family/engine only through F08/F09/F10 gates. Implement L2 as a versioned judged profile with explicit judge requirements, actual judge calls, calibrated labeled cases, rationale/evidence separation and budget/refusal accounting. Implement L3 as generated/adaptive attacks with attacker requirements, constrained scope, bounded steps and independent evaluation; preserve the deterministic baseline. Separate attack generation from judging; do not silently use one role in place of the other. Unconfigured roles yield unsupported/incomplete, not a lower-level success.

**Acceptance:** L1 makes no attacker/judge calls; L2 and L3 execute documented distinct behavior and record model/corpus versions. Judge disagreement, refusals, malformed model output and exhaustion are explicit. No level implies more assurance solely from its name. Current catalog disposition is complete only when every row has verified evidence or a documented defer/removal decision; the latter remains excluded from coverage claims.

### F22 — Cloud entry contract

**Work:** before Phase 2 coding, specify tenant isolation, queue/job state machine, idempotency, worker crash/retry behavior, cancellation and hard spend limits, encrypted evidence retention/deletion, secret lifecycle, private-runner connectivity, ownership/egress enforcement, usage accounting, backup/restore and operational support. Design the dashboard around the same result model; retain the CLI's useful free workflow. Validate demand for managed runs/history/scheduling/model execution with pilots before choosing the first paid feature.

**Acceptance:** threat model and data-flow review completed; RLS/tenant-isolation tests include a real database; job recovery/cancellation and cost accounting have test plans and explicit service targets. Health endpoints and scaffolding are never presented as the hosted product. A published decision records which user need justifies Phase 2A versus reprioritizing history/scheduling. No Cloud launch or spend is authorized by this planning document.

## 5. Every current family has a validation path

These are implementation requirements, not claims of existing coverage. Missing prerequisites must be visible. All families inherit positive, fixed/negative, error, budget, and reproducibility tests from F08/F10.

| Current families | Required production evidence / prerequisites |
| --- | --- |
| `ai.data_leakage`, `ai.hidden_context_extraction` | Per-run controlled canaries or permissioned sensitive-data references; distinguish user-supplied echo from protected-context disclosure |
| `ai.prompt_injection_direct`, `ai.jailbreak` | Explicit task/policy boundary; evidence of unauthorized behavior, not a universal fixed response string; semantic claims require calibrated evaluation |
| `ai.prompt_injection_indirect`, `ai.rag_poisoning`, `ai.memory_poisoning` | Controlled document/memory injection and reset; observed retrieval/action provenance and matched clean baseline |
| `ai.cross_tenant_bleed`, `ai.embedding_inversion` | Isolated tenant identities or controlled embedding dataset; unauthorized recovery/overlap evidence and defined denominator |
| `ai.citation_groundedness` | Reference documents and citation entailment/attribution checks; report uncertainty separately from proven exploit |
| `ai.tool_misuse`, `ai.dangerous_tool_args`, `ai.tool_chain_hijack`, `ai.privilege_identity_abuse` | Instrumented tool/action trace, identity/permission boundary and outcome observer; no inference from “called” or “sent” alone |
| `ai.code_exec_sandbox_escape`, `ai.secondary_injection`, `ai.output_handling_sinks` | Safe controlled sinks/canaries, downstream effect and containment; never execute an unbounded payload to prove a check |
| `ai.multi_agent_spoof`, `ai.cascade_rogue` | Multi-agent identities, trust boundary and observable downstream actions with reset; otherwise unsupported |
| `ai.supply_chain`, `ai.agent_posture` | Actual configuration/artifact/provenance rules and affected paths; distinguish posture warnings from exploit proof |
| `ai.unbounded_consumption` | Measured request/token/tool budget behavior in a bounded test; no real resource exhaustion required |
| `ai.harmful_content_policy`, `ai.bias` | Versioned evaluation rubric and labeled examples, model settings, repeat protocol; label safety/fairness evaluations distinctly from technical vulnerabilities |
| `web.ssti` | Randomized paired arithmetic/control requests with baseline and match context |
| `web.cmdi`, `web.path_lfi`, `web.ssrf`, `web.deserialization`, `web.xxe` | Capability-specific controlled evidence, safe target instrumentation/callbacks and blocked/patched pairs; no generic marker success |
| `logic.race` | Actual controlled concurrency and observed invariant violation with sequential baseline; isolate/reset test state |
| `infra.cve`, `infra.tls` | Version/advisory evidence with uncertainty; actual TLS negotiation against a controlled endpoint for protocol claims |
| `api.bola_idor`, `api.bfla`, `api.mass_assignment`, `auth.jwt_oauth_session` | Two controlled identities/roles and known resources/permissions, mutation reset and validated allowed/denied baselines |
| `code.sast_sinks`, `code.secrets`, `deps.sca` | Real project discovery, rule/file/line or package/lockfile/advisory evidence; avoid special fixture filenames |
| Unscheduled `code.mcp`, `code.skills`, `deps.osv`, `code.python`, `code.go` | Add canonical registry aliases/policy membership only after corresponding engine contracts are verified |
| Advertised SQLi/XSS | Add explicit `web.sqli`/`web.xss` capabilities with real upstream findings and negative controls; absent until implemented |

Transport/provider expansion is separately inventoried: HTTP, WebSocket, GraphQL, MCP targets, repository access, and every advertised model provider need auth/schema/lifecycle tests. gRPC remains unsupported until a real transport and detector integration is implemented. A provider accepted by configuration is not automatically supported by every generated engine runner.

## 6. Every catalog engine has an integration task

Use pinned official interfaces when implementing; the table deliberately does not guess exact upstream flags or APIs. Each row inherits F09's end-to-end gate.

| Engine | Required work and truthful role |
| --- | --- |
| garak | Replace blank smoke probe with a documented substantive corpus/profile; preserve actual probe/detector results and model/target configuration |
| promptfoo | Integrate real configured evaluations/red-team checks; parse native assertions/evidence instead of one static “secret” response |
| PyRIT | Define actual attack strategy/objective/target contract and result parsing; distinguish single prompt transport smoke from attack evaluation |
| DeepTeam | Align chosen vulnerability/rubric with reported family; preserve evaluation results; configure attacker/judge roles explicitly |
| mcp-scanner | Connect repository capability to policy selection; retain MCP configuration/file/rule locations and prerequisites |
| SkillSpector | Connect skill-analysis capability to policy; retain affected skill/rule/evidence and runtime requirements |
| NuGuard | Verify agent-posture result schema/severity/location; keep posture assessment distinct from proven runtime exploitation |
| ZAP | Configure intended crawl/passive/active jobs explicitly within authorization/budgets; parse native alerts, confidence and URLs |
| Nuclei | Use reviewed pinned templates relevant to named families; preserve template/matcher/location; validate SSTI controls |
| Dalfox | Integrate its actual XSS purpose and native findings; do not classify it as generic SSTI verification |
| katana | Discovery role with scoped asset output and provenance; no vulnerability pass when it discovers nothing |
| httpx | Reachability/fingerprinting role with response status/context; no vulnerability pass from an empty parser |
| Trivy | Preserve package/version/advisory/fix or misconfiguration evidence; publish exactly which scan modes are supported |
| osv-scanner | Make dependency scanning selectable; preserve lockfile/package/advisory/version/fix and valid empty-report semantics |
| gitleaks | Preserve redacted rule/file/line/fingerprint; test multiple occurrences and history versus working-tree scope |
| Bandit | Make Python rules selectable; preserve path/line/native severity/confidence and supported source discovery |
| gosec | Make Go rules selectable; preserve path/line/rule/confidence and toolchain prerequisites |

## 7. Verification, rollout and release gates

### Regression checklist

- [ ] 401-only target cannot produce exit 0.
- [ ] Wrong selector/login HTML cannot masquerade as application output.
- [ ] Failed or malformed engine execution remains incomplete even alongside a clean engine.
- [ ] Price `49` and other incidental constants do not trigger SSTI.
- [ ] Shared rate/concurrency limits hold across engines; denied secondary requests never reach the test listener.
- [ ] Every known synthetic secret is redacted in every artifact/error path.
- [ ] Match after character 500, two locations with the same rule, and multi-engine provenance survive normalization.
- [ ] Interrupted report writes and missing artifacts do not report success.
- [ ] Legacy runs remain untouched and do not claim known completeness.
- [ ] Real MCP client interoperates; Action preserves nonzero scan outcome while uploading evidence.
- [ ] Policy/engine/OS support tables match actual registry and installer behavior.
- [ ] Benchmark scorer counts extra findings and missed positives correctly.
- [ ] Public example fixes are established through comparable completed reruns.
- [ ] Built docs/site routes, mobile report, print view and accessible controls pass their user journeys.

### Commands and environment

For implementation PRs, follow repository-required checks. From core: `uv run ruff check .`, `uv run mypy insidia`, `uv run pytest`. From cloud: `uv run ruff check .`, `uv run mypy api workers`, `uv run pytest` with PostgreSQL configured so required database checks are not silently skipped. From root: `uv run --project cloud ruff check benchmark` and `uv run --project cloud python -m pytest benchmark` in the documented engine/container environment.

When ownership/validity changes, generate the matrix using `uv run --project cloud python -m benchmark.matrix.cells --write`, then require `--check` to pass. Never hand-edit generated rows to manufacture a green gate.

Site: `npm ci`, `npm test`, `npm run build`, then its secret scan. Docs: `npm ci`, `npm run check`, `npm run build`, then the built-route/anchor check introduced in F16. Add browser journeys and real engine/artifact jobs to CI; source-only unit checks do not replace them. Check dashboard/Go components when their files change. Use specialist code review appropriate to changed languages during implementation; this plan itself changes Markdown only.

Test tiers: fast unit/parser checks per PR; scoped local integration with synthetic targets per affected package; full pinned engine/platform/artifact/benchmark suite before release. Record unavailable/skipped checks explicitly. A package cannot be complete based only on an unavailable test environment.

### Rollout

Ship contract changes as a prerelease with schema/exit/profile migration notes. Keep legacy reports readable and old versions downloadable. Promote the same tested candidate artifacts after pilot gates; do not rebuild a different binary for publication. Roll back by pointing users to the previous verified release and preserving run artifacts, never by changing git history or silently reinterpreting old scores.

## 8. Traceability to the entire review

| Review concern | Owning work |
| --- | --- |
| R1 false passes / target validity | F01, F02, F14 |
| R2 fixture-specific detectors / false positives | F00, F07, F08, F10, F21 |
| R3 benchmark validity | F10, F19 |
| R4 engine selection / unsupported capabilities | F07, F09, F13, F21 |
| R5 partial results / L1–L3 / aggregation | F01, F02, F07, F11, F21 |
| R6 rate/concurrency/scope/auth boundaries | F03, F09, F12 |
| R7 taxonomy editions | F11, F16 |
| R8 MCP framing | F12 |
| R9 evidence / dedup / severity / SARIF / rerun | F06, F15 |
| R10 redaction / incomplete artifacts / retention | F04, F05 |
| R11 installation / platform / provenance / licenses | F13, F19 |
| R12 documentation / doctor / first use | F02, F14, F16 |
| Report layout, mobile, print, search, fix workflow | F15 |
| README clarity and truthful product positioning | F00, F16 |
| Homepage hierarchy, animation, accessibility, lead form | F17 |
| Actual video and public sample credibility | F18 |
| Public reachability, metadata, production links | F17, F19 |
| Developer maintainability / duplicated contracts | F01, F06, F07, F09, F11 |
| Cloud scaffolding / premature infrastructure | F22 |
| Adoption, support and product validation | F20 |

## 9. Operating the plan

The repository maintainer is accountable for each package until an owner is assigned. In each implementation PR, record: package ID; exact sub-scope; changed contracts; passing and skipped checks; sample redacted output; migrations; remaining limitations. Update the master-plan status only when work actually starts or its exit gate passes. Do not mark the review complete merely because the display text was changed.

Start with these focused PRs:

1. `test(core): capture result integrity regressions` — F00 fixtures/inventory and immediate unsupported-claim corrections.
2. `refactor(core): separate execution results from policy verdicts` — F01, including matching basic output states.
3. `fix(core): validate target responses and engine reports` — F02, making the false-pass regressions pass.
4. `fix(core): enforce shared target execution budgets` — F03, with scope/cancellation tests.
5. `fix(core): redact evidence and finalize run artifacts safely` — F04/F05, split if too large for focused review.

Then deliver F06/F07, and develop F08/F09 alongside F10's independent evaluation. Mapping/MCP/installer work can proceed after their contracts settle. Finish the user-facing path in F14–F18, then apply F19/F20. F21 continues capability expansion under the same gates. No external messages, purchases, publication or deployments are performed merely by creating this plan.

### Scheduling and decisions

Use engineering estimates after F00 and one completed engine integration; current work includes unvalidated external interfaces, so an exact calendar date would be false precision. Reserve a one-to-two-day assessment per unfamiliar engine before estimating its implementation. Size ordinary packages into PRs that one engineer can review independently; split F03/F09/F10/F21 by tested behavior, not file count. The dependency table is the execution order even if calendar estimates change.

No product answer is required to start F00–F07. Before paid live-model evaluation, the maintainer must supply a permitted endpoint and spend budget; synthetic tests and local evaluation can proceed independently. Before public media, choose a synthetic scenario and verify the tagged build. Before F20, choose pilot teams and obtain their authorization. Before F22, select the paid feature from observed demand. These are future operational inputs, not reasons to delay the result-integrity work.

**Handoff:** ready for direct implementation of F00/F01. Review the domain contract in section 3 at the start of that PR; the rest of the work proceeds through the dependency and acceptance gates above.
