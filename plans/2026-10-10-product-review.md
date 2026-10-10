# Insidia: engineering and product review

Reviewed 10 October 2026. Perspective: a senior engineer evaluating whether to adopt, contribute to, and recommend Insidia. This reviews the current checkout and six local sample runs; it is not a certification or a claim that every integration was exercised.

## Adoption verdict

**I would try Insidia on a disposable test application. I would not yet use its pass/fail result as a security release gate.** The most urgent work is making the result trustworthy, followed by making the first successful scan easy. More visual polish or a hosted attacker model cannot compensate for an invalid pass.

The product direction is coherent: combine AI security and application security engines into a reproducible benchmark, fill specific gaps, and produce evidence developers can act on. Integrating open-source tools is a valid product foundation. The value must come from reliable execution, coverage accounting, normalization without information loss, and a shorter path from finding to verified fix.

Keep the combined AI + AppSec ambition. Deliver it incrementally through verified capabilities rather than equating an installed engine or a green matrix cell with complete coverage.

### What is already useful

- Clear upstream attribution, an Apache-2.0 codebase, contribution/disclosure documents, and separate trademark treatment.
- Local execution without an account, explicit scope configuration, and a useful CLI/config foundation.
- Separate core, benchmark, site, docs, and cloud areas; typed Python, linting, tests, and CI already exist.
- A portable HTML report plus JSON and SARIF are sensible outputs. Escaping report text and avoiding a runtime web service for viewing reports are good choices.
- The site has a recognizable identity, documentation navigation, metadata, keyboard affordances, and reduced-motion/pause provisions.

These are foundations to retain. Passing the current tests establishes some implementation consistency, but the tests currently leave major product claims unverified.

## Scope and evidence

Reviewed README, plans, contribution/security rules, CLI configuration and execution, adapters/installers, policy/scoring, normalization/reporting, MCP integration, benchmark methodology, CI/release configuration, cloud/dashboard readiness, marketing and documentation source, and six saved runs. Rendered the marketing and documentation sites locally and inspected their navigation and demo animations. Inspected the supplied reference sites.

Evidence labels below distinguish **reproduced behavior**, **source inspection**, and **recommendations**. Reproductions used synthetic inputs, mocks, or an isolated localhost server; no third-party target was scanned.

Limits:

- Public Insidia domains were unreachable from this environment; that does not establish a global outage. Local previews were used for the visual review.
- The browser blocked local report file URLs. Reports were inspected through their HTML/JSON/SARIF and rendering code, not visually rendered in the browser. Mobile rendering was not conclusively verified.
- Full external-engine installation, live model evaluation, the entire Docker/upstream benchmark, clean-machine release installation, macOS/Windows execution, and database-dependent cloud tests were not completed.
- No adoption, retention, revenue, or market-demand evidence was available. Product metrics below are proposed targets, not existing results.

## Release blockers and engineering findings

Here, P0 means a blocker to presenting the result as a trustworthy security benchmark; it is not a CVSS rating. P1 means fix before recommending general use. P2 means product quality or maintainability work after correctness.

### R1 — P0: an unusable target can receive a passing result

**Reproduced:** a localhost endpoint returning HTTP 401 for every request produced `policy_passed: true`, eight passing controls, and zero findings. The scan completed in approximately 0.024 seconds with an `rps: 1` configuration.

The HTTP transport returns non-redirect response bodies without rejecting unsuccessful statuses. A missing/invalid response selector also falls back to the original body. The scanner interprets an empty finding list as a passed control, without proving that the intended application operation was reached. [HTTP transport](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:113), [selector](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:229), [verdict](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:130).

**Action:** introduce target preflight and typed execution outcomes. Check reachability, authentication, expected response shape, and per-check prerequisites. A 401 may itself be a valid security response for some checks, but it must not automatically mean every unrelated check passed. Distinguish complete, incomplete, error, unsupported, and not applicable from finding/no finding.

**Acceptance:** unauthorized endpoints, HTML login pages, missing JSON selectors, connection failures, and failed engines cannot produce an unconditional pass. A fully exercised negative control can.

### R2 — P0: many built-in checks recognize fixtures rather than general vulnerabilities

**Source inspection:** multiple detectors expect exact planted strings such as a fixed canary, `policy disabled`, `called`, or a specific vulnerable fixture version. The TLS family sends an application payload and looks for `tls1.0`; it does not measure negotiated TLS. The race family sends `once`, without concurrent requests. Repository fallbacks inspect special fixture files and exact strings. [Oracles and corpus](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/adapters.py:256), [repository fallback](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:97).

**Reproduced false positive:** with attack `{{7*7}}`, the benign response `This item costs 49 dollars.` satisfies the SSTI detector. The arithmetic check has no baseline or randomized challenge to establish causation. [Arithmetic oracle](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/adapters.py:132).

Fixture-specific detectors are valuable for testing transport and plumbing. They do not establish broad vulnerability detection on arbitrary applications.

**Action:** label fixture checks explicitly. For each production check, define prerequisites, attack/control pairs, evidence requirements, false-positive controls, and unsupported cases. Start with a smaller verified set spanning both AI and AppSec. For SSTI, use paired randomized expressions and baseline responses; preserve the matched output. For other families, use actual protocol/behavior measurements or a correctly integrated upstream detector.

### R3 — P0: the benchmark does not independently establish shipped scanner performance

Several paths bypass the shipped scanner or score its output using knowledge of the expected answer:

- `_matched` filters findings to the expected attack family, then substitutes the expected plant ID. Other emitted findings are discarded before scoring, so this path cannot measure all false positives. [Matcher](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/run_cell.py:111).
- CLI fixture runs explicitly use an empty external toolchain; SDK cases call the fixture and built-in oracle directly. [SDK/CLI paths](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/run_cell.py:135).
- Upstream white-box cases search known source locations for expected text or functions, then manufacture the expected finding. [Upstream proof](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/upstream.py:115).
- Live cases use prescribed harness exploits. AgentDojo cases directly invoke in-memory calendar/email tools, rather than measuring an attacked model or agent workflow. [Live harness](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/live.py:463), [AgentDojo path](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/benchmark/harness/suite.py:33).

These establish useful facts about fixtures and harness behavior. The plan's green Phase 1B/1C cell counts should not be presented as independent CLI detector recall or engine coverage. Permutations are also not distinct vulnerabilities.

**Action:** separate three suites: fixture integrity, adapter contracts, and black-box evaluation of the released CLI artifact. The last must score every emitted finding against independently maintained truth, include patched/benign cases and unseen variants, and retain engine/target versions. Report precision, recall, execution completeness, cost, and duration by capability; publish exclusions and uncertainty. Do not let a scan harness replace detector output with expected answers.

### R4 — P1: installed engines and advertised coverage differ from executed checks

**Reproduced selection experiment:** with all 17 catalog engines marked available, standard coverage across the 40 policy families selects Insidia for 39 families and NuGuard for one. Built-ins have priority 100; external engines have lower priorities. This is a registry experiment, not a claim all engines were installed. [Selection](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/registry.py:61), [built-in priority](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/adapters.py:246).

Five catalog families are absent from the policies: `code.mcp`, `code.skills`, `deps.osv`, `code.python`, and `code.go`. Those paths cannot be scheduled even by thorough coverage. AI engine adapters largely share the `ai.data_leakage` family and a tiny static input path. Several web tools are registered under SSTI; the CLI has no `web.sqli` or `web.xss` policy family. The ZAP plan has request/report jobs, not an active scan. Some web parsers always return no findings. [Catalog](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/catalog.py:29), [parsers](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:326), [ZAP plan](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:690).

DeepTeam's generated runner uses a bias test while its adapter is classified as data leakage, with observations rejudged through the leakage path. This needs a capability contract, not just a successful process launch. [Runner](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:892).

**Action:** maintain one registry of implemented capability, target prerequisites, supported upstream probes, parser, readiness, and benchmark evidence. Generate docs and policy compatibility from it. Show users what is installed, selected, actually executed, and unsupported. Do not treat a tool's full upstream feature list as Insidia coverage.

### R5 — P1: partial execution can look clean, and levels do not establish different assurance

**Reproduced:** a failed engine can coexist with a passing run; its skip reason is absent from HTML. Source confirms one successful empty result can make a control pass despite another failed engine. Missing/malformed external report parsing can also become an empty result. Framework aggregation can mark a category passed when one mapped control passed and others were skipped. [Execution](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:114), [report parsing](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:456), [aggregation](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/score.py:94).

L1, L2, and L3 share the same controls. Judge providers are constructed and discarded by the scan path. A benign mocked target produced the same eight passing controls for all three levels. Model availability is not a substantive level-specific execution contract. [Policies](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/policy.py:325), [provider setup](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:44).

**Action:** make completeness independent of findings, validate engine report schemas, and preserve partial findings while flagging incomplete execution. Define required versus optional checks in a versioned profile. Ship a truthful baseline first, or implement genuinely distinct level requirements; a higher label alone must not imply deeper evaluation. Show skipped/error reasons in every output.

### R6 — P1: rate, concurrency, and scope guarantees need a common execution boundary

**Reproduced/source:** the HTTP path creates a fresh limiter for every request, resetting its timing state. The configured concurrency is not enforced by the inspected execution path. External engine concurrency can also differ from target settings. [Limiter creation](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:62).

URL-based external adapters receive a narrowed URL representation rather than the full request/authentication/rate-limit configuration. Initial URL validation does not by itself constrain every request an external process subsequently makes. Some model requests use a separate urllib path. These are unproven control boundaries; an actual external-engine scope escape was not demonstrated. [Adapter dispatch](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:55), [URL handoff](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:267).

**Action:** share a limiter and concurrency budget per target; define time/request/token budgets and cancellation. Route supported network engines through an enforced scope boundary or equivalent tested egress controls. Reject unsupported authentication/method combinations explicitly. Test redirect, subdomain, alternate-port, and secondary-request behavior rather than assuming the initial URL check covers an engine's whole run.

### R7 — P1: framework mappings need correct, explicit editions

The local `owasp-llm-2026.yaml` assigns several IDs differently from the official 2025 taxonomy. For example, local LLM03 describes excessive agency while official LLM03 is supply chain; local LLM06 describes unbounded consumption, assigned LLM10 in the official edition. The filename does not establish an official 2026 standard. [Local mapping](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mappings/owasp-llm-2026.yaml:1), [official OWASP LLM list](https://genai.owasp.org/llm-top-10/).

The web mapping uses older IDs without making the edition clear. OWASP Web 2025 assigns injection A05 and software supply chain A03, unlike the older ordering. [Official OWASP Web 2025](https://top10.owasp.org/2025/). ATLAS coverage mentioned in presentation material also needs implemented mappings and evidence before being counted.

**Action:** store framework ID, edition, source URL, and mapping rationale. Version scoring alongside mappings. Validate against authoritative source data; tests that repeat incorrect local labels are insufficient. Keep the existing distinction between mapping and certification. A few tests mapped to a broad category should not read as that entire category being secure.

### R8 — P1: the MCP server uses incompatible stdio framing

**Reproduced:** feeding a newline-delimited JSON-RPC initialize request followed by EOF to the server returned no response. Source expects and writes `Content-Length` framing. [Reader/writer](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mcp.py:161).

The MCP stdio transport specifies newline-delimited JSON-RPC messages. [Official transport specification](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports). The present tests exercise the implementation's own framing, leaving real client interoperability unverified.

**Action:** use a compatible maintained SDK or implement the specified framing and lifecycle. Add a real client integration covering initialize, tools/list, a safe tool call, cancellation/error handling, and separation of stdout protocol traffic from stderr logs. Distinguish serving Insidia tools over MCP from scanning arbitrary MCP targets; they need separate support contracts.

### R9 — P1: evidence normalization loses information needed to trust and fix findings

The normalizer stores the first 500 response characters and an evidence hash, but not the matched evidence itself. It substitutes the family for the attack and the target name for a trace reference. Severity/confidence are largely assigned by Insidia rather than preserving upstream context. Deduplication by target/family/evidence hash can collapse separate locations. [Normalization](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/findings.py:36), [probe conversion](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:78).

**Observed sample:** run `20261009T090000Z-8738eb` contains a 500-character response without the standalone `49` that its evidence hash represents. It says cross-validated by Insidia and Nuclei, but both can be reacting to the same arithmetic payload/result. Two engine names do not automatically establish independent confirmation.

Repository parser output also loses locations/package details; the five finding-bearing sample SARIF files contain no result locations. The HTML rerun command only preserves the policy, dropping configuration, coverage and other reproduction context. [SARIF/rerun](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/runstore.py:203).

**Action:** preserve redacted request, matched snippet with surrounding context, affected location, upstream rule/severity, detector lineage, and reproduction parameters. Separate a finding's stable identity from individual engine observations. Say “reported by two engines” until stronger corroboration criteria are satisfied. Preserve engine versions and test lineage so repeated use of the same oracle is visible.

### R10 — P1: redaction and report persistence need stronger contracts

The masker recognizes a small set of AWS/GitHub/Stripe/PEM patterns. Synthetic generic bearer credentials, newer token formats, and email addresses were unchanged. Error text from engines follows a separate persistence/logging path. This demonstrates limited coverage, not that real credentials were found in the supplied runs. [Masking](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mask.py:9), [error persistence](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:114).

One supplied run has findings and SARIF but no benchmark JSON or HTML. The report command still returned the nonexistent HTML path with success. `write_run` writes files sequentially; latest-run selection accepts any directory. The historical cause of that incomplete run is unknown, but the present reader does not reject it. [Writing/loading](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/runstore.py:121).

**Action:** centrally redact known configured secret values and supported credential patterns in output, logs, errors, evidence, and exports. Document what data is retained and which upstream services/caches may receive it. Write a versioned run manifest with complete/incomplete status, CLI/engine versions, timestamps, config digest, policy/coverage, and target identity. Publish completed reports atomically; make report lookup validate artifacts. Use restrictive evidence permissions and explicit retention controls.

### R11 — P1: installation and release claims exceed the paths verified here

The documented bare `insidia engines install` command installs nothing: it returns a message asking for an engine name. The Docker option also does not install named engine images. [Installer](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/engines.py:106), [quickstart](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/src/content/docs/start/quickstart.md:21).

Source inspection and a platform-selection experiment found Linux asset URLs selected for multiple native tools even when the platform is Darwin. ZAP's launcher selection needs Windows handling. Python engine installation depends on uv/Python 3.12 even when the CLI was installed with pipx. Downloaded native engine artifacts lack digest/signature verification. Top-level version pins do not fully lock transitive environments. [Asset selection](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/engines.py:397).

The project's own release signing is a positive foundation. Extend the release gate to the complete distributed artifact: test installation and a real scan from wheel/container, publish only after checks, record SBOMs and engine provenance, verify downloaded artifacts, and state OS/architecture support per engine. The current narrow license checks do not establish compliance of every runtime/transitive artifact; audit them rather than inferring coverage from declared engine licenses.

### R12 — P1/P2: the first-use documentation journey breaks

**Browser reproduced:** Quickstart → Report opens `/start/concepts/report.md` and returns 404. Built output inspection found 16 broken internal link occurrences. The checker passes because it verifies source-file existence instead of generated routes. [Quickstart links](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/src/content/docs/start/quickstart.md:19), [link checker](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/docs/scripts/links.mjs:20).

The local documentation preview also logged blocked requests for shared Sora font files outside Vite's serving allow list and a 404 for `/favicon.svg`. Fix the asset paths/dev-server configuration and verify the production output separately; these local logs alone do not establish a production font failure.

The default config assumes a chat service at localhost:8080; it does not give a new user an immediately runnable target. Doctor's success is driven by Python/config checks and is not adequate evidence of target authentication, schema, or model readiness. [Doctor](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/doctor.py:43).

**Action:** add a known-good local example spanning an AI endpoint and an AppSec target, with a vulnerable and fixed version. Publish exact commands, prerequisites, expected outputs, duration/cost ranges from measured runs, and troubleshooting. Crawl built docs routes/anchors in CI. Add target-specific configuration/auth examples and a reference generated from the actual config schema.

## What the supplied reports demonstrate

Source: [local runs](/home/rushi/Desktop/Rushi/testing/.insidia/runs). The underlying files were left unchanged.

| Run | Observed artifacts/result | Interpretation |
| --- | --- | --- |
| `20261009T055850Z-18aebb` | One high SSTI finding, findings JSON and SARIF; no HTML or benchmark JSON | Incomplete stored run; report lookup must detect this |
| `20261009T060428Z-6b58d9` | L1 failed, one finding, nine controls, one skip | Predominantly the same web scenario |
| `20261009T062141Z-79bb65` | L1 failed, one finding, nine controls, one skip | Same presentation/evidence limitations |
| `20261009T065641Z-ae13b4` | L1 failed, one finding, nine controls, one skip | Same presentation/evidence limitations |
| `20261009T090000Z-8738eb` | L1 failed, one finding, nine controls, one skip | Saved response omits decisive arithmetic evidence |
| `20261009T090823Z-7e6a14` | L2 passed, zero findings, nine passing controls | Insufficient manifest information to prove a like-for-like fix/retest |

The completed failed runs show eight passing controls and one failed control. The final run shows nine passing controls. Framework summaries leave the AI/agent/API frameworks untested while summarizing the web scenario. These examples do not yet demonstrate the combined AI + AppSec product promise. Do not use the latest L2 result as proof of a fix or deeper assurance without matching configuration, versions, and target revision.

### Make the report useful before making it decorative

Recommended reading order:

1. **Run status and completeness:** what target/revision was tested, what profile ran, time, and whether anything failed to execute.
2. **What needs attention:** severity counts, affected assets, and the highest-priority findings.
3. **Evidence and action:** affected endpoint/file, actual probe, redacted request/response or code location, why the detector fired, engine/version, a specific fix, and a reproducible retest.
4. **Coverage and omissions:** requested/executed/skipped/error counts, reasons, prerequisites, and unsupported capabilities.
5. **Framework mappings and exports:** edition-specific references, JSON/SARIF, and methodology.

Keep a single-file offline report. Use finding cards with expandable evidence, severity/text labels, search/filter if the volume warrants it, sensible print styles, and responsive layouts. The current wide tables and missing viewport metadata in the template deserve a mobile pass. Framework rows should not push the only actionable finding far down the page.

Suggested example status copy, contingent on implementing the semantics:

> Scan incomplete. One finding needs review. Eight checks completed without findings; one required engine failed. Review the evidence and rerun the failed check before using this result as a release gate.

Do not add a dramatic overall security score until its denominator, applicability, completeness, weighting, and uncertainty are defensible.

## README, documentation, website, and demo

### Explain the product in one sentence

Suggested direction: **“One security report for your AI app and the application around it.”**

Supporting copy: “Insidia brings open-source AI security and AppSec engines into a local workflow, with named checks, reproducible evidence, and explicit coverage.” Use this as intended positioning; qualify current limitations beside it until the findings above are resolved.

README order:

1. One-sentence purpose and an actual report screenshot.
2. Prerelease/support status and a short “what works today” table.
3. One recommended install path with a pinned released version.
4. A runnable local demo with its expected result.
5. Configure your own AI, web/API, or repository target.
6. How to interpret findings, incomplete execution, and coverage.
7. Verified engine capabilities, upstream credit, privacy/scope, contributing, license, and roadmap.

Avoid listing an engine's capabilities as if all are exposed through Insidia. Clearly separate implemented, experimental, and planned support. The current gRPC “works with” claim conflicts with the explicit unsupported CLI path. Replace illustrative numbers in the README hero with an identifiable real example or label them prominently as mock data.

Documentation should answer practical questions: Which target format fits my app? How do I supply headers/auth without leaking them? What does the engine install? What does each profile cost and cover? Why was a check skipped? What exit codes should CI use? How do I reproduce a finding? How do I delete stored evidence? Keep agent-skill onboarding alongside a complete human quickstart.

### What to borrow from the supplied inspiration

[ihatepdf.com](https://ihatepdf.com/) puts an immediate action and task-oriented tool choices near the top. Borrow the low-friction start, concrete benefits, and visible outcome. Insidia's equivalent is an install command plus a public sanitized sample report, not a generic tool-logo grid.

The [Peerlist project](https://peerlist.io/pranavcode2442/project/ihatepdf--privacyfirst-pdf-toolkit) links to [ihatepdf.cv](https://www.ihatepdf.cv/), a different destination from the supplied .com site. Its privacy-first story and the .com site's server/browser processing descriptions should not be conflated. Do not borrow privacy claims or self-reported traction without verifying what Insidia actually does.

Use a similarly direct presentation, adapted to developer trust: show the output, explain where data goes, make getting started obvious, and substantiate the core promise. Keep Insidia's own visual identity.

### Recommended homepage

The current navy/purple background, orange/magenta identity, and spacious layout provide a usable base. The first viewport spends too much space on a large multi-line headline, multiple calls to action, and an abstract animation. Four hero choices and repeated Cloud messaging compete with trying the CLI.

Use this hierarchy:

- Compact header: Product, Sample report, Docs, GitHub.
- Short hero, two actions: **Install CLI** and **View sample report**. Include a copyable, verified install command and supported-platform note.
- A real report preview showing one finding, its evidence, and any incomplete coverage.
- Three use-case entries: AI apps and agents; web and APIs; code, secrets, and dependencies. Each links to its actual support matrix and quickstart.
- Three real workflow steps: configure scope, run checks, inspect and verify a fix.
- Credited engine capabilities, benchmark methodology, local execution/data handling, and a secondary Cloud roadmap section.

Replace defensive or implementation-centric phrases with concrete user outcomes. Keep limitations clear but place the detail where a user is evaluating support. Reduce simultaneous looping animations and decorative blank space; increase code/evidence text size. Validate keyboard navigation, contrast, reduced motion, 360px layouts, and print styles before calling the redesign complete.

The waitlist fallback currently switches to a success state around a mailto flow before delivery is established. Preserve entered data and say the email client was opened; only claim signup success after a successful submission to a working endpoint. No live form was submitted during this review.

### The current “videos” need a real evidence story

The local site presents scripted/animated interface demos. They explain an intention, but are not recordings of an end-to-end run. The hero displays “Critical · confirmed” and says the test already ran without linking a corresponding trace. A demo note says the installable skill is absent although it is now in the repo; another shows a planned expanded finding view. [Hero](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/components/DataFlowHero.tsx:70), [demo notes](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/components/ScriptedDemos.astro:85).

Record one readable 45–60 second demonstration after the underlying behavior is verified:

| Time | Show | Point |
| --- | --- | --- |
| 0–5s | Actual finding and affected sample application | Establish the outcome first |
| 5–12s | Small scope/config excerpt for the AI and AppSec targets | Show what the user supplies |
| 12–25s | Real CLI progress, selected engine names, completion state | Show execution; label any time compression |
| 25–40s | The exact evidence, location, and remediation in the report | Explain why the finding is credible |
| 40–55s | Fix and rerun with matching configuration/version | Demonstrate the useful workflow |
| 55–60s | Install command, sample report, GitHub | Make the next step obvious |

Use captions, pause controls, a static poster, and a transcript. Keep terminal text readable on a laptop. Record only behavior the released build actually supports. If an AI-to-AppSec chain is not yet established end to end, demonstrate two verified checks rather than portraying a chain as complete.

## Developer-facing design priorities

The repository does not need a wholesale rewrite. Strengthen the contracts between existing modules:

| Contract | Required information/invariant |
| --- | --- |
| Capability | Exact supported check, prerequisites, target kinds, engine/probe/version, evidence rules, readiness |
| Execution result | Complete/partial/error/unsupported, observed findings, diagnostics, duration and budget use |
| Finding and observations | Stable affected-location identity; per-engine original rule, severity, redacted evidence, detector lineage |
| Run manifest | Schema version, completion, effective config digest, tool/target versions, scope, profile, timestamps |
| Policy evaluation | Explicit required coverage; finding threshold and completeness evaluated independently |
| Benchmark case | Independent truth, vulnerable/fixed variants, reproducible target revision, all output scored |

Build report/CLI/JSON/SARIF from the same evaluated result model. Make adapter parser errors distinct from valid empty reports. Add recorded parser fixtures for each pinned engine and separate live smoke tests to detect upstream drift. Prefer regression tests that challenge assumptions—401 responses, benign arithmetic, wrong schemas, missing artifacts, duplicate rule IDs at different files—over more permutations of the same planted marker.

Keep cloud and dashboard claims aligned with their present scaffold. The dashboard is not yet a complete hosted scan experience. Before paid scanning, prove orchestration reliability, isolation, cancellation, tenancy, data retention, usage accounting, and supportability; do not use a working health endpoint as readiness evidence.

## Recommended product roadmap

Insert a **Phase 1F: reliability, evidence, and productization** before the current plan's Phase 2A hosted model service. This is a recommendation; the existing master plan was not modified. Sequence by acceptance gates, not speculative launch dates.

| Milestone | Deliverable | Exit gate |
| --- | --- | --- |
| 1. Trustworthy results | Typed execution/completeness, valid target preflight, truthful detector support, shared budgets, masking, atomic run manifests, corrected mappings | Error/unsupported cases cannot silently pass; benign controls do not trigger fixture oracles; reports retain decisive evidence |
| 2. Verified combined coverage | At least one substantive AI integration and one substantive AppSec integration, correctly selected and parsed, with a versioned capability registry | Released CLI detects independent vulnerable cases and stays quiet on matched fixed/benign cases; every advertised capability has evidence |
| 3. Repeatable user workflow | Clean install, doctor readiness, working docs, real local demo, actionable HTML/SARIF, MCP interoperability | A new tester can install, scan, understand one finding, fix, and rerun without repository knowledge; incomplete runs remain explicit |
| 4. Presentable public beta | Updated README/homepage, sanitized real sample report, recorded demo, support matrix, reproducibility page, release notes | Three to five external pilot teams complete the workflow; observed failures become issues; claims match the released artifact |
| 5. Hosted value | Shared history, scheduled runs, collaboration and managed evaluation where users request them | Repeat use and support burden justify service operations; tenancy, privacy, cost and reliability gates pass |

For the first engineering change, scope a **result integrity** PR around R1/R5: execution-state model, status/selector validation, explicit incomplete policy outcome, and consistent CLI/JSON/HTML reporting. Pair it with regression cases for the reproduced failures. Follow with detector/benchmark validity; do not merely rename a false pass as “no findings” while leaving the checks invalid.

Track time to first valid result, failed install rate, execution completeness, reproducible finding rate, false positives on curated negatives, fix-and-rerun completion, and repeat use. Establish a baseline with pilots before inventing growth goals. A credible end-to-end workflow is the launch asset.

## Checks performed

| Area | Result |
| --- | --- |
| Core | Ruff and mypy passed; 73 pytest tests passed. Socket-dependent tests required a permitted rerun outside the initial restricted sandbox |
| Cloud | Ruff and mypy passed; 8 tests passed and 3 database-dependent tests skipped |
| Benchmark | Ruff and generated matrix check passed; 25 selected matrix/harness/fixture tests passed; full external/Docker benchmark not run |
| Marketing site | 5 tests passed; production build passed; local browser inspection completed |
| Documentation | Source check and production build passed; browser navigation and built-link inspection still found broken routes |
| Targeted review experiments | HTTP 401 false pass, limiter reset, benign SSTI match, engine selection, equivalent policy levels, partial execution pass, incomplete report lookup, token masking limitations, and MCP framing behavior examined |

Only this review and the accompanying product brief were added. No scanner behavior, sample runs, release state, or existing plan status was changed.
