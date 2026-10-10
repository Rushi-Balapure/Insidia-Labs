# Implementation review — Phase 1F first changes

Reviewed 10 October 2026. **The direction is right, but the result/adapter boundary needs finishing before these packages can be considered complete.** Keep the new result model and staged report writes. Correct the regressions below before expanding into more engines or presentation work.

## Scope and verification

Reviewed `057cc03..f62b391`, covering:

- `01d7eda` — `fix(scan): keep incomplete runs and bad targets from passing`
- `f62b391` — `fix(findings): keep each location and name every engine that reported it`

The second commit arrived during review and is included here. Tests were run against isolated snapshots to avoid mixing files being edited concurrently. Later commits are outside this review. Existing sample runs were not modified.

| Verification | Result |
| --- | --- |
| Core suite at `01d7eda` | 89 passed |
| Core suite at `f62b391` | 92 passed |
| Ruff and mypy at both snapshots | Passed; 26 source files checked by mypy |
| Installed Nuclei against a synthetic localhost page | Exit 0; one request reached the target; output file existed with zero bytes |
| Targeted probes | Reproduced budget isolation, partial-result loss, error suppression, missing locations, wrong config digest, invalid-schema acceptance, uncaught timeout, and redaction gaps |

Initial tests in the restricted sandbox encountered socket-permission errors and concurrent edits; those results were discarded in favor of the stable snapshot runs above. This was not a full external-engine benchmark or a deployed website review.

## What to keep

- Execution status, policy verdict, and exit code are now separated. Incomplete plus failed policy correctly exits 2 when the aggregator receives the right records.
- HTTP 401 and selector failures no longer automatically become clean negative results; config typos receive useful errors.
- Hidden staging directories and a final rename improve artifact publication. Missing HTML is no longer reported as successfully available.
- Evidence excerpts now look around the match, and the second commit removes automatic cross-validation/confidence promotion. Explicit observations and locations are the correct model direction.

The plan still says these packages are started rather than complete. That is appropriate. Items below distinguish introduced regressions from remaining gaps in the packages being implemented; they are not a demand to finish F07–F22 in this change.

## Required changes

### C01 — P1: handle valid empty reports using each engine's completion contract

**Type:** introduced regression. **Packages:** F02/F09.

**Location:** [upstream.py:349](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:349).

`_web_bodies` rejects every empty report before it considers the engine. Nuclei emits no JSONL finding records when a completed scan finds nothing. I ran the installed binary with Insidia's generated template against a clean local page: exit 0, one request received, zero-byte report. Insidia then raised `EngineFailed("engine report is empty")`. A valid clean scan therefore becomes incomplete.

**Change:** retain process completion/exit metadata and apply per-engine format rules. Accept a zero-record Nuclei report only when successful execution and valid template/target execution are established. Do not globally treat empty files as success; missing reports, interrupted execution, or engines requiring a structured summary still need errors.

**Regression:** test the actual clean Nuclei path and a finding path, plus an interrupted run that leaves an empty file. The first must complete without findings; the interrupted case must remain incomplete.

### C02 — P1: pass the shared budget into relay request threads

**Type:** incomplete implementation of the new limiter. **Package:** F03.

**Locations:** [transport.py:54](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:54), [transport.py:264](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:264), [relay handler](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:198).

`bind_budget` stores the table in a `ContextVar` in the scan thread. The relay uses `ThreadingHTTPServer`; its request threads do not inherit that binding in the tested runtime. `_slot` therefore constructs a new limiter and semaphore per request. A probe comparing the parent and worker slots found both objects different. The main-thread HTTP path improves, but relay RPS/concurrency limits remain unenforced.

**Change:** pass an explicit execution context/budget through the relay closure into each exchange, or deliberately bind the shared table in every worker. Do not silently allocate a new budget during an active scan when the expected context is absent. WebSocket and native-engine paths also need their own coverage before F03 is complete.

**Regression:** make concurrent requests through the real relay, recording start times and active request counts at a local target. Assert aggregate RPS and peak concurrency. The new unit test of one standalone `RateLimiter` does not exercise this boundary.

### C03 — P1: return findings and execution errors together from adapters

**Type:** existing failure paths not fixed by the new aggregation layer. **Packages:** F01/F02.

**Locations:** [scan.py:164](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:164), [built-in loop](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:105), [relay return path](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:228).

Adapters still return `list[ProbeHit]` or throw an exception. Two reproduced cases contradict the new result contract:

1. The first built-in leakage probe finds a controlled canary; the second raises `ProbeError`. The local hit list is discarded, producing zero findings and an inconclusive policy instead of a failed policy with incomplete execution.
2. A relay captures a finding, then its engine raises `EngineFailed`. `_relay` returns hits before checking the failure. The scan reports execution complete, exit 1, and no skip/error, despite the engine failure.

**Change:** introduce an adapter result containing observations, completion state, and diagnostics. Preserve earlier hits when later work fails. Carry relay delivery failures and engine completion separately; an empty `pairs` list alone cannot establish successful target testing. Aggregate only after consuming both parts.

**Regression:** test both cases above through `execute`, expecting the finding to remain, execution incomplete, policy fail, and exit 2. Also test a clean response followed by failure. The current test covers different engines, not partial failure within one engine.

### C04 — P1: wire location and native rule metadata through the actual parser pipeline

**Type:** the new finding fields are not yet connected to producers. **Package:** F06.

**Locations:** [repository parser](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:338), [probe conversion](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/probes.py:79), [normalizer](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/findings.py:70).

`ProbeHit.location` is added, but `EngineHit` does not carry it, repository readers reduce results to rule strings, and `run()` never populates the field. Through the real gitleaks adapter/parser/converter, two synthetic findings with the same rule in `a.py:1` and `b.py:2` became two empty locations and then one normalized finding. The new tests pass because they manually construct populated `ProbeHit` objects.

**Change:** preserve native rule ID, file/URL, line/range, severity/confidence, and evidence in the engine observation. Transfer them through `EngineHit` → `ProbeHit` → `Finding`/SARIF. Do not hardcode `control.severity` and `high` confidence for every native observation. Keep per-observation evidence when merging; the current `Observation` keeps only engine/probe/severity/location.

**Regression:** feed a realistic native report with two locations through the full adapter, normalize it, and export it. Require two findings and two correct SARIF locations. Add distinct severities/evidence to ensure they survive conversion too.

### C05 — P1: fingerprint the configuration actually loaded for the run

**Type:** introduced rerun-integrity bug. **Packages:** F05/F06.

**Locations:** [scan.py:223](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:223), [rerun validation](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/cli.py:189).

The digest is computed from `project.path.read_bytes()` after scanning. If the user edits the file during a long scan, the loaded `Project` still targets the old configuration but the manifest records the new file's hash. I reproduced a scan using the original URL while its manifest matched a modified URL configuration. Rerun's equality check will accept that modified file without detecting that it differs from the configuration actually used.

**Change:** compute a canonical, non-secret effective configuration identity at load/start time, including command-line overrides, and carry it with the run. Never reread a mutable config file as evidence of what executed. Exclude resolved secret values; record safe references. Retain explicit config-path context so a report from a custom config can show a working rerun command.

**Regression:** modify the file during a fake slow exchange and assert the manifest retains the original effective identity; rerun must detect the difference. Include a config outside the current directory and a non-default filename.

### C06 — P1: validate engine report structure, not only JSON syntax

**Type:** incomplete F02 report validation.

**Locations:** [upstream.py:451](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:451), [repository dispatch](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/upstream.py:338).

Malformed JSON now raises an error, which is useful. Valid JSON with the wrong schema still becomes a clean result: a Trivy report containing only `{"error":"synthetic engine failure"}` returned zero findings. Reader functions commonly return `[]` when required fields/types are missing, and a nonzero process exit can still be accepted if a report file exists.

**Change:** define versioned per-engine schemas and exit-code contracts. Reject unexpected top-level shape, explicit native error states, and malformed required records; allow legitimate no-finding formats for that engine. Preserve validated partial findings plus the error through C03's result type.

**Regression:** cover a valid clean report, wrong-shape JSON, native error object, partially valid records, and each supported engine's documented finding/fatal exit codes. Assert malformed execution cannot produce exit 0.

### C07 — P1: normalize expected transport failures and preserve partial runs

**Type:** error handling remains incomplete. **Packages:** F01–F03.

**Locations:** [transport.py:184](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:184), [exception handling](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/transport.py:190), [scan error boundary](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:166).

The timeout conversion catches only `URLError` wrapping a timeout. A timeout while reading the response body can be a direct `TimeoutError`; a mocked body read reproduced it escaping unchanged. Scan catches only `EngineFailed` and `ProbeError`, so this path can abort before writing the accumulated run. Cancellation is represented in aggregation tests but is not wired into actual execution/finalization.

**Change:** normalize specific expected transport exceptions at the transport boundary; do not catch arbitrary programming errors as clean results. Add a run lifecycle that finalizes known partial observations on expected failure/cancellation, while still refusing unsafe scope operations. Connect cancellation to child-process cleanup and exit 130.

**Regression:** a target sends headers then stalls its body after an earlier successful finding; assert bounded termination, an incomplete report, and retained evidence. Add cancellation after a recorded result and verify owned child processes stop.

### C08 — P1: centralize redaction before persisting or displaying errors

**Type:** F04 remains partial; adding regexes alone does not meet its contract.

**Locations:** [mask.py:12](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/mask.py:12), [scan.py:166](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/scan.py:166).

The added OpenAI pattern does not mask a bare synthetic `sk-proj-` token because the pattern permits only alphanumerics after `sk-`. More importantly, engine exception text bypasses `mask()` entirely: a synthetic bearer value survived unchanged in `benchmark.json` and progress events. This was tested without real credentials.

**Change:** redact exact configured secret values and supported patterns at all persistence/display boundaries, including diagnostics, skips, progress, JSON/MCP responses and engine stderr. Add safe bounded evidence handling: `_around` currently returns an arbitrarily large span when the matched evidence itself is large. Use restrictive storage permissions and document the remaining limits.

**Regression:** inject synthetic credentials into an engine error and a target response; inspect all artifacts and captured output. Include project-style keys, configured arbitrary values, terminal escapes, and a very long evidence span. No raw values should escape.

### C09 — P2: do not replace a weak SSTI detector with an exact-body-only detector

**Type:** introduced false-negative behavior; broader detection still unverified. **Package:** F08.

**Location:** [adapters.py:132](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/core/insidia/adapters.py:132).

The price-49 regression is fixed by requiring the entire trimmed response to equal the product/substituted attack. That now misses rendered output such as `<html><p>49</p></html>`, while a target that always returns `49` still triggers. The existing positive test was changed to emit exactly the shape accepted by the new detector, so it does not protect ordinary HTML rendering. The external SSTI path still uses the older standalone-number rule.

**Change:** use a baseline plus paired randomized expressions and compare causal changes in the relevant response region. Preserve match context. Apply equivalent evidence requirements to the built-in and external observations, or mark the current implementation fixture-only until replaced.

**Regression:** rendered HTML with a genuine evaluation must detect; fixed `49`, price text, reflected input, and error pages must not. Test through the HTTP adapter, not just the oracle function.

### C10 — P2: make the documentation agree with the newly disabled profiles

**Type:** user-visible contradiction introduced with L2/L3 rejection. **Packages:** F00/F07/F16.

**Locations:** [README.md:96](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/README.md:96), [README.md:103](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/README.md:103), [homepage profile cards](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/site/src/pages/index.astro:149).

`execute()` now rejects L2/L3, but the README still demonstrates `--policy L2` and describes both as running the same baseline. The updated website similarly says controls are recorded as L2/L3. A user following the showcased command gets an immediate error.

**Change:** use L1 in runnable examples and describe L2/L3 as unavailable/planned. Make `policy list/show/validate` distinguish availability from a defined policy name. Audit docs, agent instructions, FAQs and scripted demos for the same promise.

**Regression:** execute published CLI examples against the documented demo, and assert unsupported profile descriptions match the actual exit behavior.

## Finish these contracts before closing F00–F06

These are remaining implementation work, not reasons to discard the approach:

- **Persist the execution records.** `CheckRecord` instances are reduced to family rows and discarded. Incomplete reasons are absent from HTML, and one passed mapped control can hide another inconclusive one in the unchanged framework aggregation. Store per-target/per-engine states and reasons, and render them consistently in HTML/JSON/SARIF. Test two targets where one fails execution.
- **Validate manifests when reading.** Hashes are written but not checked by `report`/`rerun`; schema and artifact completeness are not validated. A malformed manifest JSON raises an uncaught parsing error. Validate supported schemas, required files/digests and run-path containment; annotate legacy runs without modifying them. Add write-interruption and corrupt-read tests.
- **Keep F06's limits explicit.** Observations currently omit native rule lineage, per-observation evidence and reproduction details; manifests still lack actual CLI/engine/corpus versions and target revision. `rerun` is not yet a fully reproducible run. Record unknowns and changed versions instead of implying equivalence.
- **Treat the inventory as an inventory.** `readiness.py` is a useful start, but it does not drive selection and labels families generically. Finish F07 before treating the support table as enforcement. Provider/transport/platform claims need their own rows and evidence.
- **Reduce coupling while finishing the result boundary.** Use constrained state/verdict types and a validated adapter-result object. Extract engine-attempt execution and run finalization from the growing `_run_targets`; avoid adding more parallel lists or positional arguments to it.

## Suggested next correction sequence

1. Finish adapter result propagation and expected-failure handling: C03/C06/C07. Make observations plus errors representable end to end.
2. Repair the proven clean-Nuclei regression and relay budget sharing: C01/C02.
3. Wire actual native locations/evidence into the new observation model: C04.
4. Capture configuration identity before execution and validate stored runs: C05 plus manifest reading.
5. Close redaction paths, replace the SSTI shortcut, and align public profile examples: C08/C09/C10.

Keep the current 92-test suite, but add these boundary/integration cases. The passing suite is a useful baseline; it does not yet exercise the failures reproduced here. Do not mark F01–F06 complete until their respective acceptance cases pass.

Only this review file was added by the reviewer. Application code, implementation commits, plans, and sample runs were left unchanged.
