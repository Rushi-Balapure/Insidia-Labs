# Insidia product brief

Decision draft, 10 October 2026. Based on the current repository and [engineering/product review](/home/rushi/Desktop/Rushi/Insidia-Labs/Insidia-Labs/plans/2026-10-10-product-review.md). This is a product direction and prioritization brief, not an implementation specification.

## Product and user

**Insidia is a local security workflow and reproducible benchmark spanning AI security and application security, built on credited open-source engines and focused Insidia checks.**

The first users are engineers building AI-enabled applications and the AppSec engineers responsible for evaluating those applications. Their target includes the model/agent layer and the APIs, tools, repositories, dependencies, and permissions around it. Preserve that combined scope while publishing exactly which checks are ready.

Working problem hypothesis: these users spend time configuring separate tools, reconciling incompatible outputs, deciding whether a scan actually completed, reproducing findings, and checking whether a fix worked. The repository supports this as a plausible product problem; customer frequency, time cost, and willingness to pay have not been measured. Validate those with pilot users.

## Promise and differentiation

Suggested headline: **One security report for your AI app and the application around it.**

The differentiator must be a dependable workflow: scope once, select explicit capabilities, run engines with visible execution status, preserve attributable evidence, and retest a fix. Insidia's benchmark should independently measure the released tool, including false positives and incomplete execution.

Engine aggregation alone is easy to reproduce. Harder-to-copy value can accumulate in adapter reliability, independently maintained test cases, high-quality normalization, reproducibility, and useful links between AI behavior and application impact. These are investments to make, not advantages already proven.

## Ideal experience

A user installs a supported release, runs a documented local example, connects their own app, and gets an understandable report. Every finding identifies the engine, affected asset, observed evidence, and an actionable fix. Every untested or failed check is visible. A subsequent run establishes what changed against comparable configuration and versions. Teams can eventually share history and schedule the same trusted workflow.

## Minimum product that proves the thesis

- One well-supported install route and an explicit OS/engine support matrix.
- A substantive AI-engine profile and a substantive AppSec-engine profile, both exercised through the released CLI.
- Independent vulnerable and patched targets demonstrating detection and negative controls.
- A truthful execution model that separates findings from incomplete/error/unsupported checks.
- A versioned run manifest, redacted evidence, useful HTML/JSON/SARIF, and reproducible retesting.
- A complete human quickstart, verified agent/MCP path, public sanitized sample report, and a real short recording.

This is deliberately a smaller verified implementation of the unified vision. Broader families can be added as they meet the same gates.

## What to defer

Defer hosted GPU/model operations, a large dashboard, generalized autonomous exploitation, enterprise features, and extra presentation animations until result integrity and repeat use are demonstrated. Do not label fixture checks as comprehensive security assurance. Do not promise every upstream engine feature simply because its binary is installed.

The free CLI should complete the useful scan → evidence → fix → retest loop. A future paid service can sell managed execution, history, scheduling, collaboration, and dependable model evaluation where pilot users demonstrate demand.

## Validation and success

Recruit three to five pilot teams with permissioned AI-enabled test applications. Observe installation, configuration, the first valid run, finding interpretation, and fix/retest. Record failures without founder intervention hiding friction.

Proposed beta gates:

- Every advertised capability has an end-to-end case using the released artifact and a matched negative control.
- Known execution failures never become unconditional policy passes.
- Users can reproduce a finding from stored, redacted evidence and identify what was not tested.
- At least three pilot teams complete a valid scan and a comparable rerun; investigate why others cannot.
- Documentation and demo commands work from a clean supported environment.

Track first-result time, completion rate, reproducible findings, curated false positives, fix/retest completion, and return use. Establish measured baselines before publishing numerical quality or adoption claims. Growth, retention, and revenue are currently unknown.

## Risks and decision

The immediate risks are false assurance, fixture-overfit benchmark results, loss of decisive evidence, uneven engine support, and presentation claims ahead of verified behavior. These are addressable but central to the product, not peripheral cleanup.

**Go:** continue toward the combined AI + AppSec product and run a focused reliability/productization milestone.

**No-go yet:** present the current pass/fail output as a comprehensive authoritative benchmark, make it a security release gate, or prioritize paid hosted infrastructure over correctness.

Next step: insert a Phase 1F before the planned Cloud model service. Start with result integrity, then independently verified engine coverage, then onboarding/report polish and a public beta. The detailed review contains findings, acceptance criteria, and presentation drafts.
