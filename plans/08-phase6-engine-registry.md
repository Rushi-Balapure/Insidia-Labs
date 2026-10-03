# Phase 6 — Engine registry, overlap tuning, and Insidia Labs Engine presentation

Depends on: Phase 1 (capability registry v1, normalizer, dedup), Phase 3 (probe ids and taxonomy), Phase 4 (oracles, Insidia Labs modules M-A* and M-C*).
Parent: [00-master-plan.md](00-master-plan.md). Gaps and modules: [16-coverage-gaps.md](16-coverage-gaps.md). Tables: [14-database-schema.md](14-database-schema.md).

## Goal
No porting: the OSS engines stay as they are. This phase turns the engines and Insidia Labs-built modules into one measured, tunable system that customers see as a single **Insidia Labs Engine**:
- Every attack family knows which engines and modules cover it, how well, at what cost.
- Standard mode picks the best one per family using measurements, not guesses.
- Thorough mode runs all of them and merges results into cross-validated findings.
- No customer-facing surface can reveal an upstream engine.

## Exit
- Every attack family in the default profiles has a **measured** Standard-mode engine or module, chosen from benchmark precision, recall, and cost.
- Thorough mode finds strictly more confirmed issues than Standard on the benchmark suite, and the dashboard's cost and time estimates are within 25% of actuals.
- Cross-engine dedup merges duplicate findings with under 2% false merges on the labeled benchmark set.
- The denylist test is green on every customer-facing surface listed below.
- The Engines section of the admin console is live, and customer accounts cannot reach it (tested).
- Every Partial or Gap row in [16-coverage-gaps.md](16-coverage-gaps.md) scheduled for Phases 1 to 4 has a benchmark result.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)). Phase 6 reads the same cells; it does not own any.

## Out of scope
Rewriting or forking engines. Removing an engine is allowed (the registry routes to another), but replacing its code with ours is not a goal of this phase.

## Capability registry, full version
Phase 1 shipped a minimal registry. Phase 6 grows it to every engine and module:
- `engines` holds each upstream engine **and** each Insidia Labs module (`engine_id = 'insidia.m_c3'`, for example), with its pinned image digest and license.
- `capability_map` holds, per (engine, attack family): priority, `module_label`, measured precision and recall, cost per attempt, and median runtime.
- `probe_upstream_map` maps every upstream probe or plugin we use to an Insidia Labs probe id. An unmapped upstream probe cannot run; the normalizer rejects its output.
- The registry is edited only by migrations, proposed from the admin console, with every change audited. Changes take effect for new scans only, so a running scan never switches engines mid-way.

## Benchmark suite
- Targets and ground truth are the shared Phase T permutation suite ([17-test-suite.md](17-test-suite.md)), not a separate set: OWASP Juice Shop, crAPI, VAmPI, Damn Vulnerable GraphQL Application, AgentDojo tasks, and our fixtures (vulnerable chatbot, RAG app, MCP agent, two-agent A2A system), each sandboxed with no egress and carrying a `ground_truth.yaml`. See [16-coverage-gaps.md](16-coverage-gaps.md#validating-this-analysis).
- For each (engine or module, attack family): recall, precision, cost per attempt, runtime, and false-positive causes.
- Runs weekly and on every engine version bump. A regression larger than 5 points in recall or precision blocks the version bump.
- Results are written to `capability_map` by a reviewed migration, not automatically, so a bad run cannot silently reroute production.

## Standard-mode selection
- Default: for each family, the engine or module with the highest recall among those with at least 90% precision; ties go to lower cost.
- Deterministic-oracle engines are preferred over judge-only ones at equal recall, because their findings are provable.
- Direct-mode scans skip entries that need a runner (`probes.requires_runner`) and fall back to the next entry, and the scan summary lists what was skipped.
- Trial scans skip entries that need our attacker or judge model (`probes.requires_attacker_model`); there is no fallback, because the point of trial is model-free basic scanning. The summary lists the families held back and notes that upgrading unlocks them.

## Thorough mode and dedup
- Thorough runs every entry for the family. The normalizer maps each result to an Insidia Labs probe id, normalizes the evidence (strip timestamps, nonces, and canary values; canonicalize JSON and whitespace), computes the blind index, and merges on `(org, target, attack_family, evidence_bidx)`.
- A finding confirmed by two or more independent engines or modules is marked **cross-validated** and gets a confidence boost. Two probes from the same engine do not count as independent.
- Merged findings keep every contributing result in `finding_sources` (internal) for audit and tuning.
- Tuning uses a labeled set of true duplicates and near-misses from the benchmark.

## Cost and time estimates
- Estimates come from `capability_map` cost and runtime multiplied by the profile's probe counts, the target's rate limit, and observed target latency from the Validate step.
- After each scan, actuals are compared with the estimate, and the per-family correction factor is updated.
- Thorough and Custom show the delta against Standard before launch ("about 3x attempts, about 40 minutes more").

## Masking hardening (Insidia Labs Engine presentation)
The denylist of upstream names (engine names, package names, probe names, plugin ids, known distinctive error strings) is checked in CI on every customer-facing surface:
- API responses (contract tests on every route)
- Rendered reports (PDF, HTML), SARIF (`tool.driver.name` is "Insidia Labs Engine"), JSON exports, evidence packs
- The built dashboard bundle and source maps (source maps are not shipped to production)
- Emails, webhooks, Slack and Jira payloads
- The customer docs site ([15-customer-docs.md](15-customer-docs.md))
- Captured outbound traffic from each engine against a fixture: User-Agent and scanner headers are rewritten to `Insidia LabsLabs`, and a sniffing proxy fails the test on any header or path that names an engine

Also:
- Engine errors are logged internally and exposed only as Insidia Labs error codes (`INS-SCAN-014`).
- Upstream payload text that names its own tool (some probes include the tool's name in the prompt) is rewritten or dropped by the normalizer.
- The customer "how it works" diagram shows a single Insidia Labs Engine box, and module labels are numbered or named by capability ("Jailbreak module"), never by source.

## Engines section of the admin console
The admin console ([20-admin-console.md](20-admin-console.md)) ships in Phase 2; this phase adds its Engines and modules section.
- Shows real engine names, per-engine benchmark results, production precision from customer triage (aggregated, never raw evidence), error rates, and version pins.
- Lets staff propose registry changes, which go out as reviewed migrations.
- Uses the admin console's access model: separate internal hostname, staff SSO with authenticator-app MFA, the `app_admin_read` and `app_admin_write` roles. Evidence is visible only through an active, customer-approved `staff_access_grants` row.

## Insidia Labs modules in the registry
The gap-filling modules from [16-coverage-gaps.md](16-coverage-gaps.md) register exactly like engines. They are benchmarked the same way and compete for Standard-mode priority on merit. Where a module beats an engine on a family, it becomes the Standard choice and the engine stays available in Thorough.

## Tests
- Registry schema test: every probe in a default profile has at least one enabled capability entry; every upstream probe we run has a mapping.
- Selection test: given a fixture registry, Standard picks the expected entry, and direct mode skips runner-only entries with the skip reported.
- Dedup test on the labeled duplicate set (merge rate and false merges).
- Estimate accuracy test on recorded benchmark runs.
- Denylist tests on every surface above, including captured traffic.
- Access test: a customer session, API key, or runner certificate cannot reach any admin console route.

## Risks
- **Benchmark overfitting.** Engines tuned to a public benchmark can look better than they are. Keep a private held-out set of fixtures that no one tunes against.
- **Thorough-mode cost.** Running everything multiplies model spend. The estimate is shown before launch and counts against the org budget.
- **Masking gaps in new surfaces.** Every new customer-facing output must be added to the denylist test before it ships; the pull request template asks.
