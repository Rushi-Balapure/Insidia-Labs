# Phase 1A and 1D — Engine registry and overlap

> This is the capability registry. It ships with the CLI: Phase 1A owns the data and the selector, and Phase 1D owns the measured defaults once the benchmark has numbers. Engines are named everywhere: the report, the docs, the site, and SARIF. Registry data files live in `core/` and are versioned with the CLI, so a laptop and a Cloud worker select the same engine for a family.

Depends on: the normalizer (Phase 1A) and the benchmark mappings (Phase 1D).
Parent: [00-master-plan.md](00-master-plan.md). Gaps and modules: [16-coverage-gaps.md](16-coverage-gaps.md). Cloud tables: [14-database-schema.md](14-database-schema.md).

## Goal
No porting: the OSS engines stay as they are. The registry turns them and the Insidia modules into one measured system:
- Every attack family knows which engines and modules cover it, how well, and at what cost.
- Standard mode picks the best one per family using measurements, not guesses.
- Thorough mode runs all of them and merges results into cross-validated findings.
- Every finding names the engine or module that produced it.

## Exit
- Every attack family in the default profiles has a **measured** Standard-mode engine or module, chosen from benchmark precision, recall, and cost.
- Thorough mode finds strictly more confirmed issues than Standard on the benchmark suite, and the dashboard's cost and time estimates are within 25% of actuals.
- Cross-engine dedup merges duplicate findings with under 2% false merges on the labeled benchmark set.
- A finding from each engine names that engine in the CLI report and in the Cloud API.
- The Engines section of the admin console is live, and customer accounts cannot reach it (tested).
- Every Partial or Gap row in [16-coverage-gaps.md](16-coverage-gaps.md) scheduled for Phases 1A through 4 has a benchmark result.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)). The registry reads the same cells and owns none of them.

## Out of scope
Rewriting or forking engines. The registry may route away from an engine to another one, and engine code is used as shipped upstream.

## Capability registry
Phase 1A defines the registry for the engines and probes the first CLI release runs, together with the selector. Phase 1D extends it to every engine and module and fills in the measured values:
- `engines` holds each upstream engine **and** each Insidia Labs module (`engine_id = 'insidia.m_c3'`, for example), with its pinned image digest and license.
- `capability_map` holds, per (engine, attack family): priority, `module_label`, measured precision and recall, cost per attempt, and median runtime.
- `probe_upstream_map` maps every upstream probe we use to an Insidia probe id, and the finding keeps both names. An unmapped probe is flagged `unmapped` rather than dropped.
- The registry is edited only by migrations, proposed from the admin console, with every change audited. Changes take effect for new scans only, so a running scan never switches engines mid-way.

## Benchmark suite
- Targets and ground truth come from the scanner benchmark in `benchmark/` ([17-test-suite.md](17-test-suite.md)): OWASP Juice Shop, crAPI, VAmPI, Damn Vulnerable GraphQL Application, AgentDojo tasks, and our fixtures (vulnerable chatbot, RAG app, MCP agent, two-agent A2A system), each sandboxed with no egress and carrying a `ground_truth.yaml`. See [16-coverage-gaps.md](16-coverage-gaps.md#validating-this-analysis).
- For each (engine or module, attack family): recall, precision, cost per attempt, runtime, and false-positive causes.
- Runs weekly and on every engine version bump. A regression larger than 5 points in recall or precision blocks the version bump.
- Results are written to `capability_map` by a reviewed migration, not automatically, so a bad run cannot silently reroute production.

## Standard-mode selection
- Default: for each family, the engine or module with the highest recall among those with at least 90% precision; ties go to lower cost.
- Deterministic-oracle engines are preferred over judge-only ones at equal recall, because their findings are provable.
- Direct-mode scans skip entries that need a runner (`probes.requires_runner`) and fall back to the next entry, and the scan summary lists what was skipped.
- A scan with no model configured skips entries that need an attacker or judge (`probes.requires_attacker_model`) and lists those families, with a note that a local model or Insidia Cloud covers them. A configured model, including a user's own, is used.

## Thorough mode and dedup
- Thorough runs every entry for the family. The normalizer maps each result to an Insidia Labs probe id, normalizes the evidence (strip timestamps, nonces, and canary values; canonicalize JSON and whitespace), computes the blind index, and merges on `(org, target, attack_family, evidence_bidx)`.
- A finding confirmed by two or more independent engines or modules is marked **cross-validated** and gets a confidence boost. Two probes from the same engine do not count as independent.
- Merged findings keep every contributing result in `finding_sources` (internal) for audit and tuning.
- Tuning uses a labeled set of true duplicates and near-misses from the benchmark.

## Cost and time estimates
- Estimates come from `capability_map` cost and runtime multiplied by the profile's probe counts, the target's rate limit, and observed target latency from the Validate step.
- After each scan, actuals are compared with the estimate, and the per-family correction factor is updated.
- Thorough and Custom show the delta against Standard before launch ("about 3x attempts, about 40 minutes more").

## What stays hidden
Engine names are public. These stay private:
- Secrets and customer data. The redactor masks them, and a CI test fails if a planted secret or a real customer string appears in a report, an API response, a webhook, or the docs.
- Engine telemetry. A sniffing proxy fails the test if an engine calls home. User-Agent is `Insidia Labs` plus the engine name, so the target can see what scanned it.
- Engine crashes are shown with the engine name and our error code (`INS-SCAN-014`); raw stacks that include paths from the user's machine are redacted.

## Engines section of the admin console
The admin console ([20-admin-console.md](20-admin-console.md)) ships in Phase 2C and includes an Engines and modules section.
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
- Secret-redaction tests on every customer-facing surface, and the no-phone-home traffic test.
- Access test: a customer session, API key, or runner certificate cannot reach any admin console route.

## Risks
- **Benchmark overfitting.** Engines tuned to a public benchmark can look better than they are. Keep a private held-out set of fixtures that no one tunes against.
- **Thorough-mode cost.** Running everything multiplies model spend. The estimate is shown before launch and counts against the org budget.
- **A new output that forgets to mask secrets.** Every new customer-facing output is added to the secret-redaction test before it ships.
