# White box — static in Phase 1B, depth in Phase 3

> **v6.** gitleaks, osv-scanner, Trivy, Bandit, and gosec run locally in the free CLI (Phase 1B) against the working tree. Nothing is uploaded. Secret findings store a location and a fingerprint, never the value. The AI-BOM, the in-process SDK, and the planner that turns extracted prompts and tools into extra probes are Phase 3. Uploading an extract to Insidia Cloud is optional and paid only when a Cloud scan uses it.

Depends on: Phase 1A for the local scanners. The planner hook depends on Phase 2B and Phase 3.
Parent: [00-master-plan.md](00-master-plan.md). Coverage spec layer 9.

## Goal
Point Insidia at a repository and get static findings, plus, in Phase 3, dynamic tests generated from what the code actually does. The CLI keeps the repo on the machine. Cloud receives artifacts only when the user uploads them, and never receives secret values.

## Exit
- `insidia-runner extract --path ./app` against a fixture repo produces: prompt templates, tool schemas, an agent/tool graph, dependency manifests, and secret locations without values.
- Cloud rules flag a planted sink (LLM output passed into SQL or HTML) and a planted hardcoded key location.
- osv-scanner results and a CycloneDX AI-BOM (components: model clients, vector DB, agent framework) download from the scan.
- The Phase 6 planner accepts that context and adds at least one targeted probe that the black-box profile did not include (asserted in a test).
- SDK handler in Python completes an in-process relay loop for a fixture function. JS handler is the same protocol if time allows; Python is the exit.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)).

## Runner `extract`
- Walk the tree with a denylist (`.git`, `.env`, secrets files, `node_modules`, `venv`, build output).
- tree-sitter queries for Python and TypeScript first: OpenAI/Anthropic client calls, prompt string assignments, tool JSON schemas, `exec`/`subprocess`/`cursor.execute`/`dangerouslySetInnerHTML` near those calls.
- Secrets: run gitleaks locally or a small pattern set. Upload `{path, line, rule_id}` only. The line content is not uploaded. Test with a known AWS-shaped dummy key.
- Manifests uploaded as files: lockfiles, `requirements.txt`, `go.mod`, `package-lock.json`. These are not full source.
- Output is a signed (runner key) JSON bundle plus blobs, size-capped (for example 25 MB). Over cap: refuse and tell the user to narrow the path.

## Cloud analysis (queue `static`)
- Rules on the extracted graph, not on a second copy of the source: sink edges, tools with no auth parameter, prompts that concatenate user input with no delimiter.
- osv-scanner on the manifests in a worker image.
- ModelScan only if the customer points at a model file path and the runner uploads the file explicitly. Do not upload weights by default.
- CycloneDX 1.6 (or current) AI-BOM from the graph: libraries, declared models, tools, MCP servers from Phase 7 discover output if present.

## SDK (`shared/sdk/python`)
In-process, Lakera-style, for apps that are not a plain HTTP chat:
```python
async def handler(messages) -> str:
    return app.invoke(messages)

# test harness calls Insidia Labs cloud, which calls handler through the runner's local SDK bridge
```
The SDK bridge is a localhost port on the customer machine opened by the runner. The cloud still talks only to the runner. The SDK does not embed attack content.

OpenTelemetry GenAI spans (model name, tool name, token counts; not full prompts unless the customer opts in) travel through the runner to the scan's object prefix. Tool spans feed the `tool_trace` oracle.

## Gap-filling Insidia Labs modules in this phase
From [16-coverage-gaps.md](16-coverage-gaps.md):
- **M-A12 white-box AI analysis:** prompt and tool-graph analysis, over-privileged tools, embedding and vector-store exposure (closes spec 3.2 embedding inversion).
- **M-C9 Insidia Labs SAST, remaining languages:** Go, Java, C#, PHP, and Ruby taint rules on top of the Phase 4B engine, plus AI-specific sinks. Legal decides before this phase whether opengrep (LGPL-2.1, unmodified, separate process) may be used as the matching engine.
- **M-C10 secret liveness verifier:** opt-in, read-only provider checks that report live or dead for a leaked key, storing only the flag and fingerprint.
- **Adopt OpenSSF model-signing** for model signature and provenance checks (M-A13 static half).

## Storage
Extracted bundles are C2: encrypted with the org data key before upload to object storage, secret-redacted, and deleted on the org's retention schedule. Secret findings store `{path, line, rule_id, fingerprint}`, never the value (see [14-database-schema.md](14-database-schema.md#secrets-found-in-evidence)).

## Planner hook
`read_context()` from Phase 5 and the Phase 4 gray-box planner gain a `whitebox` block: tools, sinks, prompts. A rule adds probes such as "call tool `search_orders` with a quote in the id argument" when that tool exists. Test uses the fixture repo and expects that probe id in the plan.

## Tests
- Extract fixture: secret value absent from the bundle; sink edge present.
- Cross-org bundle key unreadable.
- Size-cap refusal.
- SDK round-trip: cloud attempt reaches the in-process function and the response returns.
- Planner snapshot includes the extra probe.

## Risks
- tree-sitter queries will false-positive. Severity for static findings starts at medium unless a second signal (dynamic oracle) confirms.
- Customers will try to upload monorepos. The cap and denylist are the mitigation; do not stream the whole disk.
