# Phase 8 — White box

Depends on: Phase 4 artifact upload limits, Phase 5/6 planners that can consume extra context, Phase 7 discovery patterns.
Parent: [00-master-plan.md](00-master-plan.md). Coverage spec layer 9.

## Goal
Point the runner at a repository and get static findings plus dynamic tests generated from what the code actually does (prompts, tools, sinks). The cloud receives artifacts, not a full copy of the repo, and never receives secret values.

## Exit
- `insidia-runner extract --path ./app` against a fixture repo produces: prompt templates, tool schemas, an agent/tool graph, dependency manifests, and secret locations without values.
- Cloud rules flag a planted sink (LLM output passed into SQL or HTML) and a planted hardcoded key location.
- osv-scanner results and a CycloneDX AI-BOM (components: model clients, vector DB, agent framework) download from the scan.
- The Phase 6 planner accepts that context and adds at least one targeted probe that the black-box profile did not include (asserted in a test).
- SDK handler in Python completes an in-process relay loop for a fixture function. JS handler is the same protocol if time allows; Python is the exit.

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

# test harness calls Insidia cloud, which calls handler through the runner's local SDK bridge
```
The SDK bridge is a localhost port on the customer machine opened by the runner. The cloud still talks only to the runner. The SDK does not embed attack content.

OpenTelemetry GenAI spans (model name, tool name, token counts; not full prompts unless the customer opts in) travel through the runner to the scan's object prefix. Tool spans feed the `tool_trace` oracle.

## Planner hook
`read_context()` from Phase 5 and the Phase 6 planner gain a `whitebox` block: tools, sinks, prompts. A rule adds probes such as "call tool `search_orders` with a quote in the id argument" when that tool exists. Test uses the fixture repo and expects that probe id in the plan.

## Tests
- Extract fixture: secret value absent from the bundle; sink edge present.
- Cross-org bundle key unreadable.
- Size-cap refusal.
- SDK round-trip: cloud attempt reaches the in-process function and the response returns.
- Planner snapshot includes the extra probe.

## Risks
- tree-sitter queries will false-positive. Severity for static findings starts at medium unless a second signal (dynamic oracle) confirms.
- Customers will try to upload monorepos. The cap and denylist are the mitigation; do not stream the whole disk.
