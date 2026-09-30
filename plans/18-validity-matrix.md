# Validity Matrix (expanded)

Companion to [17-test-suite.md](17-test-suite.md). This file is the human-readable version of `tests/matrix/validity.py`: the exact dimension tokens, the real validity function, and the matrix rendered as projection tables so the valid vs N/A cells are easy to read. The generator (`tests/matrix/cells.yaml`) is the machine source of truth; this doc must match it.

## Dimensions and exact tokens

### Connectors (17)
Grouped for readability. The six chat transports share the same validity, so tables collapse them to `chat*`.
```
CHAT   = chat_http, chat_openai, chat_anthropic, chat_bedrock, chat_azure, chat_ws
AI_APP = CHAT + rag, agent, multi_agent, sdk_inproc
AGENTIC = agent, multi_agent
API    = api_rest, api_graphql, api_grpc, api_ws
WEB_API = web + API
pseudo = ml_model (predictive model endpoint), codebase (source for white box)
```

### Box modes (3)
`black`, `gray`, `white`.

### Connection modes (4)
`direct` (sandboxed public, no install), `relay` (runner, prompt at a time), `tunnel` (runner, raw HTTP), `sdk_bridge` (in-process handler).
White-box source is provided by runner `extract` (relay/tunnel/sdk) or `upload` (direct), so code access is available in every connection mode; it is a capability, not a fifth connection mode.

### Attack types (44)
AI (24), from [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md) sections 3.1-3.11:
```
ai.prompt_injection_direct     ai.prompt_injection_indirect   ai.jailbreak
ai.hidden_context_extraction   ai.data_leakage                ai.cross_tenant_bleed
ai.embedding_inversion         ai.tool_misuse                 ai.dangerous_tool_args
ai.tool_chain_hijack           ai.privilege_identity_abuse    ai.code_exec_sandbox_escape
ai.rag_poisoning               ai.memory_poisoning            ai.citation_groundedness
ai.output_handling_sinks       ai.secondary_injection         ai.supply_chain
ai.unbounded_consumption       ai.harmful_content_policy       ai.bias
ai.multi_agent_spoof           ai.cascade_rogue               ai.predictive_ml
```
Classic (20):
```
web.xss            web.sqli           web.cmdi           web.ssti
web.path_lfi       web.ssrf           web.deserialization web.xxe
api.bola_idor      api.bfla           api.mass_assignment auth.jwt_oauth_session
logic.race         web.smuggling_cache web.client_side    code.sast_sinks
code.secrets       deps.sca           infra.cve          infra.tls
```

## The validity function
```python
# tests/matrix/validity.py
CHAT = {"chat_http", "chat_openai", "chat_anthropic", "chat_bedrock", "chat_azure", "chat_ws"}
AGENTIC = {"agent", "multi_agent"}
AI_APP = CHAT | {"rag", "agent", "multi_agent", "sdk_inproc"}
API = {"api_rest", "api_graphql", "api_grpc", "api_ws"}
WEB_API = {"web"} | API

# 1. Which connectors an attack type can apply to.
ATTACK_CONNECTORS = {
    "ai.prompt_injection_direct":   AI_APP,
    "ai.prompt_injection_indirect": {"rag", "agent", "multi_agent"},
    "ai.jailbreak":                 AI_APP,
    "ai.hidden_context_extraction": AI_APP,
    "ai.data_leakage":              AI_APP,
    "ai.cross_tenant_bleed":        {"rag", "agent", "multi_agent"},
    "ai.embedding_inversion":       {"rag"},
    "ai.tool_misuse":               AGENTIC,
    "ai.dangerous_tool_args":       AGENTIC,
    "ai.tool_chain_hijack":         AGENTIC,
    "ai.privilege_identity_abuse":  AGENTIC,
    "ai.code_exec_sandbox_escape":  AGENTIC,
    "ai.rag_poisoning":             {"rag"},
    "ai.memory_poisoning":          {"rag", "agent", "multi_agent"},
    "ai.citation_groundedness":     {"rag"},
    "ai.output_handling_sinks":     AI_APP,
    "ai.secondary_injection":       AGENTIC,
    "ai.supply_chain":              {"rag", "agent", "multi_agent", "ml_model"},
    "ai.unbounded_consumption":     AI_APP,
    "ai.harmful_content_policy":    AI_APP,
    "ai.bias":                      AI_APP,
    "ai.multi_agent_spoof":         {"multi_agent"},
    "ai.cascade_rogue":             {"multi_agent"},
    "ai.predictive_ml":             {"ml_model"},
    "web.xss":                      {"web"},
    "web.sqli":                     {"web", "api_rest", "api_graphql"},
    "web.cmdi":                     {"web", "api_rest", "api_graphql"},
    "web.ssti":                     {"web", "api_rest", "api_graphql"},
    "web.path_lfi":                 {"web", "api_rest"},
    "web.ssrf":                     {"web", "api_rest", "api_graphql"},
    "web.deserialization":          {"web", "api_rest"},
    "web.xxe":                      {"web", "api_rest"},
    "api.bola_idor":                {"web", "api_rest", "api_graphql", "api_grpc"},
    "api.bfla":                     {"web", "api_rest", "api_graphql", "api_grpc"},
    "api.mass_assignment":          {"api_rest", "api_graphql"},
    "auth.jwt_oauth_session":       WEB_API,
    "logic.race":                   {"web", "api_rest", "api_graphql"},
    "web.smuggling_cache":          {"web"},
    "web.client_side":              {"web"},
    "code.sast_sinks":              {"codebase"},
    "code.secrets":                 {"codebase"},
    "deps.sca":                     {"codebase"},
    "infra.cve":                    WEB_API,
    "infra.tls":                    WEB_API,
}

# 2. Which box modes an attack type supports (default: all three).
BOX_OVERRIDE = {
    "code.sast_sinks": {"white"}, "code.secrets": {"white"}, "deps.sca": {"white"},
    "ai.embedding_inversion": {"gray", "white"},
    "ai.supply_chain": {"gray", "white"},
    "ai.predictive_ml": {"black", "white"},
}

# 3. Which connectors a connection mode can reach at runtime.
CONN_REACH = {
    "direct":     AI_APP - {"sdk_inproc"} | WEB_API | {"ml_model", "codebase"},
    "relay":      CHAT | {"rag", "agent", "multi_agent", "codebase"},
    "tunnel":     WEB_API | {"ml_model", "codebase"},
    "sdk_bridge": AI_APP | {"codebase"},
}
# codebase is reachable everywhere (upload in direct, extract via the runner/SDK otherwise).

def is_valid(connector, box, attack, conn):
    if connector not in ATTACK_CONNECTORS[attack]:
        return False, f"{attack} does not apply to {connector}"
    if box not in BOX_OVERRIDE.get(attack, {"black", "gray", "white"}):
        return False, f"{attack} runs only in {sorted(BOX_OVERRIDE[attack])}"
    if connector not in CONN_REACH[conn]:
        return False, f"{conn} cannot reach {connector}"
    return True, "valid"
```

## Projection A: AI attack x connector (applicability)
`chat*` = all six chat transports. A checkmark means the attack applies; blank is N/A.

| AI attack | chat* | rag | agent | multi_agent | sdk_inproc | ml_model |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| prompt_injection_direct | + | + | + | + | + |  |
| prompt_injection_indirect |  | + | + | + |  |  |
| jailbreak | + | + | + | + | + |  |
| hidden_context_extraction | + | + | + | + | + |  |
| data_leakage | + | + | + | + | + |  |
| cross_tenant_bleed |  | + | + | + |  |  |
| embedding_inversion |  | + |  |  |  |  |
| tool_misuse |  |  | + | + |  |  |
| dangerous_tool_args |  |  | + | + |  |  |
| tool_chain_hijack |  |  | + | + |  |  |
| privilege_identity_abuse |  |  | + | + |  |  |
| code_exec_sandbox_escape |  |  | + | + |  |  |
| rag_poisoning |  | + |  |  |  |  |
| memory_poisoning |  | + | + | + |  |  |
| citation_groundedness |  | + |  |  |  |  |
| output_handling_sinks | + | + | + | + | + |  |
| secondary_injection |  |  | + | + |  |  |
| supply_chain |  | + | + | + |  | + |
| unbounded_consumption | + | + | + | + | + |  |
| harmful_content_policy | + | + | + | + | + |  |
| bias | + | + | + | + | + |  |
| multi_agent_spoof |  |  |  | + |  |  |
| cascade_rogue |  |  |  | + |  |  |
| predictive_ml |  |  |  |  |  | + |

## Projection B: classic attack x connector (applicability)

| Classic attack | web | api_rest | api_graphql | api_grpc | api_ws | codebase |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| web.xss | + |  |  |  |  |  |
| web.sqli | + | + | + |  |  |  |
| web.cmdi | + | + | + |  |  |  |
| web.ssti | + | + | + |  |  |  |
| web.path_lfi | + | + |  |  |  |  |
| web.ssrf | + | + | + |  |  |  |
| web.deserialization | + | + |  |  |  |  |
| web.xxe | + | + |  |  |  |  |
| api.bola_idor | + | + | + | + |  |  |
| api.bfla | + | + | + | + |  |  |
| api.mass_assignment |  | + | + |  |  |  |
| auth.jwt_oauth_session | + | + | + | + | + |  |
| logic.race | + | + | + |  |  |  |
| web.smuggling_cache | + |  |  |  |  |  |
| web.client_side | + |  |  |  |  |  |
| code.sast_sinks |  |  |  |  |  | + |
| code.secrets |  |  |  |  |  | + |
| deps.sca |  |  |  |  |  | + |
| infra.cve | + | + | + | + | + |  |
| infra.tls | + | + | + | + | + |  |

## Projection C: connector x connection mode (reachability)

| Connector | direct | relay | tunnel | sdk_bridge |
| --- | :-: | :-: | :-: | :-: |
| chat* | + | + |  | + |
| rag | + | + |  | + |
| agent | + | + |  | + |
| multi_agent | + | + |  | + |
| sdk_inproc |  |  |  | + |
| web | + |  | + |  |
| api_rest | + |  | + |  |
| api_graphql | + |  | + |  |
| api_grpc | + |  | + |  |
| api_ws | + |  | + |  |
| ml_model | + |  | + |  |
| codebase | + | + | + | + |

## Projection D: box-mode support by attack

| Rule | Attacks | Valid box modes |
| --- | --- | --- |
| Default | all not listed below | black, gray, white |
| Static, source only | code.sast_sinks, code.secrets, deps.sca | white |
| Needs context or artifacts | ai.embedding_inversion, ai.supply_chain | gray, white |
| Query or gradient only | ai.predictive_ml | black, white |

White box needs source, provided by runner `extract` or by `upload` in direct mode, so white removes no connection mode on its own.

## Worked example: the `web` connector, fully expanded
Applying the three predicates to `connector = web`:
- Applicable attacks (Projection B column `web`): xss, sqli, cmdi, ssti, path_lfi, ssrf, deserialization, xxe, bola_idor, bfla, jwt_oauth_session, race, smuggling_cache, client_side, infra.cve, infra.tls -> **16 attacks**.
- Box modes: all 16 use the default -> **3** (black, gray, white).
- Connection modes reaching `web` (Projection C): direct, tunnel -> **2**.

So `web` yields 16 x 3 x 2 = **96 valid cells**. Every other (web, box, attack, conn) combination is N/A, for example `(web, black, web.xss, relay)` is N/A because relay cannot reach web, and `(web, white, code.secrets, tunnel)` is N/A because `code.secrets` applies only to `codebase`.

## Counting the whole matrix
The full cross-product is 17 connectors x 3 box x 44 attacks x 4 conn = 8,976 combinations; the vast majority are N/A. The exact valid count is whatever `is_valid` returns true for, emitted by:
```
python -m tests.matrix.cells --count      # totals: valid, na, by-phase
python -m tests.matrix.cells --explain-na # every N/A cell with its reason
```
Keeping the count in the generator, not hand-written here, is deliberate: when a family or connector is added, the number changes and the completeness test (valid + N/A == full cross-product) is what guarantees nothing is missing.

## Keep in sync
This doc and `tests/matrix/validity.py` must agree. A CI check renders the four projections from the code and diffs them against this file, so the tables cannot drift from the function.
