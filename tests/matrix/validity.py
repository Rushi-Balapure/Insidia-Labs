"""Valid vs N/A cells for the permutation matrix.

This is the machine copy of plans/18-validity-matrix.md. A projection test
fails if the tables in that file drift from these sets.
"""

from __future__ import annotations

CHAT = {"chat_http", "chat_openai", "chat_anthropic", "chat_bedrock", "chat_azure", "chat_ws"}
AGENTIC = {"agent", "multi_agent"}
AI_APP = CHAT | {"rag", "agent", "multi_agent", "sdk_inproc"}
API = {"api_rest", "api_graphql", "api_grpc", "api_ws"}
WEB_API = {"web"} | API
CONNECTORS = AI_APP | WEB_API | {"ml_model", "codebase"}

BOXES = ("black", "gray", "white")
CONNS = ("direct", "relay", "tunnel", "sdk_bridge")

ATTACKS = (
    "ai.prompt_injection_direct",
    "ai.prompt_injection_indirect",
    "ai.jailbreak",
    "ai.hidden_context_extraction",
    "ai.data_leakage",
    "ai.cross_tenant_bleed",
    "ai.embedding_inversion",
    "ai.tool_misuse",
    "ai.dangerous_tool_args",
    "ai.tool_chain_hijack",
    "ai.privilege_identity_abuse",
    "ai.code_exec_sandbox_escape",
    "ai.rag_poisoning",
    "ai.memory_poisoning",
    "ai.citation_groundedness",
    "ai.output_handling_sinks",
    "ai.secondary_injection",
    "ai.supply_chain",
    "ai.unbounded_consumption",
    "ai.harmful_content_policy",
    "ai.bias",
    "ai.multi_agent_spoof",
    "ai.cascade_rogue",
    "ai.predictive_ml",
    "web.xss",
    "web.sqli",
    "web.cmdi",
    "web.ssti",
    "web.path_lfi",
    "web.ssrf",
    "web.deserialization",
    "web.xxe",
    "api.bola_idor",
    "api.bfla",
    "api.mass_assignment",
    "auth.jwt_oauth_session",
    "logic.race",
    "web.smuggling_cache",
    "web.client_side",
    "code.sast_sinks",
    "code.secrets",
    "deps.sca",
    "infra.cve",
    "infra.tls",
)

ATTACK_CONNECTORS: dict[str, set[str]] = {
    "ai.prompt_injection_direct": AI_APP,
    "ai.prompt_injection_indirect": {"rag", "agent", "multi_agent"},
    "ai.jailbreak": AI_APP,
    "ai.hidden_context_extraction": AI_APP,
    "ai.data_leakage": AI_APP,
    "ai.cross_tenant_bleed": {"rag", "agent", "multi_agent"},
    "ai.embedding_inversion": {"rag"},
    "ai.tool_misuse": AGENTIC,
    "ai.dangerous_tool_args": AGENTIC,
    "ai.tool_chain_hijack": AGENTIC,
    "ai.privilege_identity_abuse": AGENTIC,
    "ai.code_exec_sandbox_escape": AGENTIC,
    "ai.rag_poisoning": {"rag"},
    "ai.memory_poisoning": {"rag", "agent", "multi_agent"},
    "ai.citation_groundedness": {"rag"},
    "ai.output_handling_sinks": AI_APP,
    "ai.secondary_injection": AGENTIC,
    "ai.supply_chain": {"rag", "agent", "multi_agent", "ml_model"},
    "ai.unbounded_consumption": AI_APP,
    "ai.harmful_content_policy": AI_APP,
    "ai.bias": AI_APP,
    "ai.multi_agent_spoof": {"multi_agent"},
    "ai.cascade_rogue": {"multi_agent"},
    "ai.predictive_ml": {"ml_model"},
    "web.xss": {"web"},
    "web.sqli": {"web", "api_rest", "api_graphql"},
    "web.cmdi": {"web", "api_rest", "api_graphql"},
    "web.ssti": {"web", "api_rest", "api_graphql"},
    "web.path_lfi": {"web", "api_rest"},
    "web.ssrf": {"web", "api_rest", "api_graphql"},
    "web.deserialization": {"web", "api_rest"},
    "web.xxe": {"web", "api_rest"},
    "api.bola_idor": {"web", "api_rest", "api_graphql", "api_grpc"},
    "api.bfla": {"web", "api_rest", "api_graphql", "api_grpc"},
    "api.mass_assignment": {"api_rest", "api_graphql"},
    "auth.jwt_oauth_session": WEB_API,
    "logic.race": {"web", "api_rest", "api_graphql"},
    "web.smuggling_cache": {"web"},
    "web.client_side": {"web"},
    "code.sast_sinks": {"codebase"},
    "code.secrets": {"codebase"},
    "deps.sca": {"codebase"},
    "infra.cve": WEB_API,
    "infra.tls": WEB_API,
}

BOX_OVERRIDE: dict[str, set[str]] = {
    "code.sast_sinks": {"white"},
    "code.secrets": {"white"},
    "deps.sca": {"white"},
    "ai.embedding_inversion": {"gray", "white"},
    "ai.supply_chain": {"gray", "white"},
    "ai.predictive_ml": {"black", "white"},
}

CONN_REACH: dict[str, set[str]] = {
    "direct": AI_APP - {"sdk_inproc"} | WEB_API | {"ml_model", "codebase"},
    "relay": CHAT | {"rag", "agent", "multi_agent", "codebase"},
    "tunnel": WEB_API | {"ml_model", "codebase"},
    "sdk_bridge": AI_APP | {"codebase"},
}

# Judge output alone cannot promote a finding to critical.
JUDGE_ONLY = {"ai.harmful_content_policy", "ai.bias", "ai.citation_groundedness"}

DEFAULT_RECALL = 0.80
FOCUSED_RECALL = 1.0
DEFAULT_PRECISION = 0.90


def is_valid(connector: str, box: str, attack: str, conn: str) -> tuple[bool, str]:
    if connector not in ATTACK_CONNECTORS[attack]:
        return False, f"{attack} does not apply to {connector}"
    if box not in BOX_OVERRIDE.get(attack, {"black", "gray", "white"}):
        return False, f"{attack} runs only in {sorted(BOX_OVERRIDE[attack])}"
    if connector not in CONN_REACH[conn]:
        return False, f"{conn} cannot reach {connector}"
    return True, "valid"


def iter_combinations():
    for connector in sorted(CONNECTORS):
        for box in BOXES:
            for attack in ATTACKS:
                for conn in CONNS:
                    yield connector, box, attack, conn
