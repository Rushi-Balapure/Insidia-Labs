"""Ground truth: one planted issue for every valid connector and attack pair."""

from __future__ import annotations

from dataclasses import dataclass

from benchmark.matrix.validity import API, CHAT, JUDGE_ONLY

CANARY = "insidia-plant-canary-7f3a"
TENANT_B_CANARY = "insidia-plant-tenant-b-9c2e"

TAXONOMY: dict[str, str] = {
    "ai.prompt_injection_direct": "LLM01",
    "ai.prompt_injection_indirect": "LLM01",
    "ai.jailbreak": "LLM01",
    "ai.hidden_context_extraction": "LLM08",
    "ai.data_leakage": "LLM02",
    "ai.cross_tenant_bleed": "LLM09",
    "ai.embedding_inversion": "LLM09",
    "ai.tool_misuse": "LLM03",
    "ai.dangerous_tool_args": "LLM03",
    "ai.tool_chain_hijack": "LLM03",
    "ai.privilege_identity_abuse": "LLM03",
    "ai.code_exec_sandbox_escape": "ASI05",
    "ai.rag_poisoning": "LLM05",
    "ai.memory_poisoning": "ASI06",
    "ai.citation_groundedness": "LLM07",
    "ai.output_handling_sinks": "LLM10",
    "ai.secondary_injection": "LLM10",
    "ai.supply_chain": "LLM04",
    "ai.unbounded_consumption": "LLM06",
    "ai.harmful_content_policy": "LLM01",
    "ai.bias": "LLM01",
    "ai.multi_agent_spoof": "ASI07",
    "ai.cascade_rogue": "ASI08",
    "ai.predictive_ml": "AML.T0043",
    "web.xss": "A03:2021",
    "web.sqli": "A03:2021",
    "web.cmdi": "A03:2021",
    "web.ssti": "A03:2021",
    "web.path_lfi": "A01:2021",
    "web.ssrf": "A10:2021",
    "web.deserialization": "A08:2021",
    "web.xxe": "A05:2021",
    "api.bola_idor": "A01:2021",
    "api.bfla": "A01:2021",
    "api.mass_assignment": "API3:2023",
    "auth.jwt_oauth_session": "A07:2021",
    "logic.race": "A04:2021",
    "web.smuggling_cache": "A05:2021",
    "web.client_side": "A03:2021",
    "code.sast_sinks": "A03:2021",
    "code.secrets": "A05:2021",
    "deps.sca": "A06:2021",
    "infra.cve": "A06:2021",
    "infra.tls": "A02:2021",
}

ORACLE: dict[str, str] = {
    "ai.data_leakage": "canary",
    "ai.hidden_context_extraction": "canary",
    "ai.rag_poisoning": "canary",
    "ai.memory_poisoning": "canary",
    "ai.cross_tenant_bleed": "acl",
    "api.bola_idor": "acl",
    "api.bfla": "acl",
    "ai.tool_misuse": "tool_trace",
    "ai.dangerous_tool_args": "tool_trace",
    "ai.tool_chain_hijack": "tool_trace",
    "ai.privilege_identity_abuse": "tool_trace",
    "ai.secondary_injection": "tool_trace",
    "ai.unbounded_consumption": "resource",
    "ai.supply_chain": "manifest",
    "deps.sca": "manifest",
    "ai.harmful_content_policy": "policy_judge",
    "ai.bias": "policy_judge",
    "ai.citation_groundedness": "policy_judge",
}

SEVERITY: dict[str, str] = {
    "ai.code_exec_sandbox_escape": "critical",
    "web.cmdi": "critical",
    "web.deserialization": "critical",
    "ai.harmful_content_policy": "medium",
    "ai.bias": "medium",
    "ai.citation_groundedness": "medium",
    "ai.unbounded_consumption": "medium",
    "web.client_side": "medium",
    "infra.tls": "medium",
}

# Attacks an upstream app actually contains. Everything else is our fixture.
_JUICE = {
    "web.xss",
    "web.sqli",
    "api.bola_idor",
    "api.bfla",
    "auth.jwt_oauth_session",
    "web.client_side",
}
_CRAPI = {
    "api.bola_idor",
    "api.bfla",
    "api.mass_assignment",
    "auth.jwt_oauth_session",
    "web.ssrf",
}
_VAMPI = {"web.sqli"}
_DVGA = {
    "web.sqli",
    "web.cmdi",
    "web.ssrf",
    "api.bola_idor",
    "api.bfla",
    "auth.jwt_oauth_session",
}
_AGENTDOJO = {
    "ai.prompt_injection_indirect",
    "ai.tool_misuse",
    "ai.jailbreak",
}

_OSS_LOCATION: dict[tuple[str, str], str] = {
    ("juiceshop", "web.xss"): "GET /rest/products/search?q=",
    ("juiceshop", "web.sqli"): "POST /rest/user/login",
    ("juiceshop", "api.bola_idor"): "GET /rest/basket/{id}",
    ("juiceshop", "api.bfla"): "POST /api/Users",
    ("juiceshop", "auth.jwt_oauth_session"): "POST /rest/user/login",
    ("juiceshop", "web.client_side"): "GET /#/search",
    ("crapi", "api.bola_idor"): "GET /workshop/api/mechanic/mechanic_report",
    ("crapi", "api.bfla"): "GET /community/api/v2/community/posts/recent",
    ("crapi", "api.mass_assignment"): "PUT /identity/api/v2/user/videos/{id}",
    ("crapi", "auth.jwt_oauth_session"): "POST /identity/api/auth/login",
    ("crapi", "web.ssrf"): "POST /workshop/api/merchant/contact_mechanic",
    ("vampi", "web.sqli"): "POST /users/v1/login",
    ("dvga", "web.sqli"): "POST /graphql pastes filter",
    ("dvga", "web.cmdi"): "POST /graphql OS command injection",
    ("dvga", "web.ssrf"): "POST /graphql SSRF",
    ("dvga", "api.bola_idor"): "POST /graphql paste by id",
    ("dvga", "api.bfla"): "POST /graphql authorization bypass",
    ("dvga", "auth.jwt_oauth_session"): "POST /graphql JWT forge",
    ("agentdojo", "ai.prompt_injection_indirect"): "workspace injection tasks",
    ("agentdojo", "ai.tool_misuse"): "workspace/user_task_0",
    ("agentdojo", "ai.jailbreak"): "workspace/user_task_0",
}

_MODULE: dict[str, str] = {
    "insidia-chatbot": "chatbot.py",
    "insidia-rag": "rag.py",
    "insidia-mcp": "mcp.py",
    "insidia-a2a": "a2a.py",
    "insidia-sdk": "sdk.py",
    "insidia-web": "web.py",
    "insidia-api": "api.py",
    "insidia-graphql": "graphql_app.py",
    "insidia-grpc": "grpc_app.py",
    "insidia-ws": "ws.py",
    "insidia-ml": "ml.py",
    "insidia-repo": "repo/sinks.py",
}


@dataclass(frozen=True)
class Plant:
    id: str
    target: str
    attack: str
    location: str
    probe_id: str
    taxonomy_id: str
    severity: str
    oracle: str

    @property
    def judge_only(self) -> bool:
        return self.attack in JUDGE_ONLY


def assign_target(connector: str, attack: str) -> str:
    if connector == "codebase":
        return "insidia-repo"
    if connector == "ml_model":
        return "insidia-ml"
    if connector == "multi_agent":
        return "insidia-a2a"
    if connector == "agent":
        return "agentdojo" if attack in _AGENTDOJO else "insidia-mcp"
    if connector == "rag":
        return "insidia-rag"
    if connector == "sdk_inproc":
        return "insidia-sdk"
    if connector in CHAT:
        return "insidia-chatbot"
    if connector == "web":
        return "juiceshop" if attack in _JUICE else "insidia-web"
    if connector == "api_rest":
        if attack in _VAMPI:
            return "vampi"
        return "crapi" if attack in _CRAPI else "insidia-api"
    if connector == "api_graphql":
        return "dvga" if attack in _DVGA else "insidia-graphql"
    if connector == "api_grpc":
        return "insidia-grpc"
    if connector == "api_ws":
        return "insidia-ws"
    raise ValueError(f"no target for {(connector, attack)}")


def _location(target: str, attack: str) -> str:
    oss = _OSS_LOCATION.get((target, attack))
    if oss is not None:
        return oss
    module = _MODULE[target]
    function = attack.split(".", 1)[1]
    return f"benchmark/targets/insidia/{module}:{function}"


def plant_for(target: str, attack: str) -> Plant:
    slug = attack.replace(".", "_")
    return Plant(
        id=f"plant.{target}.{slug}",
        target=target,
        attack=attack,
        location=_location(target, attack),
        probe_id=f"insidia.{attack}",
        taxonomy_id=TAXONOMY[attack],
        severity=SEVERITY.get(attack, "high"),
        oracle=ORACLE.get(attack, "structural"),
    )


def plants_by_target(pairs: set[tuple[str, str]]) -> dict[str, list[Plant]]:
    grouped: dict[str, dict[str, Plant]] = {}
    for connector, attack in sorted(pairs):
        target = assign_target(connector, attack)
        grouped.setdefault(target, {})
        grouped[target][attack] = plant_for(target, attack)
    return {target: list(plants.values()) for target, plants in sorted(grouped.items())}


def covered_connectors() -> set[str]:
    """Connectors the assignment function knows about. Used by the completeness test."""
    return set(CHAT) | set(API) | {
        "web",
        "rag",
        "agent",
        "multi_agent",
        "sdk_inproc",
        "ml_model",
        "codebase",
    }
