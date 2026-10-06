"""Map each valid cell to the single phase that must turn it green.

1A (the CLI shell) and 1D (the benchmark format) ride on cells that already
have an owner. 2B (the pentest agent) is a separate exit test, not a cell
here. The first matching rule wins:
- 1B: black-box chat and web/API, the classic web and infra attacks, race
  conditions and the WebSocket API, and the static white-box scanners
- 1C: RAG and indirect injection, scripted agent cells, GraphQL and gRPC,
  and the API attacks
- 3: the in-process SDK, ML models, and the late depth attacks
"""

from __future__ import annotations

from benchmark.matrix.validity import CHAT, WEB_API

OWNING_PHASES = ("1B", "1C", "3")

_PHASE_3_ATTACKS = {"ai.predictive_ml", "web.smuggling_cache", "web.client_side"}
_PHASE_1B_RACE = {"logic.race"}
_PHASE_1B_CONNECTORS = {"api_ws"}
_PHASE_1C_CONNECTORS = {"agent", "multi_agent"}
_PHASE_1C_AGENT_ATTACKS = {
    "ai.tool_misuse",
    "ai.dangerous_tool_args",
    "ai.tool_chain_hijack",
    "ai.privilege_identity_abuse",
    "ai.code_exec_sandbox_escape",
    "ai.secondary_injection",
    "ai.multi_agent_spoof",
    "ai.cascade_rogue",
}
# Output sinks are 1C. The pentest agent's chained exploit is its own exit
# test, not a separate cell in this matrix.
_PHASE_1C_DEPTH_ATTACKS = {
    "ai.prompt_injection_indirect",
    "ai.memory_poisoning",
    "ai.citation_groundedness",
    "ai.cross_tenant_bleed",
    "ai.rag_poisoning",
    "ai.output_handling_sinks",
}
_PHASE_1C_API_CONNECTORS = {"api_graphql", "api_grpc"}
_PHASE_1C_API_ATTACKS = {
    "api.bola_idor",
    "api.bfla",
    "api.mass_assignment",
    "auth.jwt_oauth_session",
}
_PHASE_1B_CLASSIC_ATTACKS = {
    "web.cmdi",
    "web.ssti",
    "web.path_lfi",
    "web.ssrf",
    "web.deserialization",
    "web.xxe",
    "infra.cve",
    "infra.tls",
}


def owning_phase(connector: str, box: str, attack: str) -> str:
    """Return the phase id that must make this valid cell pass."""
    if attack in _PHASE_3_ATTACKS or connector == "ml_model":
        return "3"
    if attack in _PHASE_1B_RACE or connector in _PHASE_1B_CONNECTORS:
        return "1B"
    # Static scanners are 1B. The in-process SDK and AI-BOM are Phase 3.
    if connector == "sdk_inproc":
        return "3"
    if box == "white" or connector == "codebase":
        return "1B"
    if connector in _PHASE_1C_CONNECTORS or attack in _PHASE_1C_AGENT_ATTACKS:
        return "1C"
    if (
        connector == "rag"
        or attack in _PHASE_1C_DEPTH_ATTACKS
        or (box == "gray" and connector in CHAT)
    ):
        return "1C"
    if connector in _PHASE_1C_API_CONNECTORS or attack in _PHASE_1C_API_ATTACKS:
        return "1C"
    if attack in _PHASE_1B_CLASSIC_ATTACKS or (box == "gray" and connector in WEB_API):
        return "1B"
    if box == "black" and connector in CHAT | WEB_API:
        return "1B"
    raise ValueError(f"no owner for {(connector, box, attack)}")
