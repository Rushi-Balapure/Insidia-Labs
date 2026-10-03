"""Map each valid cell to the single phase that must turn it green.

Phase 3 adds taxonomy assertions on cells that already have an owner. It does
not own cells of its own. The first matching rule wins.
"""

from __future__ import annotations

from tests.matrix.validity import CHAT, WEB_API

OWNING_PHASES = ("1", "4A", "4B", "5", "7", "8", "9", "11")

_PHASE_11_ATTACKS = {"ai.predictive_ml", "web.smuggling_cache", "web.client_side"}
_PHASE_9_ATTACKS = {"logic.race"}
_PHASE_9_CONNECTORS = {"api_ws"}
_PHASE_7_CONNECTORS = {"agent", "multi_agent"}
_PHASE_7_ATTACKS = {
    "ai.tool_misuse",
    "ai.dangerous_tool_args",
    "ai.tool_chain_hijack",
    "ai.privilege_identity_abuse",
    "ai.code_exec_sandbox_escape",
    "ai.secondary_injection",
    "ai.multi_agent_spoof",
    "ai.cascade_rogue",
}
# Output sinks are Phase 4A. Phase 5's chained exploit is its own exit test,
# not a separate cell in this matrix.
_PHASE_4A_ATTACKS = {
    "ai.prompt_injection_indirect",
    "ai.memory_poisoning",
    "ai.citation_groundedness",
    "ai.cross_tenant_bleed",
    "ai.rag_poisoning",
    "ai.output_handling_sinks",
}
_PHASE_4B_CONNECTORS = {"api_graphql", "api_grpc"}
_PHASE_4B_ATTACKS = {
    "api.bola_idor",
    "api.bfla",
    "api.mass_assignment",
    "auth.jwt_oauth_session",
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
    if attack in _PHASE_11_ATTACKS or connector == "ml_model":
        return "11"
    if attack in _PHASE_9_ATTACKS or connector in _PHASE_9_CONNECTORS:
        return "9"
    # White-box source, the in-process SDK, and static analysis ship in Phase 8.
    if box == "white" or connector in {"sdk_inproc", "codebase"}:
        return "8"
    if connector in _PHASE_7_CONNECTORS or attack in _PHASE_7_ATTACKS:
        return "7"
    if connector == "rag" or attack in _PHASE_4A_ATTACKS or (box == "gray" and connector in CHAT):
        return "4A"
    if (
        connector in _PHASE_4B_CONNECTORS
        or attack in _PHASE_4B_ATTACKS
        or (box == "gray" and connector in WEB_API)
    ):
        return "4B"
    if box == "black" and connector in CHAT | WEB_API:
        return "1"
    raise ValueError(f"no owner for {(connector, box, attack)}")
