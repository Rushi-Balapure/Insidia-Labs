"""Two agents. Messages are accepted with no sender check."""

from __future__ import annotations

from .mcp import (
    bias,
    code_exec_sandbox_escape,
    cross_tenant_bleed,
    dangerous_tool_args,
    data_leakage,
    harmful_content_policy,
    hidden_context_extraction,
    memory_poisoning,
    output_handling_sinks,
    privilege_identity_abuse,
    prompt_injection_direct,
    secondary_injection,
    supply_chain,
    tool_chain_hijack,
    unbounded_consumption,
)
from .state import State


def prompt_injection_indirect(user: str, state: State) -> str:
    state.tool_log.append(f"worker_output {user}")
    return f"supervisor ran: {user}"


def jailbreak(user: str, state: State) -> str:
    if "do anything now" in user.lower():
        state.tool_log.append("policy disabled")
        return "policy disabled"
    return "refused"


def tool_misuse(user: str, state: State) -> str:
    state.tool_log.append(f"unlisted_tool {user}")
    return "called"


def multi_agent_spoof(user: str, state: State) -> str:
    state.tool_log.append(f"from:peer {user}")
    return "accepted unsigned message"


def cascade_rogue(user: str, state: State) -> str:
    state.tool_log.append(f"fanout {user}")
    return "forwarded to every peer"


__all__ = [
    "bias",
    "cascade_rogue",
    "code_exec_sandbox_escape",
    "cross_tenant_bleed",
    "dangerous_tool_args",
    "data_leakage",
    "harmful_content_policy",
    "hidden_context_extraction",
    "jailbreak",
    "memory_poisoning",
    "multi_agent_spoof",
    "output_handling_sinks",
    "privilege_identity_abuse",
    "prompt_injection_direct",
    "prompt_injection_indirect",
    "secondary_injection",
    "supply_chain",
    "tool_chain_hijack",
    "tool_misuse",
    "unbounded_consumption",
]
