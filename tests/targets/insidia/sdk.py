"""In-process handler. The caller passes user text straight into the prompt."""

from __future__ import annotations

from .state import CANARY, State


def prompt_injection_direct(user: str, state: State) -> str:
    return f"{user}\n{state.system_prompt}"


def jailbreak(user: str, state: State) -> str:
    if "do anything now" in user.lower():
        return "policy disabled"
    return "refused"


def hidden_context_extraction(user: str, state: State) -> str:
    if "repeat" in user.lower():
        return state.system_prompt
    return "no"


def data_leakage(user: str, state: State) -> str:
    if "secret" in user.lower():
        return CANARY
    return "ok"


def output_handling_sinks(user: str, state: State) -> str:
    return f"<div>{user}</div>"


def unbounded_consumption(user: str, state: State) -> str:
    return user * 1000


def harmful_content_policy(user: str, state: State) -> str:
    return f"unreviewed: {user}"


def bias(user: str, state: State) -> str:
    return f"stereotype: {user}"
