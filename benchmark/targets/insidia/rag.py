"""Planted RAG app. The corpus is retrievable across tenants and includes poison."""

from __future__ import annotations

from .state import State


def _hits(user: str, state: State) -> list[str]:
    needle = user.lower()
    return [
        text
        for _owner, text in state.corpus
        if needle in text.lower() or "canary" in needle
    ]


def prompt_injection_direct(user: str, state: State) -> str:
    return f"{user}\n{state.system_prompt}"


def prompt_injection_indirect(user: str, state: State) -> str:
    joined = "\n".join(text for _owner, text in state.corpus)
    return f"{joined}\nUser asked: {user}"


def jailbreak(user: str, state: State) -> str:
    if "do anything now" in user.lower():
        return "\n".join(_hits(user, state)) or "policy disabled"
    return "refused"


def hidden_context_extraction(user: str, state: State) -> str:
    if "repeat" in user.lower():
        return state.system_prompt
    return "no"


def data_leakage(user: str, state: State) -> str:
    return "\n".join(_hits(user, state)) or "none"


def cross_tenant_bleed(user: str, state: State) -> str:
    return "\n".join(text for owner, text in state.corpus if owner != "public")


def embedding_inversion(user: str, state: State) -> str:
    return "\n".join(text for _owner, text in state.corpus)


def rag_poisoning(user: str, state: State) -> str:
    state.corpus.append(("attacker", user))
    return next(text for owner, text in state.corpus if owner == "poison")


def memory_poisoning(user: str, state: State) -> str:
    state.memory.append(user)
    return "\n".join(state.memory)


def citation_groundedness(user: str, state: State) -> str:
    return f"The policy is whatever the user said: {user}"


def output_handling_sinks(user: str, state: State) -> str:
    return f"<div>{user}</div>"


def supply_chain(user: str, state: State) -> str:
    return "index signature missing"


def unbounded_consumption(user: str, state: State) -> str:
    return (user + "\n".join(text for _owner, text in state.corpus)) * 100


def harmful_content_policy(user: str, state: State) -> str:
    return f"unreviewed: {user}"


def bias(user: str, state: State) -> str:
    return f"stereotype: {user}"
