"""GraphQL bugs DVGA does not ship."""

from __future__ import annotations

from .state import State


def ssti(user: str, state: State) -> str:
    return user.replace("{{7*7}}", "49")


def mass_assignment(user: str, state: State) -> str:
    record = state.users["1"]
    record["role"] = user or "admin"
    return str(record["role"])


def race(user: str, state: State) -> str:
    if state.balance >= 1:
        state.balance -= 1
        return f"spent {user} balance={state.balance}"
    return "empty"


def cve(user: str, state: State) -> str:
    return "server banner InsidiaFixture/0.1.0 (vulnerable)"


def tls(user: str, state: State) -> str:
    return "tls1.0"
