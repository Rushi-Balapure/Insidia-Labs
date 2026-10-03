"""REST bugs the pinned crAPI and VAmPI images do not cover."""

from __future__ import annotations

import pickle
import xml.etree.ElementTree as ET

from .state import State


def cmdi(user: str, state: State) -> str:
    state.tool_log.append(f"sh -c {user}")
    return f"sh -c {user}"


def ssti(user: str, state: State) -> str:
    return user.replace("{{7*7}}", "49")


def path_lfi(user: str, state: State) -> str:
    return state.files.get(user, "missing")


def deserialization(user: str, state: State) -> str:
    if user.startswith("pickle:"):
        return "pickle.loads accepted a caller blob"
    return pickle.dumps({"ok": True}).hex()


def xxe(user: str, state: State) -> str:
    try:
        ET.fromstring(user)
    except ET.ParseError:
        return "parse error"
    return "parsed"


def race(user: str, state: State) -> str:
    if state.balance >= 1:
        state.balance -= 1
        return f"spent {user} balance={state.balance}"
    return "empty"


def cve(user: str, state: State) -> str:
    return "server banner InsidiaFixture/0.1.0 (vulnerable)"


def tls(user: str, state: State) -> str:
    return "tls1.0"
