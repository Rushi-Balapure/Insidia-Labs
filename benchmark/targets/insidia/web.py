"""Web bugs the pinned Juice Shop image does not cover."""

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


def ssrf(user: str, state: State) -> str:
    state.tool_log.append(f"fetch {user}")
    return f"fetched {user}"


def deserialization(user: str, state: State) -> str:
    if user == "pickle":
        return "pickle.loads would run the payload"
    return pickle.dumps(b"ok").hex()


def xxe(user: str, state: State) -> str:
    # The parser resolves entities. The plant is this call, not a live fetch.
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


def smuggling_cache(user: str, state: State) -> str:
    return f"content-length mismatch {user}"
