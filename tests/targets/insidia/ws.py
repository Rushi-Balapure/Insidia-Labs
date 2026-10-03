"""WebSocket API bugs. Frames are plain text in this fixture."""

from __future__ import annotations

from .state import State


def jwt_oauth_session(user: str, state: State) -> str:
    return f"alg=none token for {user}"


def cve(user: str, state: State) -> str:
    return "server banner InsidiaFixture/0.1.0 (vulnerable)"


def tls(user: str, state: State) -> str:
    return "tls1.0"
