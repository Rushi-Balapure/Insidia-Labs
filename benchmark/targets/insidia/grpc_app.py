"""gRPC-shaped handlers. The sandbox serves them over HTTP until the tunnel exists."""

from __future__ import annotations

from .state import State


def bola_idor(user: str, state: State) -> str:
    return str(state.users.get(user, state.users["2"]))


def bfla(user: str, state: State) -> str:
    state.users["1"]["role"] = "admin"
    return f"promoted {user}"


def jwt_oauth_session(user: str, state: State) -> str:
    return f"alg=none token for {user}"


def cve(user: str, state: State) -> str:
    return "server banner InsidiaFixture/0.1.0 (vulnerable)"


def tls(user: str, state: State) -> str:
    return "tls1.0"
