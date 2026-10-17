"""Keep every request inside the hosts declared in insidia.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from insidia.errors import ConfigError, ScopeError

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class ScopeHost:
    host: str
    authorized: bool


def check_url(url: str, scope: tuple[ScopeHost, ...]) -> str:
    """Return the host when it is in scope.

    The port is not part of the match. localhost, 127.0.0.1, and ::1 are local
    on every port and do not need authorized: true. A redirect that changes
    port, or downgrades https, is refused by redirect_refusal instead.
    """
    if urlparse(url).username or urlparse(url).password:
        raise ConfigError("put credentials in secret_ref, not in the URL")
    host = hostname(url)
    entry = next((item for item in scope if item.host == host), None)
    if entry is None:
        raise ScopeError(f"{host} is not in scope")
    if host not in LOCAL_HOSTS and not entry.authorized:
        raise ScopeError(f"{host} needs authorized: true in scope")
    return host


def hostname(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https", "ws", "wss", "grpc"}:
        raise ConfigError(f"unsupported URL scheme: {parsed.scheme or '(none)'}")
    if not parsed.hostname:
        raise ConfigError("URL is missing a host")
    return parsed.hostname.lower()


def needs_confirmation(scope: tuple[ScopeHost, ...]) -> bool:
    return any(item.host not in LOCAL_HOSTS for item in scope)


def unauthorized_host(scope: tuple[ScopeHost, ...]) -> str | None:
    """First non-local host that is missing authorized: true."""
    for item in scope:
        if item.host not in LOCAL_HOSTS and not item.authorized:
            return item.host
    return None


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "grpc": 443}


def redirect_refusal(origin: str, nxt: str) -> str | None:
    """Why this hop must not be followed, or None when it stays on the origin.

    The next request must keep the host and the port. https and wss must not
    downgrade to http or ws. An upgrade on the same port is allowed.
    """
    start_scheme, start_host, start_port = _endpoint(origin)
    hop_scheme, hop_host, hop_port = _endpoint(nxt)
    if hop_host != start_host:
        return f"redirect left {start_host}"
    if start_scheme in {"https", "wss"} and hop_scheme in {"http", "ws"}:
        return f"redirect downgraded {start_scheme} to {hop_scheme}"
    if hop_port != start_port:
        return "redirect changed port"
    return None


def _endpoint(url: str) -> tuple[str, str, int]:
    host = hostname(url)
    parsed = urlparse(url)
    port = parsed.port if parsed.port is not None else _DEFAULT_PORTS[parsed.scheme]
    return parsed.scheme, host, port
