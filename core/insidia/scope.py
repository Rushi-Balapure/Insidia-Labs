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
