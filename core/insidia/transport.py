"""Send one probe payload to a target that is already in scope."""

from __future__ import annotations

import contextvars
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

from insidia.config import Target, resolve_secret
from insidia.errors import CliError, ConfigError, ProbeError, ScopeError
from insidia.scope import ScopeHost, check_url, hostname

_MAX_BODY = 1_000_000
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


Budget = dict[str, tuple["RateLimiter", threading.Semaphore]]
_budget: contextvars.ContextVar[Budget | None] = contextvars.ContextVar(
    "insidia_budget", default=None
)


@dataclass
class RateLimiter:
    rps: float
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        self._interval = 1.0 / self.rps
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = self.clock()
            delay = self._next - now if now < self._next else 0.0
            self._next = (self._next if delay else now) + self._interval
        if delay:
            self.sleep(delay)


def bind_budget(targets: tuple[Target, ...]) -> contextvars.Token[Budget | None]:
    """One limiter and one concurrency slot per target, shared by every engine."""

    table = {
        target.name: (
            RateLimiter(target.rate_limit.rps),
            threading.Semaphore(target.rate_limit.concurrency),
        )
        for target in targets
    }
    return _budget.set(table)


def reset_budget(token: contextvars.Token[Budget | None]) -> None:
    _budget.reset(token)


def current_budget() -> Budget | None:
    return _budget.get()


class BoundBudget:
    """Apply a budget captured on the scan thread inside a worker thread."""

    def __init__(self, table: Budget | None) -> None:
        self._table = table
        self._token: contextvars.Token[Budget | None] | None = None

    def __enter__(self) -> BoundBudget:
        if self._table is not None:
            self._token = _budget.set(self._table)
        return self

    def __exit__(self, *args: object) -> None:
        if self._token is not None:
            _budget.reset(self._token)


def exchange(target: Target, payload: str, scope: tuple[ScopeHost, ...], root: Path) -> str:
    if target.kind == "repo":
        repo_path(target, root)
        raise CliError(f"{target.name} has no network probe")
    if target.command and target.url is None:
        raise CliError(f"{target.name}: local commands are not available in this release")
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    scheme = urlparse(target.url).scheme
    if scheme == "grpc" or target.api == "grpc":
        grpc_url = target.url if scheme == "grpc" else f"grpc://{urlparse(target.url).hostname}"
        check_url(grpc_url, scope)
        raise CliError(f"{target.name}: gRPC probes are not available in this CLI yet")
    if scheme in {"ws", "wss"}:
        return _websocket(target, payload, scope)
    return _http(target, payload, scope)


def _http(target: Target, payload: str, scope: tuple[ScopeHost, ...]) -> str:
    assert target.url is not None
    limiter, gate = _slot(target)
    url = _with_query(target.url, target.query, payload)
    method = target.method
    body = _body(target, payload)
    headers = _headers(target, body is not None)
    with gate:
        observed = read_url(
            url,
            scope,
            method=method,
            body=body,
            headers=headers,
            limiter=limiter,
            timeout=600,
        )
    if target.kind in {"chat", "agent", "rag", "mcp"} and _login_page(observed):
        raise ProbeError(f"{target.name} returned an HTML login page")
    return _select(observed, target.response_selector)


def _websocket(target: Target, payload: str, scope: tuple[ScopeHost, ...]) -> str:
    assert target.url is not None
    check_url(target.url, scope)
    parsed = urlparse(target.url)
    assert parsed.hostname is not None
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    sock = socket.create_connection((parsed.hostname, port), timeout=10)
    try:
        if parsed.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
        key = b64encode(os.urandom(16)).decode()
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(handshake.encode())
        head = _read_until(sock, b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise CliError(f"{target.name} did not accept the websocket upgrade")
        sock.sendall(_client_frame(payload.encode()))
        return _read_text_frame(sock)
    finally:
        sock.close()


def read_url(
    url: str,
    scope: tuple[ScopeHost, ...],
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    limiter: RateLimiter | None = None,
    timeout: float = 10,
) -> str:
    """Read one URL. Redirects that change host are refused, and no proxy is used."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    origin = hostname(url)
    current = url
    request_headers = dict(headers or {})
    for _ in range(4):
        check_url(current, scope)
        if hostname(current) != origin:
            raise ScopeError(f"redirect left {origin}")
        if limiter is not None:
            limiter.wait()
        request = urllib.request.Request(
            current,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                if status in _REDIRECTS:
                    location = response.headers.get("Location")
                    if not isinstance(location, str) or not location:
                        raise CliError("redirect is missing Location")
                    current = urljoin(current, location)
                    if status in {301, 302, 303}:
                        method = "GET"
                        body = None
                    continue
                raw = response.read(_MAX_BODY)
                if not isinstance(raw, bytes):
                    raise CliError("response was not bytes")
                if status >= 400:
                    raise ProbeError(f"target returned HTTP {status}")
                return raw.decode("utf-8", "replace")
        except TimeoutError as exc:
            raise ProbeError("target timed out") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError | socket.timeout):
                raise ProbeError("target timed out") from exc
            raise ProbeError("endpoint is unreachable") from exc
    raise CliError("redirected too many times")


def repo_path(target: Target, root: Path) -> Path:
    if target.path is None:
        raise ConfigError(f"{target.name} needs path")
    candidate = Path(target.path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    project = root.resolve()
    if resolved != project and project not in resolved.parents:
        raise ScopeError(f"{target.name} path is outside the project")
    return resolved


def _with_query(url: str, query: dict[str, str], payload: str) -> str:
    if not query:
        return url
    parsed = urlparse(url)
    rendered = {key: _fill(value, payload) for key, value in query.items()}
    return urlunparse(parsed._replace(query=urlencode(rendered)))


def _body(target: Target, payload: str) -> bytes | None:
    if target.method == "GET":
        return None
    if target.request_template:
        return _fill(target.request_template, payload).encode()
    document: dict[str, object]
    if target.api == "anthropic":
        document = {"messages": [{"role": "user", "content": payload}]}
    elif target.kind == "mcp":
        document = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": payload}},
        }
    elif target.api == "graphql":
        document = {"query": payload}
    elif target.api == "openai":
        document = {"messages": [{"role": "user", "content": payload}]}
    else:
        document = {"prompt": payload}
    return json.dumps(document).encode()


def _headers(target: Target, has_body: bool) -> dict[str, str]:
    headers = dict(target.headers)
    if has_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    if target.auth is not None:
        secret = resolve_secret(target.auth.secret_ref)
        prefix = f"{target.auth.scheme} " if target.auth.scheme else ""
        headers[target.auth.header] = prefix + secret
    return headers


def _fill(template: str, payload: str) -> str:
    conversation = json.dumps([{"role": "user", "content": payload}])
    return (
        template.replace("{{conversation_json}}", conversation)
        .replace("{{prompt_json}}", json.dumps(payload))
        .replace("{{prompt}}", payload)
        .replace("{{payload}}", payload)
    )


def _slot(target: Target) -> tuple[RateLimiter, threading.Semaphore]:
    table = _budget.get()
    if table is not None and target.name in table:
        return table[target.name]
    return RateLimiter(target.rate_limit.rps), threading.Semaphore(target.rate_limit.concurrency)


def _login_page(body: str) -> bool:
    sample = body[:4000].lower()
    if "<html" not in sample and "<!doctype html" not in sample:
        return False
    return "password" in sample or "sign in" in sample or "log in" in sample


def _select(body: str, selector: str | None) -> str:
    if not selector:
        return body
    try:
        value: object = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProbeError("response was not JSON for the configured selector") from exc
    path = selector[2:] if selector.startswith("$.") else selector
    for part in path.split("."):
        name, _, index_text = part.partition("[")
        if name:
            if not isinstance(value, dict) or name not in value:
                raise ProbeError(f"response selector {selector} did not match")
            value = value[name]
        if index_text:
            if not index_text.endswith("]"):
                raise ProbeError(f"response selector {selector} did not match")
            try:
                index = int(index_text[:-1])
            except ValueError as exc:
                raise ProbeError(f"response selector {selector} did not match") from exc
            if not isinstance(value, list) or index >= len(value) or index < 0:
                raise ProbeError(f"response selector {selector} did not match")
            value = value[index]
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _client_frame(payload: bytes) -> bytes:
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    length = len(payload)
    if length < 126:
        header = bytes([0x81, 0x80 | length])
    elif length < 65536:
        header = bytes([0x81, 0x80 | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([0x81, 0x80 | 127]) + length.to_bytes(8, "big")
    return header + mask + masked


def _read_text_frame(sock: socket.socket) -> str:
    header = _read_exact(sock, 2)
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(_read_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_read_exact(sock, 8), "big")
    if length > _MAX_BODY:
        raise CliError("websocket response is too large")
    return _read_exact(sock, length).decode("utf-8", "replace")


def _read_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > _MAX_BODY:
            raise CliError("response is too large")
    return data


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise CliError("connection closed early")
        data += chunk
    return data
