"""Send one probe payload to a target that is already in scope."""

from __future__ import annotations

import contextvars
import http.client
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
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse

from insidia.config import Target, resolve_secret
from insidia.errors import CliError, ConfigError, HttpStatus, ProbeError, ScopeError
from insidia.scope import ScopeHost, check_url, redirect_refusal

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
        self.sent = 0

    def wait(self) -> None:
        with self._lock:
            self.sent += 1
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


AI_KINDS = frozenset({"chat", "agent", "rag", "mcp"})
_NO_ROUTE = {404: "check url", 405: "check method", 501: "check method"}


def preflight(target: Target, scope: tuple[ScopeHost, ...], root: Path) -> str:
    """Why this target cannot be scanned at all, or an empty string.

    A web app may answer one odd input with 400 or 500, and that answer is
    evidence. A missing route, a wrong method, or an AI endpoint that rejects
    a plain prompt means every check would fail the same way. A 3xx is also
    an answer: the route exists, even when the page it points at does not.
    """
    if target.kind == "repo":
        return ""
    scheme = urlparse(target.url).scheme if target.url else ""
    if scheme in {"http", "https"} and target.api != "grpc":
        try:
            status, _headers, body = fetch_target(target, "hello", scope, follow=False)
        except ProbeError as exc:
            return f"{target.url}: {exc}"
        if status in _REDIRECTS or status < 400:
            return ""
        return _status_reason(target, HttpStatus(status, body), scope)
    try:
        exchange(target, "hello", scope, root)
    except HttpStatus as exc:
        return _status_reason(target, exc, scope)
    except ProbeError as exc:
        return f"{target.url}: {exc}"
    return ""


def _status_reason(target: Target, exc: HttpStatus, scope: tuple[ScopeHost, ...]) -> str:
    hint = _NO_ROUTE.get(exc.status)
    if exc.status == 404 and target.kind not in AI_KINDS and _app_answer(target, exc, scope):
        hint = None
    if hint is None and target.kind not in AI_KINDS:
        return ""
    where = f"{target.method} {target.url}"
    if hint == "check method":
        hint = f"method is {target.method}; set method: GET if the app reads a query"
    return f"{where} returned HTTP {exc.status}" + (f" ({hint})" if hint else "")


def _app_answer(target: Target, missing: HttpStatus, scope: tuple[ScopeHost, ...]) -> bool:
    """A 404 that differs from the server's 404 for a route that cannot exist.

    `/file?name=hello` may answer "no such file", and that is the app talking.
    A 404 that matches the catch-all page means the route itself is wrong.
    """
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    parsed = urlparse(target.url)
    missing_path = f"/insidia-no-such-route-{os.urandom(4).hex()}"
    probe = urlunparse(parsed._replace(path=missing_path, query=""))
    try:
        status, _headers, body = fetch(probe, scope, headers=dict(target.headers))
    except ProbeError:
        return True
    return status != 404 or body.strip() != missing.body.strip()


def _http(target: Target, payload: str, scope: tuple[ScopeHost, ...]) -> str:
    status, _headers, text = fetch_target(target, payload, scope)
    if status >= 400:
        raise HttpStatus(status, text)
    if target.kind in AI_KINDS and _login_page(text):
        raise ProbeError(f"{target.name} returned an HTML login page")
    return _select(text, target.response_selector)


def fetch_target(
    target: Target,
    payload: str,
    scope: tuple[ScopeHost, ...],
    *,
    follow: bool = True,
) -> tuple[int, dict[str, str], str]:
    """Status, headers, and body for one payload. Redirects are optional."""
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    limiter, gate = _slot(target)
    url = _with_query(_in_path(target.url, payload), target.query, payload)
    body = _body(target, payload)
    headers = _headers(target, body is not None)
    with gate:
        return fetch(
            url,
            scope,
            target.method,
            body,
            headers,
            limiter,
            target.timeout,
            follow=follow,
        )


def _websocket(target: Target, payload: str, scope: tuple[ScopeHost, ...]) -> str:
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    check_url(target.url, scope)
    parsed = urlparse(target.url)
    if parsed.hostname is None:
        raise ConfigError("URL is missing a host")
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
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    limiter: RateLimiter | None = None,
    timeout: float = 10,
) -> str:
    """Read one URL. A redirect that changes host or port, or downgrades TLS, is refused."""
    status, _headers, text = fetch(url, scope, method, body, headers, limiter, timeout)
    if status >= 400:
        raise HttpStatus(status, text)
    return text


def fetch(
    url: str,
    scope: tuple[ScopeHost, ...],
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    limiter: RateLimiter | None = None,
    timeout: float = 10,
    *,
    follow: bool = True,
) -> tuple[int, dict[str, str], str]:
    """Status, response headers, and body. An error status is returned, not raised.

    Redirects are followed only when `follow` is true. A 3xx is returned as-is
    otherwise, and its Location is not requested. A Location that urllib cannot
    request, such as one with a raw space, is not followed either: the 3xx is
    returned to the probe.
    """
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    origin = url
    current = url
    request_headers = dict(headers or {})
    for _ in range(4):
        check_url(current, scope)
        refusal = redirect_refusal(origin, current)
        if refusal is not None:
            raise ScopeError(refusal)
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
                raw = response.read(_MAX_BODY)
                if not isinstance(raw, bytes):
                    raise CliError("response was not bytes")
                received = {key.lower(): value for key, value in response.headers.items()}
                text = raw.decode("utf-8", "replace")
                if status not in _REDIRECTS:
                    return status, received, text
                if not follow:
                    return status, received, text
                location = received.get("location", "")
                if not location:
                    raise CliError("redirect is missing Location")
                nxt = urljoin(current, location)
                if not _location_is_requestable(nxt):
                    _refuse_unrequested_location(origin, nxt, scope)
                    return status, received, text
                current = nxt
                if status in {301, 302, 303}:
                    method = "GET"
                    body = None
                continue
        except TimeoutError as exc:
            raise ProbeError("target timed out") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError | socket.timeout):
                raise ProbeError("target timed out") from exc
            raise ProbeError("endpoint is unreachable") from exc
        except http.client.InvalidURL as exc:
            raise ProbeError("redirect Location is not a valid URL") from exc
        except (http.client.HTTPException, ConnectionError) as exc:
            raise ProbeError("target closed the connection without a response") from exc
    raise CliError("redirected too many times")


def _control_char(text: str) -> bool:
    """Characters http.client rejects in a request target, including a raw space."""
    return any(ord(char) <= 0x20 or ord(char) == 0x7F for char in text)


def _location_is_requestable(url: str) -> bool:
    """False when following this URL would raise InvalidURL instead of connecting."""
    try:
        request = urllib.request.Request(url)
    except (ValueError, http.client.InvalidURL):
        return False
    selector = request.selector or ""
    host = request.host or ""
    return not (_control_char(selector) or _control_char(host))


def _refuse_unrequested_location(origin: str, nxt: str, scope: tuple[ScopeHost, ...]) -> None:
    """A Location we will not request still cannot leave the host or the port.

    A hop that changes port or downgrades TLS is refused before any connection.
    A Location that is not a URL at all is skipped.
    """
    try:
        check_url(nxt, scope)
        refusal = redirect_refusal(origin, nxt)
    except ConfigError:
        return
    if refusal is not None:
        raise ScopeError(refusal)


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


# Placeholders `_fill` substitutes. The path is narrower: only {{payload}}, matching `_in_path`.
_FILL_MARKERS = ("{{conversation_json}}", "{{prompt_json}}", "{{prompt}}", "{{payload}}")


def carries_payload(target: Target) -> bool:
    """True when a probe string changes the request, not only the text we meant to send.

    This follows `_http`: `{{payload}}` in the URL path, any `_fill` placeholder in
    the URL query or `query` map, and the body from `_body`. A non-GET target with
    no request template sends the raw payload as JSON, so it does carry one.
    A websocket frame is the payload itself.
    """
    if target.url is None:
        return False
    if urlparse(target.url).scheme in {"ws", "wss"}:
        return True
    if _path_carries(target.url) or _query_carries(target.url, target.query):
        return True
    return _body_carries(target)


def _path_carries(url: str) -> bool:
    return "{{payload}}" in urlparse(url).path


def _query_carries(url: str, query: dict[str, str]) -> bool:
    parsed = urlparse(url)
    values = [value for _key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    values.extend(query.values())
    return any(_has_fill_marker(value) for value in values)


def _body_carries(target: Target) -> bool:
    if target.method == "GET":
        return False
    if target.request_template:
        return _has_fill_marker(target.request_template)
    return True


def _has_fill_marker(text: str) -> bool:
    return any(marker in text for marker in _FILL_MARKERS)


def _in_path(url: str, payload: str) -> str:
    """Fill {{payload}} in the URL path, as in /users/{{payload}}. The host is never filled."""
    marker = "{{payload}}"
    parsed = urlparse(url)
    if marker not in parsed.path:
        return url
    return urlunparse(parsed._replace(path=parsed.path.replace(marker, quote(payload, safe="/"))))


def _with_query(url: str, query: dict[str, str], payload: str) -> str:
    """Fill placeholders in the URL's own query and in `query`. Both are kept."""
    parsed = urlparse(url)
    if not query and "{{" not in parsed.query:
        return url
    pairs = [
        (key, _fill(value, payload))
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    pairs.extend((key, _fill(value, payload)) for key, value in query.items())
    return urlunparse(parsed._replace(query=urlencode(pairs)))


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
