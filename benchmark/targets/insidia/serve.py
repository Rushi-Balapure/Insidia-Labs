"""HTTP front for the local fixtures. Listens only inside the sandbox network."""

from __future__ import annotations

import importlib
import inspect
from urllib.parse import parse_qs, urlparse

from .state import new_state

STATE = new_state()
MODULES = (
    "chatbot",
    "rag",
    "mcp",
    "a2a",
    "sdk",
    "web",
    "api",
    "graphql_app",
    "grpc_app",
    "ws",
    "ml",
)


def reset() -> None:
    STATE.reset()


def call(module: str, function: str, user: str) -> str:
    if module not in MODULES:
        raise KeyError(module)
    loaded = importlib.import_module(f".{module}", package=__package__)
    handler = getattr(loaded, function)
    parameters = inspect.signature(handler).parameters
    if "state" in parameters:
        result = handler(user, STATE)
    else:
        result = handler(user)
    return str(result)


def main() -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                body = b"ok"
            elif parsed.path == "/call":
                query = parse_qs(parsed.query)
                module = query.get("module", [""])[0]
                function = query.get("fn", [""])[0]
                user = query.get("q", [""])[0]
                body = call(module, function, user).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/reset":
                self.send_response(404)
                self.end_headers()
                return
            reset()
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
