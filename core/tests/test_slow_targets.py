import io
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.config import RateLimit, load_project
from insidia.errors import ConfigError, ProbeError
from insidia.probes import _replies
from insidia.scope import ScopeHost
from insidia.transport import RateLimiter, exchange
from insidia.ui import Event, ScanView, Terminal
from tests.support import target

SCOPE = (ScopeHost("127.0.0.1", False),)


@pytest.fixture
def slow() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            time.sleep(1.5 if b"stall" in body else 0.4)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def test_target_timeout_is_used(slow: int, tmp_path: Path) -> None:
    app = replace(target("web", f"http://127.0.0.1:{slow}/"), timeout=0.5)
    with pytest.raises(ProbeError, match="timed out"):
        exchange(app, "stall", SCOPE, tmp_path)


def test_payloads_run_in_parallel_up_to_concurrency(slow: int, tmp_path: Path) -> None:
    app = replace(target("web", f"http://127.0.0.1:{slow}/"), rate_limit=RateLimit(100, 4))
    payloads = tuple(f"p{index}" for index in range(8))
    began = time.monotonic()
    replies = list(_replies(app, payloads, "web.cmdi", SCOPE, tmp_path))
    assert [payload for payload, _reply in replies] == list(payloads)
    assert time.monotonic() - began < 8 * 0.4 / 2


def test_timeout_must_be_in_range(tmp_path: Path) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        "version: 1\nscope:\n  - host: 127.0.0.1\ntargets:\n"
        "  app:\n    kind: web\n    url: http://127.0.0.1:1/\n    timeout: 0\n"
    )
    with pytest.raises(ConfigError, match="timeout"):
        load_project(config)
    config.write_text(config.read_text().replace("timeout: 0", "timeout: 15"))
    assert load_project(config).targets[0].timeout == 15.0


def test_live_line_counts_requests() -> None:
    limiter = RateLimiter(1000)
    stream = io.StringIO()
    view = ScanView(Terminal(stream, animate=True, no_color=True))
    view(Event("begin", "app", "web.cmdi", ("insidia",), sent=lambda: limiter.sent))
    for _ in range(3):
        limiter.wait()
    time.sleep(0.3)
    view(Event("end", "app", "web.cmdi", ("insidia",), "pass"))
    assert "3 requests" in stream.getvalue()
