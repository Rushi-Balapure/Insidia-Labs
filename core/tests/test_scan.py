import json
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from insidia.cli import main
from insidia.config import ModelRole
from insidia.errors import CliError, ScopeError
from insidia.providers import build_provider
from insidia.scope import ScopeHost
from insidia.transport import RateLimiter, exchange
from tests.support import start_fixture, stop_fixture, target


def test_rate_limiter_uses_the_supplied_clock() -> None:
    now = [0.0]
    slept: list[float] = []

    def clock() -> float:
        return now[0]

    def sleep(delay: float) -> None:
        slept.append(delay)
        now[0] += delay

    limiter = RateLimiter(10, clock=clock, sleep=sleep)
    limiter.wait()
    limiter.wait()
    assert slept == [0.1]


def test_rate_limiter_spaces_calls() -> None:
    limiter = RateLimiter(10)
    started = time.monotonic()
    limiter.wait()
    limiter.wait()
    assert time.monotonic() - started >= 0.05


def test_repo_path_outside_the_project_is_rejected(tmp_path: Path) -> None:
    project = tmp_path / "app"
    project.mkdir()
    try:
        exchange(target(kind="repo", path="/etc"), "secret", (), project)
    except ScopeError as exc:
        assert "outside the project" in str(exc)
    else:
        raise AssertionError("expected ScopeError")


def test_redirect_to_an_unlisted_host_is_rejected(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://example.com/secret")
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        exchange(
            target(url=f"http://127.0.0.1:{port}/chat", method="GET"),
            "secret",
            (ScopeHost("127.0.0.1", False),),
            tmp_path,
        )
    except CliError as exc:
        assert "not in scope" in str(exc)
    else:
        raise AssertionError("expected CliError")
    finally:
        server.shutdown()


def test_redirect_to_another_in_scope_host_is_refused(tmp_path: Path) -> None:
    hit = {"followed": False}

    class Other(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            hit["followed"] = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"no")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    other = ThreadingHTTPServer(("localhost", 0), Other)
    other_port = other.server_address[1]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{other_port}/secret")
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True),
        threading.Thread(target=other.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    port = server.server_address[1]
    scope = (ScopeHost("127.0.0.1", False), ScopeHost("localhost", False))
    try:
        exchange(
            target(url=f"http://127.0.0.1:{port}/chat", method="GET"),
            "secret",
            scope,
            tmp_path,
        )
    except ScopeError as exc:
        assert "redirect left 127.0.0.1" in str(exc)
    else:
        raise AssertionError("expected ScopeError")
    finally:
        server.shutdown()
        other.shutdown()
    assert hit["followed"] is False


def test_local_command_is_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    config = tmp_path / "insidia.yaml"
    command = json.dumps([sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"])
    config.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
targets:
  app:
    kind: chat
    command: {command}
"""
    )
    assert main(["scan", "--config", str(config)]) == 2
    assert not marker.exists()


def test_openai_provider_sends_the_prompt_and_returns_content() -> None:
    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            seen["body"] = json.loads(self.rfile.read(length))
            seen["auth"] = self.headers.get("Authorization")
            body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        role = ModelRole(
            "attacker",
            "openai-compatible",
            f"http://127.0.0.1:{port}/v1",
            "qwen",
            None,
        )
        provider = build_provider(role, (ScopeHost("127.0.0.1", False),))
        assert provider.complete("hello") == "ok"
        assert seen["body"] == {"model": "qwen", "messages": [{"role": "user", "content": "hello"}]}
        assert seen["auth"] is None
    finally:
        server.shutdown()


def test_scan_finds_the_sandbox_plants_and_passes_a_clean_target(tmp_path: Path) -> None:
    port = _free_port()
    process = start_fixture(port)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz")
        _write(tmp_path, port, "data_leakage", "ssti")
        failed = main(["scan", "--config", str(tmp_path / "insidia.yaml")])
        assert failed == 1
        findings = json.loads(_latest(tmp_path, "findings.json").read_text())
        engines = {item["engine"] for item in findings}
        attacks = {item["attack"] for item in findings}
        assert engines == {"insidia"}
        assert attacks == {"ai.data_leakage", "web.ssti"}
        report = _latest(tmp_path, "report.html").read_text()
        assert "insidia.ai.data_leakage" in report
        assert "<table>" in report

        clean = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
        threading.Thread(target=clean.serve_forever, daemon=True).start()
        try:
            _write(tmp_path, int(clean.server_address[1]), "data_leakage", "ssti")
            assert main(["scan", "--config", str(tmp_path / "insidia.yaml")]) == 0
        finally:
            clean.shutdown()
            clean.server_close()
    finally:
        stop_fixture(process)


def test_scan_refuses_a_remote_host_without_yes(tmp_path: Path) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: example.com
    authorized: true
targets:
  app:
    kind: chat
    url: http://example.com/chat
"""
    )
    code = main(["scan", "--config", str(config)])
    assert code == 2


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _write(root: Path, port: int, chat_fn: str, web_fn: str) -> None:
    (root / "insidia.yaml").write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  sandbox-chat:
    kind: chat
    url: http://127.0.0.1:{port}/call
    method: GET
    query:
      module: chatbot
      fn: {chat_fn}
      q: "{{{{prompt}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  sandbox-web:
    kind: web
    url: http://127.0.0.1:{port}/call
    method: GET
    query:
      module: web
      fn: {web_fn}
      q: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )


def _latest(root: Path, name: str) -> Path:
    runs = sorted((root / ".insidia" / "runs").iterdir())
    return runs[-1] / name


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait(url: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("sandbox did not start")
