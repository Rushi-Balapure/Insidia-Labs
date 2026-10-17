import json
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.cli import main
from insidia.config import ModelRole, load_project
from insidia.errors import CliError, ScopeError
from insidia.probes import Attempt
from insidia.providers import build_provider
from insidia.registry import Capability
from insidia.scan import execute
from insidia.scope import ScopeHost
from insidia.transport import RateLimiter, exchange, fetch
from insidia.ui import Event
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


def test_redirect_to_another_port_is_refused(tmp_path: Path) -> None:
    hit = {"followed": False}

    class Other(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            hit["followed"] = True
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    other_port = other.server_address[1]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{other_port}/secret")
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
    try:
        exchange(
            target(url=f"http://127.0.0.1:{port}/go", method="GET"),
            "next",
            (ScopeHost("127.0.0.1", False),),
            tmp_path,
        )
    except ScopeError as exc:
        assert "redirect changed port" in str(exc)
    else:
        raise AssertionError("expected ScopeError")
    finally:
        server.shutdown()
        other.shutdown()
    assert hit["followed"] is False


def test_same_origin_redirect_is_followed(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/go"):
                self.send_response(302)
                self.send_header("Location", "/land")
                self.end_headers()
                return
            body = b"land"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        body = exchange(
            target(url=f"http://127.0.0.1:{port}/go", method="GET"),
            "next",
            (ScopeHost("127.0.0.1", False),),
            tmp_path,
        )
    finally:
        server.shutdown()
    assert body == "land"


@pytest.mark.parametrize("location", ["a b", "/v1/127.0.0.1 && id"])
def test_redirect_with_a_raw_space_returns_the_302(location: str) -> None:
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        status, headers, _body = fetch(
            f"http://127.0.0.1:{port}/go",
            (ScopeHost("127.0.0.1", False),),
        )
    finally:
        server.shutdown()
    assert status == 302
    assert headers.get("location") == location
    assert seen == ["/go"]


def test_spaced_location_that_changes_port_is_not_contacted() -> None:
    hit = {"followed": False}

    class Other(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            hit["followed"] = True
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    other_port = other.server_address[1]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{other_port}/a b")
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
    try:
        fetch(
            f"http://127.0.0.1:{port}/go",
            (ScopeHost("127.0.0.1", False),),
        )
    except ScopeError as exc:
        assert "redirect changed port" in str(exc)
        assert "closed the connection" not in str(exc)
    else:
        raise AssertionError("expected ScopeError")
    finally:
        server.shutdown()
        other.shutdown()
    assert hit["followed"] is False


def test_scan_refuses_a_same_host_port_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hit = {"followed": False}

    class Other(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            hit["followed"] = True
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    other_port = int(other.server_address[1])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{other_port}/secret")
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [
        threading.Thread(target=other.serve_forever, daemon=True),
        threading.Thread(target=server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    port = int(server.server_address[1])
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  hop:
    kind: api
    url: http://127.0.0.1:{port}/go
    method: GET
"""
    )
    try:
        code = main(["scan", "--config", str(config), "--quiet"])
    finally:
        server.shutdown()
        other.shutdown()
    assert code == 2
    assert hit["followed"] is False
    benchmark = json.loads(_latest(tmp_path, "benchmark.json").read_text())
    text = json.dumps(benchmark)
    hop = f"http://127.0.0.1:{other_port}/secret"
    assert f"hop: refused redirect to {hop}" in text
    assert "redirect changed port" in text
    assert benchmark["execution_status"] == "incomplete"


def test_a_refused_redirect_keeps_the_earlier_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, benchmark, findings, followed, hop = _scan_then_refuse_redirect(
        tmp_path, monkeypatch, finding=False
    )
    assert code == 2
    assert findings == []
    assert followed == 0
    assert benchmark["execution_status"] == "incomplete"
    assert any(
        row["target"] == "kept" and row["result"] == "pass" for row in benchmark["controls"]
    )
    refused = json.dumps([row for row in benchmark["controls"] if row["target"] == "second"])
    assert f"second: refused redirect to {hop}" in refused
    assert "redirect changed port" in refused


def test_a_refused_redirect_keeps_an_earlier_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, benchmark, findings, followed, hop = _scan_then_refuse_redirect(
        tmp_path, monkeypatch, finding=True
    )
    assert code == 1
    assert followed == 0
    assert any(
        item["target"] == "kept" and item["attack"] == "web.open_redirect" for item in findings
    )
    refused = json.dumps(benchmark)
    assert f"second: refused redirect to {hop}" in refused
    assert "redirect changed port" in refused


def _scan_then_refuse_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, finding: bool
) -> tuple[int, dict[str, object], list[dict[str, object]], int, str]:
    """Scan a finished target, then refuse a port-changing redirect on the next one."""
    followed = {"n": 0}

    class Other(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            followed["n"] += 1
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    other_port = int(other.server_address[1])
    hop = f"http://127.0.0.1:{other_port}/secret"

    class Kept(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if finding and "insidia-redirect.invalid" in self.path:
                self.send_response(302)
                self.send_header("Location", "https://insidia-redirect.invalid/")
                self.end_headers()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    class Second(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", hop)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    kept = ThreadingHTTPServer(("127.0.0.1", 0), Kept)
    second = ThreadingHTTPServer(("127.0.0.1", 0), Second)
    for server in (other, kept, second):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    kept_port = int(kept.server_address[1])
    second_port = int(second.server_address[1])
    (tmp_path / "insidia.yaml").write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  kept:
    kind: web
    url: http://127.0.0.1:{kept_port}/hello
    method: GET
    query:
      q: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  second:
    kind: web
    url: http://127.0.0.1:{second_port}/go
    method: GET
    query:
      q: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )
    try:
        code = main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--quiet"])
    finally:
        for server in (kept, second, other):
            server.shutdown()
    benchmark = json.loads(_latest(tmp_path, "benchmark.json").read_text())
    findings = json.loads(_latest(tmp_path, "findings.json").read_text())
    return code, benchmark, findings, followed["n"], hop


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


def test_provider_scope_check_does_not_connect() -> None:
    outside = ModelRole(
        "attacker",
        "openai-compatible",
        "http://qa-out-of-scope.invalid/v1",
        "qwen",
        None,
    )
    with pytest.raises(ScopeError, match="qa-out-of-scope.invalid is not in scope"):
        build_provider(outside, (ScopeHost("127.0.0.1", False),))
    local = ModelRole("judge", "openai-compatible", "http://127.0.0.1:9/v1", "qwen", None)
    build_provider(local, (ScopeHost("127.0.0.1", False),))


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


def test_trivy_and_osv_scanner_are_named_in_the_scan_output(
    tmp_path: Path, monkeypatch: object
) -> None:
    (tmp_path / "insidia.yaml").write_text(
        "version: 1\npolicy: L1\ncoverage: thorough\nscope:\n"
        "  - host: 127.0.0.1\ntargets:\n  repo:\n    kind: repo\n    path: .\n"
    )

    def fake_select(
        family: str, mode: str, model_available: bool = False, entries: object = None
    ) -> list[Capability]:
        del mode, model_available, entries
        if family != "deps.sca":
            return []
        return [
            Capability("deps.sca", "trivy", "insidia.deps.sca", 40, False, True),
            Capability("deps.sca", "osv-scanner", "insidia.deps.sca", 30, False, True),
        ]

    def fake_run(*_args: object, **_kwargs: object) -> Attempt:
        return Attempt()

    monkeypatch.setattr("insidia.scan.select", fake_select)  # type: ignore[attr-defined]
    monkeypatch.setattr("insidia.scan.run", fake_run)  # type: ignore[attr-defined]
    monkeypatch.delenv("INSIDIA_VULN_DB", raising=False)  # type: ignore[attr-defined]
    events: list[Event] = []
    outcome = execute(
        load_project(tmp_path / "insidia.yaml"), tmp_path, progress=events.append
    )
    assert outcome.notes == ()
    assert [event.detail for event in events if event.kind == "note"] == []
    monkeypatch.setenv("INSIDIA_VULN_DB", "1")  # type: ignore[attr-defined]
    opted: list[Event] = []
    opted_in = execute(
        load_project(tmp_path / "insidia.yaml"), tmp_path, progress=opted.append
    )
    assert opted_in.notes == (
        "trivy downloads a vulnerability database from mirror.gcr.io and ghcr.io "
        "because INSIDIA_VULN_DB=1",
        "osv-scanner downloads a vulnerability database from api.osv.dev "
        "because INSIDIA_VULN_DB=1",
    )
    assert [event.detail for event in opted if event.kind == "note"] == list(opted_in.notes)


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
