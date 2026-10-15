"""One bad route is one line, and one rejected payload does not stop a check."""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from insidia.cli import main


@pytest.fixture
def app() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != "/hello":
                self._reply(404, "not found")
                return
            name = parse_qs(parsed.query).get("name", [""])[0]
            if "<" in name:
                self._reply(400, "bad name")
                return
            self._reply(200, f"Hello {name}")

        def do_POST(self) -> None:  # noqa: N802
            self._reply(501, "Unsupported method")

        def _reply(self, status: int, body: str) -> None:
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def _scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str) -> tuple[int, dict]:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(f"version: 1\nscope:\n  - host: 127.0.0.1\ntargets:\n  site:\n{target}")
    code = main(["scan", "--config", str(config), "--quiet"])
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    return code, json.loads((latest / "benchmark.json").read_text())


def test_a_wrong_route_is_reported_once(
    app: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = f"    kind: web\n    url: http://127.0.0.1:{app}/missing\n    method: GET\n"
    code, benchmark = _scan(tmp_path, monkeypatch, target)
    assert code == 2
    assert benchmark["skips"] == [
        f"site: GET http://127.0.0.1:{app}/missing returned HTTP 404 (check url)"
    ]


def test_post_to_a_get_app_names_the_method(
    app: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = f"    kind: web\n    url: http://127.0.0.1:{app}/hello\n"
    code, benchmark = _scan(tmp_path, monkeypatch, target)
    assert code == 2
    assert "set method: GET" in benchmark["skips"][0]


def test_placeholders_in_the_url_are_filled() -> None:
    from insidia.transport import _in_path, _with_query

    assert _with_query("http://h/hello?name={{payload}}&x=1", {}, "a b") == (
        "http://h/hello?name=a+b&x=1"
    )
    assert _with_query("http://h/hello?x=1", {"name": "{{payload}}"}, "z") == (
        "http://h/hello?x=1&name=z"
    )
    assert _in_path("http://h/users/{{payload}}", "../etc") == "http://h/users/../etc"


def test_an_error_page_for_one_payload_is_still_an_answer(
    app: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = (
        f"    kind: web\n    url: http://127.0.0.1:{app}/hello\n    method: GET\n"
        '    query:\n      name: "{{payload}}"\n'
    )
    _code, benchmark = _scan(tmp_path, monkeypatch, target)
    assert not [skip for skip in benchmark["skips"] if "HTTP 400" in skip]
