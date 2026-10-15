"""Built-in web checks catch real bugs, not only Insidia's own planted strings."""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from insidia.cli import main

_PASSWD = "root:x:0:0:root:/root:/bin/bash\napp:x:1000:1000::/home/app:/bin/sh\n"
_USERS = {
    "1": {"id": 1, "name": "ada", "email": "ada@example.com", "role": "user"},
    "2": {"id": 2, "name": "grace", "email": "grace@example.com", "role": "admin"},
}


def _vulnerable(path: str, value: str) -> tuple[int, str]:
    if path == "/ping":
        if any(mark in value for mark in (";", "&&", "|", "$(", "`")):
            return 200, f"PING {value}\nuid=1000(app) gid=1000(app) groups=1000(app)"
        return 200, f"PING {value}: 1 packet"
    if path == "/file":
        if "../" in value or value.startswith("/etc"):
            return 200, _PASSWD
        return 404, "no such file"
    if path.startswith("/users/"):
        user = _USERS.get(path.removeprefix("/users/"))
        return (200, json.dumps(user)) if user else (404, '{"error": "not found"}')
    return 200, "home"


def _clean(path: str, value: str) -> tuple[int, str]:
    if path.startswith("/users/"):
        return 200, json.dumps({"id": 1, "name": "ada", "email": "ada@example.com"})
    return 200, f"You searched for {value}"


@pytest.fixture(params=["vulnerable", "clean"])
def app(request: pytest.FixtureRequest) -> Iterator[tuple[str, int]]:
    handle = _vulnerable if request.param == "vulnerable" else _clean

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            value = next(iter(query.values()), [""])[0]
            status, body = handle(unquote(parsed.path), value)
            raw = body.encode()
            self.send_response(status)
            self.send_header("Server", "Apache/2.4.49 (Unix)")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield request.param, int(server.server_address[1])
    server.shutdown()
    server.server_close()


def test_planted_web_bugs(
    app: tuple[str, int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flavor, port = app
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    base = f"http://127.0.0.1:{port}"
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  ping:
    kind: web
    url: {base}/ping
    method: GET
    query:
      host: "{{{{payload}}}}"
  files:
    kind: web
    url: {base}/file
    method: GET
    query:
      name: "{{{{payload}}}}"
  users:
    kind: api
    url: {base}/users/{{{{payload}}}}
    method: GET
"""
    )
    main(["scan", "--config", str(config), "--quiet"])
    runs = tmp_path / ".insidia" / "runs"
    run = max(runs.iterdir(), key=lambda path: path.name)
    findings = json.loads((run / "findings.json").read_text())
    found = {(item["target"], item["attack"]) for item in findings}
    controls = json.loads((run / "benchmark.json").read_text())["controls"]
    tls = {row["target"]: row["result"] for row in controls if row["id"] == "infra.tls"}
    assert set(tls.values()) == {"not tested"}
    assert ("ping", "infra.cve") in found
    if flavor == "vulnerable":
        assert {
            ("ping", "web.cmdi"),
            ("files", "web.path_lfi"),
            ("users", "api.bola_idor"),
        } <= found
    else:
        assert not {attack for _target, attack in found} & {
            "web.cmdi",
            "web.path_lfi",
            "api.bola_idor",
        }
