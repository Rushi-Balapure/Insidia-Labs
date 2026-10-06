import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from insidia.cli import main
from tests.support import start_fixture, stop_fixture

CANARY = "insidia-plant-canary-7f3a"


def test_mcp_http_sends_a_tool_call_and_reports_a_leak(tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            seen["body"] = json.loads(self.rfile.read(length))
            body = CANARY.encode()
            self.send_response(200)
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
        _write(tmp_path, f"http://127.0.0.1:{port}/mcp", "POST", {})
        assert main(["scan", "--config", str(tmp_path / "insidia.yaml")]) == 1
    finally:
        server.shutdown()
    assert seen["body"] == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "secret"}},
    }


def test_mcp_sandbox_plant_is_a_finding(tmp_path: Path) -> None:
    port = _free_port()
    process = start_fixture(port)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz")
        _write(
            tmp_path,
            f"http://127.0.0.1:{port}/call",
            "GET",
            {"module": "mcp", "fn": "data_leakage", "q": "{{prompt}}"},
        )
        assert main(["scan", "--config", str(tmp_path / "insidia.yaml")]) == 1
        findings = json.loads(_findings(tmp_path).read_text())
        assert findings[0]["attack"] == "ai.data_leakage"
        assert CANARY in findings[0]["response"]
    finally:
        stop_fixture(process)


def _write(root: Path, url: str, method: str, query: dict[str, str]) -> None:
    query_yaml = ""
    if query:
        lines = "\n".join(f"      {key}: {json.dumps(value)}" for key, value in query.items())
        query_yaml = f"    query:\n{lines}\n"
    (root / "insidia.yaml").write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  agent:
    kind: mcp
    url: {url}
    method: {method}
{query_yaml}    rate_limit:
      rps: 100
      concurrency: 1
"""
    )


def _findings(root: Path) -> Path:
    runs = sorted((root / ".insidia" / "runs").iterdir())
    return runs[-1] / "findings.json"


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
