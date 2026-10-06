import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from insidia.cli import main


def test_graphql_target_sends_the_query_and_reports_ssti(tmp_path: Path) -> None:
    seen: list[object] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            seen.append(json.loads(self.rfile.read(length)))
            body = b"49"
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
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  api:
    kind: api
    api: graphql
    url: http://127.0.0.1:{port}/graphql
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )
    try:
        assert main(["scan", "--config", str(config)]) == 1
    finally:
        server.shutdown()
    assert {"query": "{{7*7}}"} in seen
    findings = json.loads(_findings(tmp_path).read_text())
    assert findings[0]["attack"] == "web.ssti"


def _findings(root: Path) -> Path:
    runs = sorted((root / ".insidia" / "runs").iterdir())
    return runs[-1] / "findings.json"
