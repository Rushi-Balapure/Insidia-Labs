"""Run one matrix cell. The scanner arrives in the phase that owns the cell."""

from __future__ import annotations

import atexit
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from benchmark.harness.score import Finding
from benchmark.matrix.plants import plant_for
from benchmark.matrix.registry import Cell

_REPO = Path(__file__).resolve().parents[2]
_INSIDIA = "benchmark/targets/insidia/"
_SCANS: dict[tuple[str, str, str], list[dict[str, object]]] = {}
_SANDBOX: subprocess.Popen[bytes] | None = None
_SANDBOX_PORT = 0

_PLANT_FILES = {
    "chatbot.py": ("chat", "chatbot"),
    "rag.py": ("rag", "rag"),
    "mcp.py": ("mcp", "mcp"),
    "a2a.py": ("agent", "a2a"),
    "web.py": ("web", "web"),
    "api.py": ("api", "api"),
    "graphql_app.py": ("api", "graphql_app"),
    "grpc_app.py": ("api", "grpc_app"),
    "ws.py": ("api", "ws"),
    "repo/sinks.py": ("repo", "repo"),
}


class ScannerNotBuilt(Exception):
    def __init__(self, cell: Cell) -> None:
        self.cell = cell
        super().__init__(f"{cell.cell_id} is owned by phase {cell.phase} and has no scanner yet")


@dataclass(frozen=True)
class SandboxCall:
    """One planted function the built-in probes can hit."""

    kind: str
    module: str
    fn: str
    attack: str


def scanner_ready(cell: Cell) -> bool:
    """True when this cell's plant is one the scanner can prove."""
    if cell.phase not in {"1B", "1C"}:
        return False
    if plant_for(cell.target, cell.attack).location.startswith(_INSIDIA):
        return True
    from benchmark.harness.live import live_ready

    if cell.phase == "1C":
        return live_ready(cell)
    from benchmark.harness.upstream import upstream_ready

    return upstream_ready(cell) or live_ready(cell)


def run_cell(cell: Cell) -> list[Finding]:
    if not scanner_ready(cell):
        raise ScannerNotBuilt(cell)
    if plant_for(cell.target, cell.attack).location.startswith(_INSIDIA):
        return _prove(cell)
    from benchmark.harness.live import live_ready, prove_live
    from benchmark.harness.upstream import prove_upstream, upstream_ready

    white = upstream_ready(cell)
    live = live_ready(cell)
    if white and live:
        raise RuntimeError(f"{cell.cell_id} is both a file needle and a live hit")
    if white:
        return prove_upstream(cell)
    if live:
        return prove_live(cell)
    raise ScannerNotBuilt(cell)


def _prove(cell: Cell) -> list[Finding]:
    call = _call_for(cell)
    key = (call.module, call.fn, cell.conn)
    findings = _SCANS.get(key)
    if findings is None:
        findings = _scan(call, cell.conn)
        _SCANS[key] = findings
    return _matched(cell, findings)


def _matched(cell: Cell, findings: list[dict[str, object]]) -> list[Finding]:
    if any(item.get("attack") == cell.attack for item in findings):
        return [Finding(cell.plant_ids[0])]
    return []


def _call_for(cell: Cell) -> SandboxCall:
    relative, function = plant_for(cell.target, cell.attack).location.split(":", 1)
    name = relative.removeprefix(_INSIDIA)
    kind, module = _PLANT_FILES[name]
    return SandboxCall(kind, module, function, cell.attack)


def _scan(call: SandboxCall, conn: str) -> list[dict[str, object]]:
    if call.kind == "repo":
        return _cli(call, None)
    if conn == "sdk_bridge":
        return _sdk(call)
    sandbox = _ensure_sandbox()
    _reset(sandbox)
    with _front(conn, sandbox) as port:
        return _cli(call, port)


def _sdk(call: SandboxCall) -> list[dict[str, object]]:
    _ensure_insidia_import()
    from insidia.adapters import BUILT_IN, ORACLES
    from insidia.config import RateLimit, Target

    from benchmark.targets.insidia.serve import call as plant
    from benchmark.targets.insidia.serve import reset

    reset()
    spec = next(item for item in BUILT_IN.probes if item.family == call.attack)
    oracle = ORACLES[spec.family]
    viewed = Target(
        "plant",
        call.kind,
        None,
        None,
        "GET",
        None,
        None,
        {},
        {},
        None,
        RateLimit(100, 1),
        "http",
        None,
        (),
    )
    found: list[dict[str, object]] = []
    for payload in BUILT_IN.corpus[spec]:
        if oracle(payload, plant(call.module, call.fn, payload), viewed) is not None:
            found.append({"attack": call.attack})
    return found


def _cli(call: SandboxCall, port: int | None) -> list[dict[str, object]]:
    _ensure_insidia_import()
    previous = os.environ.get("INSIDIA_TOOLCHAIN")
    with tempfile.TemporaryDirectory(prefix="insidia-cell-") as name:
        root = Path(name)
        toolchain = root / "toolchain"
        toolchain.mkdir()
        os.environ["INSIDIA_TOOLCHAIN"] = str(toolchain)
        try:
            if call.kind == "repo":
                _write_repo(root)
            else:
                assert port is not None
                _write_project(root, port, call)
            return _run_scan(root)
        finally:
            if previous is None:
                os.environ.pop("INSIDIA_TOOLCHAIN", None)
            else:
                os.environ["INSIDIA_TOOLCHAIN"] = previous


@contextlib.contextmanager
def _front(conn: str, sandbox: int) -> Iterator[int]:
    if conn == "direct":
        yield sandbox
        return
    if conn == "relay":
        server, thread = _start_relay(sandbox)
        try:
            yield int(server.server_address[1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        return
    if conn == "tunnel":
        listener, thread = _start_tunnel(sandbox)
        try:
            yield int(listener.getsockname()[1])
        finally:
            listener.close()
            thread.join(timeout=2)
        return
    raise RuntimeError(f"unknown connection {conn}")


def _ensure_insidia_import() -> None:
    core = str(_REPO / "core")
    if core not in sys.path:
        sys.path.insert(0, core)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _ensure_sandbox() -> int:
    global _SANDBOX, _SANDBOX_PORT
    if _SANDBOX is not None and _SANDBOX.poll() is None:
        return _SANDBOX_PORT
    _SANDBOX_PORT = _free_port()
    _SANDBOX = _start_sandbox(_SANDBOX_PORT)
    try:
        _wait_healthy(_SANDBOX_PORT, _SANDBOX)
    except (OSError, RuntimeError):
        _stop_sandbox(_SANDBOX)
        _SANDBOX = None
        raise
    return _SANDBOX_PORT


def _shutdown_sandbox() -> None:
    global _SANDBOX
    if _SANDBOX is not None:
        _stop_sandbox(_SANDBOX)
        _SANDBOX = None


def _start_sandbox(port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-m", "benchmark.targets.insidia.serve"],
        cwd=_REPO,
        env={
            **os.environ,
            "PYTHONPATH": str(_REPO),
            "INSIDIA_FIXTURE_HOST": "127.0.0.1",
            "INSIDIA_FIXTURE_PORT": str(port),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _stop_sandbox(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _wait_healthy(port: int, process: subprocess.Popen[bytes]) -> None:
    url = f"http://127.0.0.1:{port}/healthz"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            err = process.stderr.read().decode() if process.stderr else ""
            raise RuntimeError(f"sandbox exited {process.returncode}: {err}")
        try:
            with urllib.request.urlopen(url, timeout=0.2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("sandbox did not start")


def _reset(port: int) -> None:
    request = urllib.request.Request(f"http://127.0.0.1:{port}/reset", method="POST")
    with urllib.request.urlopen(request, timeout=2) as response:
        response.read()


def _start_relay(sandbox: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            url = f"http://127.0.0.1:{sandbox}{self.path}"
            with urllib.request.urlopen(url, timeout=10) as response:
                body = response.read()
                status = int(response.status)
            self.send_response(status)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server, thread


def _start_tunnel(dest: int) -> tuple[socket.socket, threading.Thread]:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.05)

    def accept_loop() -> None:
        while True:
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=_pump, args=(client, dest), daemon=True).start()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return listener, thread


def _pump(client: socket.socket, dest: int) -> None:
    upstream: socket.socket | None = None
    try:
        upstream = socket.create_connection(("127.0.0.1", dest), timeout=10)
        client.settimeout(10)
        upstream.settimeout(10)

        def copy(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        left = threading.Thread(target=copy, args=(client, upstream), daemon=True)
        right = threading.Thread(target=copy, args=(upstream, client), daemon=True)
        left.start()
        right.start()
        left.join(timeout=10)
        right.join(timeout=10)
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


def _write_project(root: Path, port: int, call: SandboxCall) -> None:
    (root / "insidia.yaml").write_text(
        f"""\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  plant:
    kind: {call.kind}
    url: http://127.0.0.1:{port}/call
    method: GET
    query:
      module: {call.module}
      fn: {call.fn}
      q: "{{{{prompt}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )


def _write_repo(root: Path) -> None:
    source = _REPO / "benchmark" / "targets" / "insidia" / "repo"
    dest = root / "benchmark" / "targets" / "insidia" / "repo"
    dest.mkdir(parents=True)
    for name in ("sinks.py", "requirements.txt"):
        text = (source / name).read_text(encoding="utf-8")
        (dest / name).write_text(text, encoding="utf-8")
    (root / "insidia.yaml").write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  plant:
    kind: repo
    path: benchmark/targets/insidia/repo
"""
    )


def _run_scan(root: Path) -> list[dict[str, object]]:
    from insidia.cli import main

    with contextlib.redirect_stdout(io.StringIO()):
        main(["scan", "--config", str(root / "insidia.yaml"), "--coverage", "standard"])
    runs = root / ".insidia" / "runs"
    if not runs.is_dir():
        return []
    latest = max(runs.iterdir(), key=lambda path: path.name)
    payload = json.loads((latest / "findings.json").read_text())
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


atexit.register(_shutdown_sandbox)
