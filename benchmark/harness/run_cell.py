"""Run one matrix cell. The scanner arrives in the phase that owns the cell."""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from benchmark.harness.score import Finding
from benchmark.matrix.registry import Cell

_REPO = Path(__file__).resolve().parents[2]


class ScannerNotBuilt(Exception):
    def __init__(self, cell: Cell) -> None:
        self.cell = cell
        super().__init__(
            f"{cell.cell_id} is owned by phase {cell.phase} and has no scanner yet"
        )


@dataclass(frozen=True)
class SandboxCall:
    """One planted function the built-in probes can hit over GET /call."""

    kind: str
    module: str
    fn: str


# Rows the existing probes can prove. Ownership still has to mark the cell 1B.
_CALLS: dict[tuple[str, str], SandboxCall] = {
    ("insidia-chatbot", "ai.data_leakage"): SandboxCall("chat", "chatbot", "data_leakage"),
    ("insidia-rag", "ai.data_leakage"): SandboxCall("rag", "rag", "data_leakage"),
    ("insidia-mcp", "ai.data_leakage"): SandboxCall("mcp", "mcp", "data_leakage"),
    ("insidia-web", "web.ssti"): SandboxCall("web", "web", "ssti"),
    ("insidia-api", "web.ssti"): SandboxCall("api", "api", "ssti"),
}


def scanner_ready(cell: Cell) -> bool:
    """True when this cell's plant is one the built-in scan can prove."""
    return (
        cell.phase == "1B"
        and cell.conn == "direct"
        and cell.box != "white"
        and (cell.target, cell.attack) in _CALLS
    )


def run_cell(cell: Cell) -> list[Finding]:
    if not scanner_ready(cell):
        raise ScannerNotBuilt(cell)
    return _prove(cell)


def _prove(cell: Cell) -> list[Finding]:
    call = _CALLS[(cell.target, cell.attack)]
    _ensure_insidia_import()
    port = _free_port()
    previous = os.environ.get("INSIDIA_TOOLCHAIN")
    with tempfile.TemporaryDirectory(prefix="insidia-cell-") as name:
        root = Path(name)
        toolchain = root / "toolchain"
        toolchain.mkdir()
        # Empty so the scan stays on the built-in probes and does not launch engines.
        os.environ["INSIDIA_TOOLCHAIN"] = str(toolchain)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = _start_sandbox(port)
            _wait_healthy(port, process)
            _write_project(root, port, call)
            findings = _run_scan(root)
        finally:
            if process is not None:
                _stop_sandbox(process)
            if previous is None:
                os.environ.pop("INSIDIA_TOOLCHAIN", None)
            else:
                os.environ["INSIDIA_TOOLCHAIN"] = previous
    return _matched(cell, findings)


def _matched(cell: Cell, findings: list[dict[str, object]]) -> list[Finding]:
    if any(item.get("attack") == cell.attack for item in findings):
        return [Finding(cell.plant_ids[0])]
    return []


def _ensure_insidia_import() -> None:
    # The cloud test env does not install the insidia package.
    core = str(_REPO / "core")
    if core not in sys.path:
        sys.path.insert(0, core)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
