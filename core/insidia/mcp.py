"""MCP server over stdio. Tools call the local CLI and never take a URL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import BinaryIO, cast

from insidia import __version__
from insidia.config import init_config, load_project
from insidia.doctor import diagnose
from insidia.errors import CliError
from insidia.policy import POLICIES
from insidia.runstore import latest_run
from insidia.scan import execute

_PROTOCOL = "2024-11-05"


def serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    while True:
        message = _read(stdin)
        if message is None:
            return 0
        response = dispatch(message)
        if response is not None:
            _write(stdout, response)


def dispatch(message: dict[str, object]) -> dict[str, object] | None:
    method = message.get("method")
    if not isinstance(method, str):
        return _error(message.get("id"), -32600, "missing method")
    if method.startswith("notifications/"):
        return None
    handler = _METHODS.get(method)
    if handler is None:
        return _error(message.get("id"), -32601, f"unknown method {method}")
    try:
        result = handler(message.get("params"))
    except CliError as exc:
        if method == "tools/call":
            return _result(message.get("id"), _tool_error(str(exc)))
        return _error(message.get("id"), -32000, str(exc))
    return _result(message.get("id"), result)


def _initialize(params: object) -> dict[str, object]:
    del params
    return {
        "protocolVersion": _PROTOCOL,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "insidia", "version": __version__},
    }


def _ping(params: object) -> dict[str, object]:
    del params
    return {}


def _tools_list(params: object) -> dict[str, object]:
    del params
    return {"tools": list(_TOOLS)}


def _tools_call(params: object) -> dict[str, object]:
    document = _object(params)
    name = document.get("name")
    if not isinstance(name, str) or name not in _TOOL_CALLS:
        raise CliError(f"unknown tool {name}")
    arguments = document.get("arguments", {})
    if not isinstance(arguments, dict):
        raise CliError("tool arguments must be an object")
    payload = _TOOL_CALLS[name](cast(dict[str, object], arguments))
    return {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}


def _init(arguments: dict[str, object]) -> dict[str, object]:
    del arguments
    path = init_config(Path.cwd())
    return {"wrote": path.name}


def _doctor(arguments: dict[str, object]) -> dict[str, object]:
    del arguments
    checks, code = diagnose(Path("insidia.yaml"))
    if code:
        raise CliError(json.dumps({"checks": checks}))
    return {"checks": checks}


def _scan(arguments: dict[str, object]) -> dict[str, object]:
    if arguments.get("confirmed") is not True:
        raise CliError("scan requires confirmed true after the user names the hosts")
    policy = arguments.get("policy")
    if policy is not None and policy not in POLICIES:
        raise CliError(f"unknown policy {policy}")
    policy_name = policy if isinstance(policy, str) else None
    project = load_project(Path("insidia.yaml"))
    outcome = execute(project, Path.cwd(), policy_name=policy_name, assume_yes=True)
    return {
        "schema_version": "2.0",
        "run_id": outcome.run_id,
        "passed": outcome.passed,
        "execution_status": outcome.execution_status,
        "policy_verdict": outcome.policy_verdict or ("pass" if outcome.passed else "fail"),
        "findings": len(outcome.findings),
        "run_dir": str(outcome.run_dir),
    }


def _findings(arguments: dict[str, object]) -> dict[str, object]:
    directory = _run_dir(_run_id(arguments))
    loaded = json.loads((directory / "findings.json").read_text())
    return {"run_id": directory.name, "findings": loaded}


def _report(arguments: dict[str, object]) -> dict[str, object]:
    directory = _run_dir(_run_id(arguments))
    return {"run_id": directory.name, "report": str(directory / "report.html")}


def _run_id(arguments: dict[str, object]) -> str | None:
    run_id = arguments.get("run_id")
    if run_id is None:
        return None
    if not isinstance(run_id, str) or Path(run_id).name != run_id or run_id in {".", ".."}:
        raise CliError("invalid run id")
    return run_id


def _run_dir(run_id: str | None) -> Path:
    root = Path.cwd()
    if run_id:
        directory = root / ".insidia" / "runs" / run_id
        if not directory.is_dir():
            raise CliError(f"no run {run_id}")
        return directory
    latest = latest_run(root)
    if latest is None:
        raise CliError("no runs yet")
    return latest


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CliError("params must be an object")
    return cast(dict[str, object], value)


def _tool_error(message: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _result(message_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _error(message_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


def _read(stdin: BinaryIO) -> dict[str, object] | None:
    headers: dict[str, str] = {}
    while True:
        line = stdin.readline()
        if line == b"":
            return None
        if line in {b"\r\n", b"\n"}:
            break
        decoded = line.decode()
        if ":" not in decoded:
            raise CliError("missing MCP header")
        key, value = decoded.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        raise CliError("missing Content-Length")
    loaded = json.loads(stdin.read(length))
    if not isinstance(loaded, dict):
        raise CliError("MCP message must be an object")
    return cast(dict[str, object], loaded)


def _write(stdout: BinaryIO, payload: dict[str, object]) -> None:
    raw = json.dumps(payload).encode()
    stdout.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    stdout.flush()


_TOOLS: tuple[dict[str, object], ...] = (
    {
        "name": "init",
        "description": "Write insidia.yaml with a localhost scope. Refuses to overwrite.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "doctor",
        "description": "Check Python, the config file, and optional engines.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "scan",
        "description": "Scan the hosts already listed in insidia.yaml. Does not accept a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy": {"type": "string", "enum": ["L1", "L2", "L3"]},
                "confirmed": {
                    "type": "boolean",
                    "description": "True only after the user names the hosts to test.",
                },
            },
            "required": ["confirmed"],
        },
    },
    {
        "name": "findings",
        "description": "Read findings.json for the latest run, or for run_id.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
        },
    },
    {
        "name": "report",
        "description": "Return the path of report.html for the latest run, or for run_id.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
        },
    },
)

_TOOL_CALLS = {
    "init": _init,
    "doctor": _doctor,
    "scan": _scan,
    "findings": _findings,
    "report": _report,
}

_METHODS = {
    "initialize": _initialize,
    "ping": _ping,
    "tools/list": _tools_list,
    "tools/call": _tools_call,
}
