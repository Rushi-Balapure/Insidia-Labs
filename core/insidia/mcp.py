"""MCP server over stdio. Tools call the local CLI and never take a URL."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import BinaryIO, cast

from insidia import __version__
from insidia.config import init_config, load_project
from insidia.doctor import diagnose
from insidia.errors import CliError
from insidia.policy import POLICIES
from insidia.runstore import latest_run
from insidia.scan import execute
from insidia.scope import needs_confirmation

# Newest first. A client that asks for one of these gets it back. Any other
# request gets the newest, and the client decides whether to continue.
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
# One NDJSON line or one Content-Length body. Larger input is rejected.
_MAX_MESSAGE = 1024 * 1024
_TOO_LARGE = "message exceeds 1 MB"
# Set only by `insidia mcp --allow-remote`. The model cannot set this.
_allow_remote = False
_REMOTE_REFUSAL = (
    "non-local scope is refused over MCP; "
    "start the server with --allow-remote or INSIDIA_MCP_ALLOW_REMOTE=1"
)


def serve(stdin: BinaryIO, stdout: BinaryIO, allow_remote: bool = False) -> int:
    """Newline-delimited JSON-RPC, as the MCP stdio transport specifies.

    Content-Length framing from older clients is still read, and those
    clients get framed replies.
    """
    global _allow_remote
    previous = _allow_remote
    _allow_remote = allow_remote
    try:
        return _serve(stdin, stdout)
    finally:
        _allow_remote = previous


def _serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    while True:
        try:
            read = _read(stdin)
        except CliError as exc:
            _write(stdout, _error(None, -32700, str(exc)), framed=False)
            continue
        if read is None:
            return 0
        message, framed = read
        response = dispatch(message)
        if response is not None:
            _write(stdout, response, framed=framed)


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
    except Exception:
        # A corrupt run file or any other unexpected failure must not kill the
        # server, and the message must not echo file contents or secrets.
        return _error(message.get("id"), -32603, "internal error")
    return _result(message.get("id"), result)


def _initialize(params: object) -> dict[str, object]:
    requested = params.get("protocolVersion") if isinstance(params, dict) else None
    version = requested if requested in PROTOCOLS else PROTOCOLS[0]
    return {
        "protocolVersion": version,
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


def _remote_allowed() -> bool:
    """Human opt-in for a non-local scope. A tool argument cannot set this."""
    if _allow_remote:
        return True
    return os.environ.get("INSIDIA_MCP_ALLOW_REMOTE") == "1"


def _scan(arguments: dict[str, object]) -> dict[str, object]:
    if arguments.get("confirmed") is not True:
        raise CliError("scan requires confirmed true after the user names the hosts")
    policy = arguments.get("policy")
    if policy is not None and policy not in POLICIES:
        raise CliError(f"unknown policy {policy}")
    policy_name = policy if isinstance(policy, str) else None
    project = load_project(Path("insidia.yaml"))
    if needs_confirmation(project.scope) and not _remote_allowed():
        raise CliError(_REMOTE_REFUSAL)
    outcome = execute(project, Path.cwd(), policy_name=policy_name, assume_yes=True)
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "run_id": outcome.run_id,
        "passed": outcome.passed,
        "execution_status": outcome.execution_status,
        "policy_verdict": outcome.policy_verdict or ("pass" if outcome.passed else "fail"),
        "findings": len(outcome.findings),
        "run_dir": str(outcome.run_dir),
    }
    if outcome.notes:
        payload["notes"] = list(outcome.notes)
    return payload


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


def _read(stdin: BinaryIO) -> tuple[dict[str, object], bool] | None:
    """One message and whether it came Content-Length framed."""
    line = _read_line(stdin)
    while line is not None and line.strip() == b"":
        line = _read_line(stdin)
    if line is None:
        return None
    if line.lstrip().startswith(b"{"):
        return _decode(line), False
    headers: dict[str, str] = {}
    while line.strip():
        decoded = line.decode("utf-8", "replace")
        if ":" not in decoded:
            raise CliError("message is neither JSON nor an MCP header")
        key, value = decoded.split(":", 1)
        headers[key.strip().lower()] = value.strip()
        line = _read_line(stdin)
        if line is None:
            return None
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError as exc:
        raise CliError("Content-Length is not a number") from exc
    if length <= 0:
        raise CliError("missing Content-Length")
    if length > _MAX_MESSAGE:
        _discard(stdin, length)
        raise CliError(_TOO_LARGE)
    return _decode(stdin.read(length)), True


def _read_line(stdin: BinaryIO) -> bytes | None:
    """One line, or None at EOF before any byte. Lines over 1 MB are refused."""
    line = stdin.readline(_MAX_MESSAGE + 1)
    if line == b"":
        return None
    if len(line) <= _MAX_MESSAGE:
        return line
    if not line.endswith(b"\n"):
        _discard_line(stdin)
    raise CliError(_TOO_LARGE)


def _discard_line(stdin: BinaryIO) -> None:
    while True:
        chunk = stdin.readline(65536)
        if chunk == b"" or chunk.endswith(b"\n"):
            return


def _discard(stdin: BinaryIO, length: int) -> None:
    remaining = length
    while remaining > 0:
        chunk = stdin.read(min(65536, remaining))
        if not chunk:
            return
        remaining -= len(chunk)


def _decode(raw: bytes) -> dict[str, object]:
    try:
        loaded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("message is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise CliError("MCP message must be an object")
    return cast(dict[str, object], loaded)


def _write(stdout: BinaryIO, payload: dict[str, object], framed: bool) -> None:
    raw = json.dumps(payload).encode()
    if framed:
        stdout.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    else:
        stdout.write(raw + b"\n")
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
        "description": (
            "Scan the hosts already listed in insidia.yaml. Does not accept a URL. "
            "Localhost scope only, unless the server was started with --allow-remote "
            "or INSIDIA_MCP_ALLOW_REMOTE=1."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy": {"type": "string", "enum": ["L1", "L2", "L3"]},
                "confirmed": {
                    "type": "boolean",
                    "description": (
                        "True only after the user names the hosts to test. "
                        "This does not authorize a non-local scope."
                    ),
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
