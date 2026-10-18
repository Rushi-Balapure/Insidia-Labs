import hashlib
import json
from io import BytesIO
from pathlib import Path

from insidia.mcp import _MAX_MESSAGE, PROTOCOLS, dispatch, serve
from insidia.runstore import latest_run
from insidia.scan import ScanOutcome
from insidia.scope import ScopeHost


def test_initialize_and_list_tools() -> None:
    listed = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == ["init", "doctor", "scan", "findings", "report"]
    started = dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert started is not None
    assert started["result"]["serverInfo"]["name"] == "insidia"
    assert dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_scan_refuses_until_the_user_confirms(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]

    def explode(*_args: object, **_kwargs: object) -> ScanOutcome:
        raise AssertionError("scan should not run")

    monkeypatch.setattr("insidia.mcp.execute", explode)  # type: ignore[attr-defined]
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"confirmed": False}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True


def test_scan_runs_only_the_project_file(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    (tmp_path / "insidia.yaml").write_text("version: 1\n")
    seen: dict[str, object] = {}

    def fake_execute(*_args: object, **kwargs: object) -> ScanOutcome:
        seen.update(kwargs)
        return ScanOutcome("run-1", tmp_path / "run", True, [], [])

    monkeypatch.setattr("insidia.mcp.execute", fake_execute)  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "insidia.mcp.load_project",
        lambda _path: _project((ScopeHost("127.0.0.1", False),)),
    )  # type: ignore[attr-defined]
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"confirmed": True, "policy": "L1"}},
        }
    )
    assert response is not None
    body = json.loads(response["result"]["content"][0]["text"])
    assert body["run_id"] == "run-1"
    assert seen["assume_yes"] is True
    assert seen["policy_name"] == "L1"


def test_scan_refuses_non_local_scope_without_a_human_switch(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    (tmp_path / "insidia.yaml").write_text("version: 1\n")
    remote = (ScopeHost("::ffff:127.0.0.1", True),)

    def explode(*_args: object, **_kwargs: object) -> ScanOutcome:
        raise AssertionError("scan should not run")

    monkeypatch.setattr("insidia.mcp.execute", explode)  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "insidia.mcp.load_project", lambda _path: _project(remote)
    )  # type: ignore[attr-defined]
    response = _scan_call()
    assert response is not None
    assert response["result"]["isError"] is True
    assert "INSIDIA_MCP_ALLOW_REMOTE" in response["result"]["content"][0]["text"]

    monkeypatch.setenv("INSIDIA_MCP_ALLOW_REMOTE", "1")  # type: ignore[attr-defined]
    seen: dict[str, object] = {}

    def fake_execute(*_args: object, **kwargs: object) -> ScanOutcome:
        seen.update(kwargs)
        return ScanOutcome("run-1", tmp_path / "run", True, [], [])

    monkeypatch.setattr("insidia.mcp.execute", fake_execute)  # type: ignore[attr-defined]
    allowed = _scan_call()
    assert allowed is not None
    assert allowed["result"]["isError"] is False
    assert seen["assume_yes"] is True

    monkeypatch.delenv("INSIDIA_MCP_ALLOW_REMOTE", raising=False)  # type: ignore[attr-defined]
    monkeypatch.setattr("insidia.mcp._allow_remote", True)  # type: ignore[attr-defined]
    flagged = _scan_call()
    assert flagged is not None
    assert flagged["result"]["isError"] is False


def _project(scope: tuple[ScopeHost, ...]) -> object:
    class _Loaded:
        pass

    loaded = _Loaded()
    loaded.scope = scope  # type: ignore[attr-defined]
    return loaded


def _scan_call() -> dict[str, object] | None:
    return dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"confirmed": True, "policy": "L1"}},
        }
    )


def test_init_writes_localhost_scope(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    response = dispatch(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "init"}}
    )
    assert response is not None
    text = (tmp_path / "insidia.yaml").read_text()
    assert "host: localhost" in text
    assert "authorized:" not in text


def test_newline_delimited_round_trip() -> None:
    lines = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    stdin = BytesIO(b"".join(json.dumps(line).encode() + b"\n" for line in lines))
    stdout = BytesIO()
    assert serve(stdin, stdout) == 0
    replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [reply["id"] for reply in replies] == [1, 2]
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert b"Content-Length" not in stdout.getvalue()


def test_initialize_negotiates_the_protocol_version() -> None:
    for asked, expected in (
        ("2024-11-05", "2024-11-05"),
        ("2025-03-26", "2025-03-26"),
        ("2099-01-01", PROTOCOLS[0]),
    ):
        started = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": asked},
            }
        )
        assert started is not None
        assert started["result"]["protocolVersion"] == expected


def test_bad_json_line_gets_a_parse_error_and_the_server_keeps_going() -> None:
    ping = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode()
    stdin = BytesIO(b"{not json\n" + ping + b"\n")
    stdout = BytesIO()
    assert serve(stdin, stdout) == 0
    first, second = (json.loads(line) for line in stdout.getvalue().splitlines())
    assert first["error"]["code"] == -32700
    assert second["id"] == 7


def test_corrupt_findings_is_an_error_and_the_next_call_is_answered(
    tmp_path: Path, monkeypatch: object, capsys: object
) -> None:
    """The crash input from the security sweep: bad findings.json, then ping."""
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    run = tmp_path / ".insidia" / "runs" / "r1"
    run.mkdir(parents=True)
    raw = b"{bad"
    (run / "findings.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (run / "manifest.json").write_text(json.dumps({"files": {"findings.json": digest}}))
    crash = (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"findings","arguments":{"run_id":"r1"}}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    )
    stdin = BytesIO(crash.encode())
    stdout = BytesIO()
    assert serve(stdin, stdout) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    written = stdout.getvalue()
    assert b"Traceback" not in written
    assert b"{bad" not in written
    first, second = (json.loads(line) for line in written.splitlines())
    assert first["id"] == 1
    assert first["error"]["code"] == -32603
    assert first["error"]["message"] == "internal error"
    assert second["id"] == 2
    assert second["result"] == {}


def test_an_oversized_line_is_rejected_and_the_next_call_is_answered() -> None:
    ping = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode() + b"\n"
    huge = b"{" + (b"a" * _MAX_MESSAGE) + b"\n"
    stdout = BytesIO()
    assert serve(BytesIO(huge + ping), stdout) == 0
    first, second = (json.loads(line) for line in stdout.getvalue().splitlines())
    assert first["error"]["code"] == -32700
    assert first["error"]["message"] == "message exceeds 1 MB"
    assert second["id"] == 2
    assert second["result"] == {}


def test_an_oversized_content_length_is_skipped() -> None:
    body = b"x" * (_MAX_MESSAGE + 8)
    framed = f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    ping = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}).encode()
    follow = f"Content-Length: {len(ping)}\r\n\r\n".encode() + ping
    stdout = BytesIO()
    assert serve(BytesIO(framed + follow), stdout) == 0
    error_line, rest = stdout.getvalue().split(b"\n", 1)
    error = json.loads(error_line)
    assert error["error"]["code"] == -32700
    assert error["error"]["message"] == "message exceeds 1 MB"
    header, payload = rest.split(b"\r\n\r\n", 1)
    assert header.startswith(b"Content-Length:")
    assert json.loads(payload)["id"] == 9


def test_symlinked_run_dir_and_findings_are_refused(
    tmp_path: Path, monkeypatch: object
) -> None:
    """A later symlink must not win, and a linked findings file must not be read."""
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    runs = tmp_path / ".insidia" / "runs"
    runs.mkdir(parents=True)
    outside = tmp_path / "outside-store"
    outside.mkdir()
    marker = "planted-marker-not-a-secret"
    (outside / "findings.json").write_text(json.dumps([{"detail": marker}]))
    (outside / "report.html").write_text(marker)

    link = runs / "20990101T000000Z-link"
    link.symlink_to(outside, target_is_directory=True)
    assert latest_run(tmp_path) is None
    for name, arguments in (
        ("findings", {}),
        ("findings", {"run_id": link.name}),
        ("report", {"run_id": link.name}),
    ):
        refused = _tool(name, arguments)
        assert refused is not None
        assert refused["result"]["isError"] is True
        blob = json.dumps(refused)
        assert marker not in blob
        assert "outside-store" not in blob

    real = runs / "20260101T000000Z-real"
    real.mkdir()
    (real / "findings.json").write_text(json.dumps([{"id": "kept"}]))
    _seal(real)
    assert latest_run(tmp_path) == real
    latest = _tool("findings", {})
    assert latest is not None
    assert latest["result"]["isError"] is False
    body = json.loads(latest["result"]["content"][0]["text"])
    assert body["run_id"] == real.name
    assert body["findings"] == [{"id": "kept"}]
    assert marker not in json.dumps(latest)

    stolen = runs / "20260102T000000Z-file"
    stolen.mkdir()
    (stolen / "findings.json").symlink_to(outside / "findings.json")
    (stolen / "manifest.json").write_text(
        json.dumps({"files": {"findings.json": "0" * 64}})
    )
    file_link = _tool("findings", {"run_id": stolen.name})
    assert file_link is not None
    assert file_link["result"]["isError"] is True
    assert marker not in json.dumps(file_link)
    assert "outside-store" not in json.dumps(file_link)


def _tool(name: str, arguments: dict[str, object]) -> dict[str, object] | None:
    return dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )


def _seal(directory: Path) -> None:
    raw = (directory / "findings.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    (directory / "manifest.json").write_text(json.dumps({"files": {"findings.json": digest}}))


def test_stdio_round_trip() -> None:
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    stdin = BytesIO(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
    stdout = BytesIO()
    assert serve(stdin, stdout) == 0
    written = stdout.getvalue()
    header, body = written.split(b"\r\n\r\n", 1)
    assert header.startswith(b"Content-Length:")
    payload = json.loads(body)
    assert payload["result"] == {}
