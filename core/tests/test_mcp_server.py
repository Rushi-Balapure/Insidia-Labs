import json
from io import BytesIO
from pathlib import Path

from insidia.mcp import PROTOCOLS, dispatch, serve
from insidia.scan import ScanOutcome


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
    monkeypatch.setattr("insidia.mcp.load_project", lambda _path: object())  # type: ignore[attr-defined]
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
    (run / "findings.json").write_text("{bad")
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
