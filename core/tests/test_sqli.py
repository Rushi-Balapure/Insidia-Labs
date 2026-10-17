"""SQL injection is caught on a concatenated query and quiet on a parameterised one."""

import json
import sqlite3
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from insidia.cli import main
from insidia.policy import get_policy

_ROWS = (("ada", "one"), ("grace", "two"), ("linus", "three"))
Reply = Callable[[str], tuple[int, str]]


def _database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE accounts (name TEXT, note TEXT)")
    connection.executemany("INSERT INTO accounts VALUES (?, ?)", _ROWS)
    return connection


def _concatenated(query: str) -> tuple[int, str]:
    connection = _database()
    try:
        found = connection.execute(
            f"SELECT name, note FROM accounts WHERE name = '{query}'"
        ).fetchall()
    except sqlite3.Error as exc:
        return 500, f"sqlite3.OperationalError: {exc}"
    return 200, json.dumps([{"name": name, "note": note} for name, note in found])


def _boolean_only(query: str) -> tuple[int, str]:
    """The same concatenated query, with the database error hidden."""
    status, body = _concatenated(query)
    if status >= 400:
        return 200, "[]"
    return status, body


def _error_only(query: str) -> tuple[int, str]:
    """A quote raises. A successful injection still returns one fixed row."""
    connection = _database()
    try:
        connection.execute(f"SELECT name, note FROM accounts WHERE name = '{query}'").fetchall()
    except sqlite3.Error as exc:
        return 500, f"sqlite3.OperationalError: {exc}"
    return 200, json.dumps([{"name": "ada", "note": "one"}])


def _parameterised(query: str) -> tuple[int, str]:
    if not query.isalnum():
        return 400, "bad query"
    connection = _database()
    found = connection.execute(
        "SELECT name, note FROM accounts WHERE name = ?", (query,)
    ).fetchall()
    return 200, json.dumps([{"name": name, "note": note} for name, note in found])


def _always_error(query: str) -> tuple[int, str]:
    del query
    return 200, "syntax error near the search box"


@pytest.fixture
def search_app() -> Iterator[Callable[[Reply], int]]:
    reply: dict[str, Reply] = {"fn": _parameterised}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query).get("q", [""])[0]
            status, body = reply["fn"](query)
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def use(fn: Reply) -> int:
        reply["fn"] = fn
        return int(server.server_address[1])

    yield use
    server.shutdown()
    server.server_close()


def _scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, port: int
) -> tuple[int, list[dict[str, object]]]:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  search:
    kind: api
    url: http://127.0.0.1:{port}/v1/accounts
    method: GET
    query:
      q: "{{{{payload}}}}"
"""
    )
    code = main(["scan", "--config", str(config), "--quiet"])
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    findings = json.loads((latest / "findings.json").read_text())
    return code, findings


def test_sqli_control_names_injection() -> None:
    control = get_policy("L1").control("web.sqli")
    assert control.kinds == ("web", "api")
    assert "owasp-web:A03" in control.taxonomy
    assert "CWE-89" in control.remediation


@pytest.mark.parametrize("vulnerable", [_concatenated, _boolean_only, _error_only])
def test_sqli_is_caught_on_a_concatenated_query(
    vulnerable: Reply,
    search_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, findings = _scan(tmp_path, monkeypatch, search_app(vulnerable))
    sqli = [item for item in findings if item["attack"] == "web.sqli"]
    assert code == 1
    assert sqli
    assert {item["engine"] for item in sqli} == {"insidia"}
    assert "CWE-89" in str(sqli[0]["remediation"])


def test_sqli_is_clean_on_a_parameterised_query(
    search_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, findings = _scan(tmp_path, monkeypatch, search_app(_parameterised))
    assert code == 0
    assert [item for item in findings if item["attack"] == "web.sqli"] == []


def test_sqli_error_on_the_baseline_is_not_a_finding(
    search_app: Callable[[Reply], int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code, findings = _scan(tmp_path, monkeypatch, search_app(_always_error))
    assert code == 0
    assert findings == []
