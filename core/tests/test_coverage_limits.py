"""Payload reach, engine credit, and fixture-only request cost."""

import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from insidia.cli import main
from insidia.probes import Attempt, ProbeHit
from insidia.registry import Capability
from insidia.scan import run as real_run
from insidia.scan import select as real_select
from insidia.transport import carries_payload
from tests.support import target

_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
_NO_PAYLOAD = "no {{payload}} placeholder"


def test_carries_payload_follows_the_request_builder() -> None:
    get = target(kind="web", url="http://127.0.0.1/api/users/1", method="GET")
    assert carries_payload(get) is False
    assert carries_payload(replace(get, url="http://127.0.0.1/users/{{payload}}")) is True
    assert carries_payload(replace(get, url="http://127.0.0.1/users?id={{payload}}")) is True
    assert carries_payload(replace(get, query={"id": "{{payload}}"})) is True
    assert carries_payload(replace(get, query={"q": "{{prompt}}"})) is True
    # The path filler only substitutes {{payload}}, not {{prompt}}.
    assert carries_payload(replace(get, url="http://127.0.0.1/chat/{{prompt}}")) is False
    posted = replace(get, method="POST")
    assert carries_payload(posted) is True
    assert carries_payload(replace(posted, request_template='{"message": "fixed"}')) is False
    assert carries_payload(replace(posted, request_template='{"message": {{prompt_json}}}')) is True
    assert (
        carries_payload(replace(posted, request_template='{"messages": {{conversation_json}}}'))
        is True
    )
    assert carries_payload(replace(get, url="ws://127.0.0.1/chat")) is True


class _Recorder:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []


@contextmanager
def _serve(
    recorder: _Recorder, body_for: Callable[[str, bytes], tuple[int, str]]
) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            _reply(self, b"")

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            _reply(self, self.rfile.read(length))

        def log_message(self, fmt: str, *args: object) -> None:
            return

    def _reply(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        recorder.requests.append((handler.command, handler.path, body))
        status, payload = body_for(handler.path, body)
        raw = payload.encode()
        handler.send_response(status)
        handler.send_header("Server", "Apache/2.4.49 (Unix)")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _web_answer(path: str, body: bytes) -> tuple[int, str]:
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    value = next(iter(query.values()), [""])[0]
    if not value and body:
        try:
            loaded = json.loads(body)
        except json.JSONDecodeError:
            loaded = {}
        if isinstance(loaded, dict):
            prompt = loaded.get("prompt", "")
            value = prompt if isinstance(prompt, str) else ""
    if parsed.path == "/ping" and any(mark in value for mark in (";", "|", "$(", "`")):
        return 200, f"uid=1000(app) gid=1000(app) groups=1000(app)\n{value}"
    if parsed.path == "/file" and ("../" in value or value.startswith("/etc")):
        return 200, _PASSWD
    if parsed.path.startswith("/users/"):
        user_id = parsed.path.removeprefix("/users/")
        if user_id == "2":
            return 200, json.dumps(
                {"id": 2, "name": "grace", "email": "g@example.com", "role": "admin"}
            )
        return 200, json.dumps({"id": 1, "name": "ada", "email": "a@example.com", "role": "user"})
    return 200, "ok"


def _scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> tuple[int, dict[str, object]]:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(text)
    code = main(["scan", "--config", str(config), "--quiet"])
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    benchmark = json.loads((latest / "benchmark.json").read_text())
    findings = json.loads((latest / "findings.json").read_text())
    benchmark["finding_attacks"] = {item["attack"] for item in findings}
    return code, benchmark


def _rows(benchmark: dict[str, object], family: str) -> list[dict[str, str]]:
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    return [row for row in controls if isinstance(row, dict) and row.get("id") == family]


def test_get_without_a_placeholder_does_not_pass_injection_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()
    with _serve(recorder, _web_answer) as port:
        code, benchmark = _scan(
            tmp_path,
            monkeypatch,
            f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  users:
    kind: web
    url: http://127.0.0.1:{port}/api/users/1
    method: GET
    rate_limit:
      rps: 100
      concurrency: 1
""",
        )
    assert code == 1
    for family in ("web.ssti", "web.cmdi", "web.path_lfi", "api.bola_idor"):
        rows = _rows(benchmark, family)
        assert rows and {row["result"] for row in rows} == {"not tested"}
        assert all(_NO_PAYLOAD in row["reason"] for row in rows)
    cve = _rows(benchmark, "infra.cve")
    assert {row["result"] for row in cve} == {"fail"}
    assert "infra.cve" in benchmark["finding_attacks"]
    assert len(recorder.requests) <= 6


def test_the_same_route_with_a_placeholder_still_finds_the_bug(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()
    with _serve(recorder, _web_answer) as port:
        code, benchmark = _scan(
            tmp_path,
            monkeypatch,
            f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  ping:
    kind: web
    url: http://127.0.0.1:{port}/ping
    method: GET
    query:
      host: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  users:
    kind: api
    url: http://127.0.0.1:{port}/users/{{{{payload}}}}
    method: GET
    rate_limit:
      rps: 100
      concurrency: 1
""",
        )
    assert code == 1
    attacks = benchmark["finding_attacks"]
    assert isinstance(attacks, set)
    assert {"web.cmdi", "api.bola_idor"} <= attacks
    cmdi = _rows(benchmark, "web.cmdi")
    assert any(row["target"] == "ping" and row["result"] == "fail" for row in cmdi)


def test_post_without_a_template_still_carries_the_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()
    with _serve(recorder, _web_answer) as port:
        code, benchmark = _scan(
            tmp_path,
            monkeypatch,
            f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  ping:
    kind: web
    url: http://127.0.0.1:{port}/ping
    method: POST
    rate_limit:
      rps: 100
      concurrency: 1
""",
        )
    assert code == 1
    assert "web.cmdi" in benchmark["finding_attacks"]


def test_ai_template_without_a_prompt_placeholder_is_not_tested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        _code, benchmark = _scan(
            tmp_path,
            monkeypatch,
            f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  bot:
    kind: chat
    url: http://127.0.0.1:{port}/chat
    request_template: '{{"message": "hello"}}'
    rate_limit:
      rps: 100
      concurrency: 1
""",
        )
    rows = _rows(benchmark, "ai.data_leakage")
    assert rows and {row["result"] for row in rows} == {"not tested"}
    assert all(_NO_PAYLOAD in row["reason"] for row in rows)
    # Preflight still checks the endpoint. The probes themselves do not.
    assert len(recorder.requests) == 1


def _garak_hit() -> ProbeHit:
    return ProbeHit(
        "bot",
        "ai.data_leakage",
        "garak",
        "garak.ai.data_leakage",
        "secret",
        "high",
        "high",
        "ai",
        ("owasp-llm:LLM02",),
        "Stop returning secrets.",
    )


def _install_shallow_garak(monkeypatch: pytest.MonkeyPatch, finding: bool) -> None:
    def fake_select(
        family: str,
        coverage: str,
        model_available: bool = False,
        entries: tuple[Capability, ...] | None = None,
    ) -> list[Capability]:
        chosen = real_select(
            family, coverage, model_available=model_available, entries=entries
        )
        if family == "ai.data_leakage":
            chosen.append(
                Capability(family, "garak", "garak.ai.data_leakage", 50, False, True)
            )
        return chosen

    def fake_run(adapter: object, spec: object, *args: object, **kwargs: object) -> Attempt:
        if getattr(adapter, "engine", "") == "garak":
            hits = (_garak_hit(),) if finding else ()
            return Attempt(hits, untested="garak sent only 1 prompt(s)")
        return real_run(adapter, spec, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("insidia.scan.select", fake_select)
    monkeypatch.setattr("insidia.scan.run", fake_run)


def _chat_config(port: int) -> str:
    return f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  bot:
    kind: chat
    url: http://127.0.0.1:{port}/chat
    rate_limit:
      rps: 100
      concurrency: 1
"""


def _result_line(err: str, family: str, label: str) -> str:
    matched = [line for line in err.splitlines() if family in line and label in line]
    assert len(matched) == 1, err
    return matched[0]


def test_a_limited_relay_is_not_credited_for_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    _install_shallow_garak(monkeypatch, finding=False)
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        config = tmp_path / "insidia.yaml"
        config.write_text(_chat_config(port))
        code = main(
            ["scan", "--config", str(config), "--coverage", "thorough", "--yes"]
        )
    err = capsys.readouterr().err
    line = _result_line(err, "ai.data_leakage", "pass")
    assert "insidia" in line
    assert "garak" not in line
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    report = (latest / "report.html").read_text()
    findings = json.loads((latest / "findings.json").read_text())
    assert "garak" not in report
    assert all("garak" not in item["engines"] for item in findings)
    assert code == 0


def test_a_limited_relay_that_found_a_bug_is_still_credited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    _install_shallow_garak(monkeypatch, finding=True)
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        config = tmp_path / "insidia.yaml"
        config.write_text(_chat_config(port))
        code = main(
            ["scan", "--config", str(config), "--coverage", "thorough", "--yes"]
        )
    err = capsys.readouterr().err
    line = _result_line(err, "ai.data_leakage", "FAIL")
    assert "garak" in line
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    report = (latest / "report.html").read_text()
    findings = json.loads((latest / "findings.json").read_text())
    leak = next(item for item in findings if item["attack"] == "ai.data_leakage")
    assert "garak" in leak["engines"]
    assert "garak" in report
    assert code == 1


def _sent_payloads(recorder: _Recorder) -> list[str]:
    sent: list[str] = []
    for _method, path, body in recorder.requests:
        for values in parse_qs(urlparse(path).query).values():
            sent.extend(values)
        if not body:
            continue
        try:
            loaded = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict) and isinstance(loaded.get("prompt"), str):
            sent.append(loaded["prompt"])
    return sent


def test_fixture_only_families_send_one_request_to_a_real_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        _scan(
            tmp_path,
            monkeypatch,
            f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  ping:
    kind: web
    url: http://127.0.0.1:{port}/ping
    method: GET
    query:
      host: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  bot:
    kind: agent
    url: http://127.0.0.1:{port}/chat
    rate_limit:
      rps: 100
      concurrency: 1
""",
        )
    sent = _sent_payloads(recorder)
    assert sent.count("pickle:blob") == 0
    assert sent.count("pickle") == 1
    assert sent.count("insidia-memory-next") == 0
    assert sent.count("insidia-memory-plant") == 1
    assert sent.count("make a bomb") == 1
    assert sent.count("group") == 1
