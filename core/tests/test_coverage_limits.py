"""Payload reach, engine credit, and fixture-only request cost."""

import json
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from insidia.adapters import BUILT_IN, Invocation, ProbeSpec, RelayAdapter, RelayEndpoint
from insidia.cli import main
from insidia.config import Project
from insidia.errors import ProbeError
from insidia.policy import POLICIES
from insidia.probes import (
    _FIXTURE_ONLY_NOTE,
    _FIXTURE_ONLY_TIMEOUT,
    _JUDGE_UNUSED_NOTE,
    _RELAY_MIN_PROMPTS,
    Attempt,
    ProbeHit,
    _judge,
)
from insidia.probes import run as probe_run
from insidia.registry import Capability
from insidia.scan import run as real_run
from insidia.scan import select as real_select
from insidia.scope import ScopeHost
from insidia.transport import carries_payload
from tests.support import target

_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
_NO_PAYLOAD = "no {{payload}} placeholder"
_REAL_CHECKS = ("ai.data_leakage", "web.ssti", "web.sqli", "web.cmdi")
_LOCAL = (ScopeHost("127.0.0.1", False),)


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
        assert all(_NO_PAYLOAD in row["detail"] for row in rows)
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
    assert all(_NO_PAYLOAD in row["detail"] for row in rows)
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


def _install_garak(
    monkeypatch: pytest.MonkeyPatch, finding: bool, *, shallow: bool = True
) -> None:
    def fake_select(
        family: str,
        coverage: str,
        model_available: bool = False,
        entries: tuple[Capability, ...] | None = None,
    ) -> list[Capability]:
        chosen = real_select(family, coverage, model_available=model_available, entries=entries)
        if family == "ai.data_leakage":
            chosen.append(Capability(family, "garak", "garak.ai.data_leakage", 50, False, True))
        return chosen

    def fake_run(adapter: object, spec: object, *args: object, **kwargs: object) -> Attempt:
        if getattr(adapter, "engine", "") == "garak":
            hits = (_garak_hit(),) if finding else ()
            note = "garak sent only 1 prompt(s)" if shallow else ""
            return Attempt(hits, untested=note)
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
    _install_garak(monkeypatch, finding=False)
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
    assert "garak sent only 1 prompt" in line
    assert "insidia, garak" not in line
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    report = (latest / "report.html").read_text()
    findings = json.loads((latest / "findings.json").read_text())
    benchmark = json.loads((latest / "benchmark.json").read_text())
    rows = _rows(benchmark, "ai.data_leakage")
    assert rows and all("garak sent only 1 prompt" in row["detail"] for row in rows)
    assert "garak sent only 1 prompt" in report
    assert all("garak" not in item["engines"] for item in findings)
    assert code == 0


def test_a_one_prompt_hit_does_not_credit_garak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    _install_garak(monkeypatch, finding=True)
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        config = tmp_path / "insidia.yaml"
        config.write_text(_chat_config(port))
        code = main(["scan", "--config", str(config), "--coverage", "thorough", "--yes"])
    err = capsys.readouterr().err
    line = _result_line(err, "ai.data_leakage", "FAIL")
    assert "garak sent only 1 prompt" in line
    assert "insidia, garak" not in line
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    report = (latest / "report.html").read_text()
    findings = json.loads((latest / "findings.json").read_text())
    benchmark = json.loads((latest / "benchmark.json").read_text())
    rows = _rows(benchmark, "ai.data_leakage")
    assert any(
        row["result"] == "fail" and "garak sent only 1 prompt" in row["detail"] for row in rows
    )
    assert "garak sent only 1 prompt" in report
    assert all("garak" not in item["engines"] for item in findings)
    assert all(item["attack"] != "ai.data_leakage" for item in findings)
    assert code == 1


def test_a_relay_at_the_minimum_is_credited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    _install_garak(monkeypatch, finding=True, shallow=False)
    recorder = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    with _serve(recorder, answer) as port:
        config = tmp_path / "insidia.yaml"
        config.write_text(_chat_config(port))
        code = main(["scan", "--config", str(config), "--coverage", "thorough", "--yes"])
    err = capsys.readouterr().err
    line = _result_line(err, "ai.data_leakage", "FAIL")
    assert "garak" in line
    assert "sent only" not in line
    runs = tmp_path / ".insidia" / "runs"
    latest = max(runs.iterdir(), key=lambda path: path.name)
    findings = json.loads((latest / "findings.json").read_text())
    leak = next(item for item in findings if item["attack"] == "ai.data_leakage")
    assert leak["engines"] == ["garak"]
    assert leak["reported_by"] == 1
    assert code == 1


def test_a_relay_hit_keeps_the_shallow_note_until_the_minimum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def exchange(app: object, payload: str, scope: object, root: object) -> str:
        del app, payload, scope, root
        return "insidia-plant-canary-7f3a"

    monkeypatch.setattr("insidia.probes.exchange", exchange)
    one = _relay_attempt(tmp_path, 1)
    assert one.hits
    assert one.untested == "garak sent only 1 prompt(s)"
    covered = _relay_attempt(tmp_path, _RELAY_MIN_PROMPTS)
    assert covered.hits
    assert covered.untested == ""


def _relay_attempt(tmp_path: Path, prompts: int) -> Attempt:
    holder: list[RelayEndpoint] = []

    def prepare(spec: ProbeSpec, endpoint: RelayEndpoint, workspace: Path) -> Invocation:
        del spec, workspace
        holder.append(endpoint)
        return Invocation("garak", (), "unused.json")

    def launch(invocation: Invocation, workspace: Path) -> None:
        del invocation, workspace
        endpoint = holder[0]
        for index in range(prompts):
            body = json.dumps({"prompt": f"probe-{index}"}).encode()
            request = urllib.request.Request(
                endpoint.url,
                data=body,
                headers={
                    "Authorization": f"Bearer {endpoint.token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200

    spec = ProbeSpec("garak.ai.data_leakage", "test.Blank", "ai.data_leakage", 50, False, ("chat",))
    adapter = RelayAdapter("garak", "Apache-2.0", (spec,), prepare)
    project = Project(tmp_path / "insidia.yaml", 1, "L1", "standard", _LOCAL, (), None, None)
    bot = target(kind="chat", url="http://127.0.0.1/chat")
    return probe_run(
        adapter,
        spec,
        bot,
        project,
        tmp_path,
        POLICIES["L1"].control("ai.data_leakage"),
        launch,
    )


def _sent_payloads(recorder: _Recorder) -> list[str]:
    return _query_values(recorder) + _prompts(recorder)


def _query_values(recorder: _Recorder) -> list[str]:
    sent: list[str] = []
    for _method, path, _body in recorder.requests:
        for values in parse_qs(urlparse(path).query).values():
            sent.extend(values)
    return sent


def _prompts(recorder: _Recorder) -> list[str]:
    sent: list[str] = []
    for _method, _path, body in recorder.requests:
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
    judge = _Recorder()

    def answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 200, "ok"

    def judge_answer(path: str, body: bytes) -> tuple[int, str]:
        del path, body
        return 500, "judge should not be called"

    monkeypatch.setenv("INSIDIA_JUDGE_KEY", "qa-dummy-not-a-key")
    with _serve(recorder, answer) as port, _serve(judge, judge_answer) as judge_port:
        _code, benchmark = _scan(
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
models:
  judge:
    provider: openai-compatible
    base_url: http://127.0.0.1:{judge_port}/v1
    model: dummy
    secret_ref: env:INSIDIA_JUDGE_KEY
""",
        )
    sent = _sent_payloads(recorder)
    assert sent.count("pickle:blob") == 0
    assert sent.count("pickle") == 1
    assert sent.count("insidia-memory-next") == 0
    assert sent.count("insidia-memory-plant") == 1
    assert sent.count("make a bomb") == 1
    assert sent.count("group") == 1
    assert judge.requests == []
    for family in ("ai.harmful_content_policy", "ai.bias"):
        rows = _rows(benchmark, family)
        assert rows and {row["result"] for row in rows} == {"not tested"}
        assert all(row["detail"] == _JUDGE_UNUSED_NOTE for row in rows)
    rows = _rows(benchmark, "web.deserialization")
    assert rows and {row["result"] for row in rows} == {"not tested"}
    assert all(_FIXTURE_ONLY_NOTE in row["detail"] for row in rows)
    for family in _REAL_CHECKS:
        rows = _rows(benchmark, family)
        assert rows and "not tested" not in {row["result"] for row in rows}

    # The stub blocks for whatever timeout it is given. A 30s target must be capped.
    slow = replace(target(kind="web", url="http://127.0.0.1/ping", method="GET"), timeout=30)
    spec = next(item for item in BUILT_IN.probes if item.family == "web.deserialization")
    seen: list[tuple[str, float]] = []

    def blocked(app: object, payload: str, scope: object, root: object) -> str:
        del scope, root
        given = float(app.timeout)
        seen.append((payload, given))
        if given != _FIXTURE_ONLY_TIMEOUT:
            raise AssertionError(f"fixture probe used the target timeout {given}")
        raise ProbeError("target timed out")

    monkeypatch.setattr("insidia.probes.exchange", blocked)
    started = time.monotonic()
    hits, error, note = _judge(BUILT_IN, spec, slow, _LOCAL, tmp_path)
    assert time.monotonic() - started < 2
    assert seen == [("pickle", _FIXTURE_ONLY_TIMEOUT)]
    assert hits == []
    assert error == ""
    assert note == _FIXTURE_ONLY_NOTE

    plant = next(item for item in BUILT_IN.probes if item.family == "ai.harmful_content_policy")
    bot = replace(target(kind="agent", url="http://127.0.0.1/chat"), timeout=30)

    def matched(app: object, payload: str, scope: object, root: object) -> str:
        del scope, root
        assert float(app.timeout) == _FIXTURE_ONLY_TIMEOUT
        return f"unreviewed: {payload}"

    monkeypatch.setattr("insidia.probes.exchange", matched)
    hits, error, note = _judge(BUILT_IN, plant, bot, _LOCAL, tmp_path)
    assert error == ""
    assert note == _JUDGE_UNUSED_NOTE
    assert len(hits) == 1
    cited = next(item for item in BUILT_IN.probes if item.family == "ai.citation_groundedness")
    rag = replace(target(kind="rag", url="http://127.0.0.1/rag"), timeout=30)
    hits, error, note = _judge(BUILT_IN, cited, rag, _LOCAL, tmp_path)
    assert error == ""
    assert note == _JUDGE_UNUSED_NOTE
    project = Project(tmp_path / "insidia.yaml", 1, "L1", "standard", _LOCAL, (), None, None)
    attempt = probe_run(
        BUILT_IN,
        plant,
        bot,
        project,
        tmp_path,
        POLICIES["L1"].control(plant.family),
    )
    assert attempt.hits
    assert attempt.error == ""
    assert attempt.untested == ""
