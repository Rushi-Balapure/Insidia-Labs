import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import (
    ADAPTERS,
    BUILT_IN,
    ORACLES,
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RelayEndpoint,
    ReportAdapter,
    ScopedUrl,
    find,
)
from insidia.config import Project
from insidia.errors import ScopeError
from insidia.findings import normalize
from insidia.policy import get_policy
from insidia.probes import ProbeHit, run
from insidia.registry import capabilities
from insidia.scope import ScopeHost, hostname
from tests.support import target

LOCAL = (ScopeHost("127.0.0.1", False),)
SSTI = ProbeSpec("fixture.web.ssti", "insidia-ssti-arith", "web.ssti", 50, False, ("web", "api"))
RECORDED = {
    "template-id": "insidia-ssti-arith",
    "engine": "someone-else",
    "request": "GET /call?q=%7B%7B7*7%7D%7D",
    "response": "HTTP/1.1 200 OK\r\n\r\nhello 49",
    "extracted-results": ["49"],
}


def _project(scope: tuple[ScopeHost, ...] = LOCAL) -> Project:
    return Project(Path("insidia.yaml"), 1, "L1", "standard", scope, (), None, None)


def _prepare(spec: ProbeSpec, view: ScopedUrl, workspace: Path) -> Invocation:
    report = "report.jsonl"
    args = ("-u", view.url, "-id", spec.upstream, "-jsonl", "-o", str(workspace / report))
    return Invocation("nuclei", args, report)


def _parse(report: Path, spec: ProbeSpec) -> list[EngineHit]:
    rows = [json.loads(line) for line in report.read_text().splitlines()]
    return [
        EngineHit(row["template-id"], row["request"], row["response"], row["extracted-results"][0])
        for row in rows
    ]


REPORT_ENGINE = ReportAdapter(
    engine="fixture-nuclei",
    license="MIT",
    probes=(SSTI,),
    view=ScopedUrl,
    prepare=_prepare,
    parse=_parse,
)


def _relay_prepare(spec: ProbeSpec, endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    config = f"--generator_option_url={endpoint.url}"
    return Invocation("garak", ("--probes", spec.upstream, config), "report.jsonl")


RELAY_ENGINE = RelayAdapter(
    engine="fixture-garak",
    license="Apache-2.0",
    probes=(replace(SSTI, probe="fixture.ai.leak", family="ai.data_leakage"),),
    prepare=_relay_prepare,
)


class _Recorder:
    def __init__(self) -> None:
        self.invocations: list[Invocation] = []
        self.workspaces: list[Path] = []

    def __call__(self, invocation: Invocation, workspace: Path) -> None:
        self.invocations.append(invocation)
        self.workspaces.append(workspace)
        (workspace / invocation.report).write_text(json.dumps(RECORDED) + "\n")


def test_every_registered_probe_resolves_to_its_adapter(
    monkeypatch: object, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))  # type: ignore[attr-defined]
    assert ADAPTERS[0] is BUILT_IN
    installed = [(item.probe, item.engine) for item in capabilities() if item.available]
    assert installed == [
        ("insidia.ai.data_leakage", "insidia"),
        ("insidia.web.ssti", "insidia"),
    ]
    for spec in BUILT_IN.probes:
        assert find(spec.probe) == (BUILT_IN, spec)
        assert spec.family in ORACLES


def test_builtin_ssti_hits_a_web_target_and_skips_a_chat_target(tmp_path: Path) -> None:
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(json.loads(body)["prompt"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"rendered 49")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/render"
    adapter, spec = find("insidia.web.ssti")
    control = get_policy("L1").control("web.ssti")
    try:
        hits = run(adapter, spec, target(kind="web", url=url), _project(), tmp_path, control)
        skipped = run(adapter, spec, target(kind="chat", url=url), _project(), tmp_path, control)
    finally:
        server.shutdown()
    assert [(hit.engine, hit.probe, hit.evidence) for hit in hits] == [
        ("insidia", "insidia.web.ssti", "49")
    ]
    assert skipped == []
    assert seen == ["{{7*7}}"]


def test_report_adapter_hit_is_stamped_with_the_adapter_engine(tmp_path: Path) -> None:
    launch = _Recorder()
    web = target(kind="web", url="http://127.0.0.1:8080/call")
    control = get_policy("L1").control("web.ssti")
    hits = run(REPORT_ENGINE, SSTI, web, _project(), tmp_path, control, launch=launch)
    assert [(hit.engine, hit.probe, hit.upstream, hit.evidence) for hit in hits] == [
        ("fixture-nuclei", "fixture.web.ssti", "insidia-ssti-arith", "49")
    ]
    assert launch.invocations[0].args[:2] == ("-u", "http://127.0.0.1:8080/call")
    assert not launch.workspaces[0].exists()


def test_report_adapter_never_launches_against_an_unscoped_url(tmp_path: Path) -> None:
    launch = _Recorder()
    web = target(kind="web", url="http://example.com/call")
    control = get_policy("L1").control("web.ssti")
    with pytest.raises(ScopeError):
        run(REPORT_ENGINE, SSTI, web, _project(), tmp_path, control, launch=launch)
    assert launch.invocations == []


def test_relay_invocation_carries_no_target_host(tmp_path: Path) -> None:
    chat = target(url="http://sandbox.internal:8080/chat")
    endpoint = RelayEndpoint("http://127.0.0.1:49152/v1/send", "token")
    invocation = RELAY_ENGINE.prepare(RELAY_ENGINE.probes[0], endpoint, tmp_path)
    rendered = " ".join((invocation.program, *invocation.args, invocation.report))
    assert chat.url is not None and hostname(chat.url) not in rendered
    assert "--generator_option_url=http://127.0.0.1:49152/v1/send" in invocation.args


def test_same_evidence_in_different_responses_is_one_cross_validated_finding() -> None:
    def hit(engine: str, response: str) -> ProbeHit:
        return ProbeHit(
            "site",
            "web.ssti",
            engine,
            f"{engine}.web.ssti",
            response,
            "high",
            "high",
            "classic",
            ("cwe:CWE-1336",),
            "Do not evaluate user input as a template.",
            "insidia-ssti-arith",
            "49",
        )

    findings = normalize([hit("insidia", "rendered 49"), hit("nuclei", "HTTP/1.1 200\r\n\r\n49")])
    assert [(item.engine, item.cross_validated) for item in findings] == [("insidia", True)]
    assert findings[0].engines == ("insidia", "nuclei")
