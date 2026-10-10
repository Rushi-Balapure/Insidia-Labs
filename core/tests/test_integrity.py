"""Regressions for the 10 October 2026 review. Later packages remove the xfails."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import arithmetic_echo
from insidia.catalog import SPECS
from insidia.cli import main
from insidia.errors import EngineFailed
from insidia.policy import POLICIES, Policy
from insidia.probes import Attempt, ProbeHit
from insidia.readiness import ABSENT_CAPABILITIES, REVIEW, UNSCHEDULED_FAMILIES, inventory
from insidia.registry import Capability
from insidia.upstream import _load_json
from tests.support import target


def test_every_current_capability_has_a_disposition() -> None:
    rows = inventory()
    names = {row.name for row in rows}
    families = {control.family for control in POLICIES["L1"].controls}
    engines = {spec.name for spec in SPECS}
    assert families <= names
    assert set(UNSCHEDULED_FAMILIES) <= names
    assert engines <= names
    assert set(ABSENT_CAPABILITIES) <= names
    assert families.isdisjoint(UNSCHEDULED_FAMILIES)
    assert {item.item_id for item in REVIEW} == {f"R{number}" for number in range(1, 13)}
    unsupported = {row.name for row in rows if row.readiness == "unsupported"}
    assert set(UNSCHEDULED_FAMILIES) <= unsupported
    assert set(ABSENT_CAPABILITIES) <= unsupported


def test_a_failed_engine_keeps_the_other_engines_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_chat(tmp_path)

    def fake_select(
        family: str,
        coverage: str,
        *,
        model_available: bool,
        entries: tuple[Capability, ...] | None = None,
    ) -> list[Capability]:
        del coverage, model_available, entries
        chosen = [Capability(family, "insidia", f"insidia.{family}", 100, False, True)]
        if family == "ai.data_leakage":
            chosen.append(Capability(family, "garak", "garak.ai.data_leakage", 50, False, True))
        return chosen

    def fake_run(*args: object, **kwargs: object) -> Attempt:
        del kwargs
        adapter = args[0]
        spec = args[1]
        engine = getattr(adapter, "engine", "")
        family = getattr(spec, "family", "")
        if engine == "garak":
            return Attempt((), "garak report missing")
        if family == "ai.data_leakage":
            return Attempt(
                (
                    ProbeHit(
                        "app",
                        family,
                        "insidia",
                        f"insidia.{family}",
                        "secret",
                        "high",
                        "high",
                        "ai",
                        ("owasp-llm:LLM02",),
                        "Stop returning secrets.",
                    ),
                )
            )
        return Attempt()

    monkeypatch.setattr("insidia.scan.select", fake_select)
    monkeypatch.setattr("insidia.scan.run", fake_run)
    code = main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--json", "--quiet"])
    document = json.loads(capsys.readouterr().out)
    benchmark = json.loads(_latest(tmp_path, "benchmark.json").read_text())
    findings = json.loads(_latest(tmp_path, "findings.json").read_text())
    report = _latest(tmp_path, "report.html").read_text()
    assert code == 2
    assert document["execution_status"] == "incomplete"
    assert document["policy_verdict"] == "fail"
    assert document["passed"] is False
    assert benchmark["schema_version"] == "2.0"
    assert benchmark["execution_status"] == "incomplete"
    assert benchmark["policy_verdict"] == "fail"
    assert findings
    assert "did not finish" in report
    assert "did not pass" in report


def test_no_applicable_controls_are_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_chat(tmp_path)
    monkeypatch.setattr("insidia.scan.get_policy", lambda name: Policy("L1", "empty", ()))
    code = main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--json", "--quiet"])
    document = json.loads(capsys.readouterr().out)
    report = _latest(tmp_path, "report.html").read_text()
    assert code == 2
    assert document["policy_verdict"] == "inconclusive"
    assert document["passed"] is False
    assert document["findings"] == []
    assert "inconclusive" in report


def test_malformed_engine_report_is_not_an_empty_result(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("{")
    with pytest.raises(EngineFailed, match="not valid JSON"):
        _load_json(report)


def test_unauthorized_target_cannot_pass(tmp_path: Path) -> None:
    class Denied(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b'{"error":"unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Denied)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = int(server.server_address[1])
    try:
        _write_chat(tmp_path, port)
        code = main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--quiet"])
    finally:
        server.shutdown()
    assert code != 0


def test_l2_is_not_a_higher_level(tmp_path: Path) -> None:
    _write_chat(tmp_path)
    path = tmp_path / "insidia.yaml"
    path.write_text(path.read_text().replace("policy: L1", "policy: L3"))
    assert main(["scan", "--config", str(path), "--quiet"]) == 2


def test_unknown_config_field_is_rejected(tmp_path: Path) -> None:
    _write_chat(tmp_path)
    path = tmp_path / "insidia.yaml"
    path.write_text(path.read_text().replace("coverage: standard", "covrage: thorough"))
    code = main(["scan", "--config", str(path), "--quiet"])
    assert code == 2


def test_a_later_transport_error_keeps_the_earlier_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from insidia.adapters import find
    from insidia.errors import ProbeError
    from insidia.policy import get_policy
    from insidia.probes import run
    from tests.support import target

    calls = {"n": 0}

    def fake_exchange(*args: object, **kwargs: object) -> str:
        del args, kwargs
        calls["n"] += 1
        if calls["n"] == 1:
            return "insidia-plant-canary-7f3a"
        raise ProbeError("target timed out")

    monkeypatch.setattr("insidia.probes.exchange", fake_exchange)
    adapter, spec = find("insidia.ai.data_leakage")
    attempt = run(
        adapter,
        spec,
        target(url="http://127.0.0.1:9/chat"),
        _project(tmp_path),
        tmp_path,
        get_policy("L1").control("ai.data_leakage"),
    )
    assert attempt.hits
    assert "timed out" in attempt.error


def _project(root: Path) -> object:
    from insidia.config import Project
    from insidia.scope import ScopeHost

    return Project(
        root / "insidia.yaml",
        1,
        "L1",
        "standard",
        (ScopeHost("127.0.0.1", False),),
        (),
        None,
        None,
    )


def test_a_clean_nuclei_report_is_not_a_failure(tmp_path: Path) -> None:
    from insidia.errors import EngineFailed
    from insidia.upstream import _web_bodies

    report = tmp_path / "report.jsonl"
    report.write_text("")
    assert _web_bodies("nuclei", report) == []
    with pytest.raises(EngineFailed, match="empty"):
        _web_bodies("zap", report)


def test_trivy_error_object_is_not_a_clean_result(tmp_path: Path) -> None:
    from insidia.errors import EngineFailed
    from insidia.upstream import build

    report = tmp_path / "report.json"
    report.write_text('{"error":"synthetic engine failure"}')
    adapter = next(item for item in build() if item.engine == "trivy")
    with pytest.raises(EngineFailed, match="error"):
        adapter.parse(report, adapter.probes[0])


def test_price_49_is_not_template_execution() -> None:
    evidence = arithmetic_echo("{{7*7}}", "This item costs 49 dollars.", target())
    assert evidence is None


def _write_chat(root: Path, port: int = 9) -> None:
    (root / "insidia.yaml").write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:{port}/chat
    method: GET
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )


def _latest(root: Path, name: str) -> Path:
    runs = sorted((root / ".insidia" / "runs").iterdir())
    return runs[-1] / name
