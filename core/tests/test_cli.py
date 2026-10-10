from pathlib import Path

from insidia.cli import main, scan_message
from insidia.config import load_project
from insidia.engines import install
from insidia.findings import Finding
from insidia.runstore import write_run
from insidia.scan import ScanOutcome


def test_init_doctor_and_policy(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    assert main(["init"]) == 0
    project = load_project(tmp_path / "insidia.yaml")
    assert project.policy == "L1"
    assert project.scope[0].host == "localhost"
    assert main(["init"]) == 2
    assert main(["doctor"]) == 0
    assert main(["policy", "list"]) == 0
    assert main(["policy", "validate"]) == 0
    assert main(["engines", "list"]) == 0
    assert main(["engines", "install"]) == 0


def test_scan_says_the_tool_ran_and_opens_the_report(
    tmp_path: Path,
    monkeypatch: object,
    capsys: object,
) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    assert main(["init"]) == 0
    finding = Finding(
        track="classic",
        engine="insidia",
        probe="insidia.web.ssti",
        severity="high",
        confidence="high",
        attack="web.ssti",
        response="49",
        trace_ref="shop",
        taxonomy=("owasp-web:A03",),
        remediation="Do not evaluate user input as a template.",
        evidence_hash="abc",
        cross_validated=False,
        target="shop",
    )
    outcome = ScanOutcome("run-1", tmp_path, False, [finding], [])

    def fake_execute(*_args: object, **_kwargs: object) -> ScanOutcome:
        return outcome

    opened: list[str] = []

    def fake_open(url: str) -> bool:
        opened.append(url)
        return True

    monkeypatch.setattr("insidia.cli.execute", fake_execute)  # type: ignore[attr-defined]
    monkeypatch.setattr("insidia.cli.webbrowser.open", fake_open)  # type: ignore[attr-defined]
    assert main(["scan", "--policy", "L1"]) == 1
    assert opened
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "The scan ran. Policy L1 did not pass. 1 finding. Opened" in out
    closed = scan_message("L1", True, 0, "report.html", False)
    assert closed == "The scan ran. Policy L1 passed. No findings. Report: report.html."


def test_rerun_refuses_a_changed_configuration(tmp_path: Path) -> None:
    (tmp_path / "insidia.yaml").write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
"""
    )
    write_run(
        tmp_path,
        "run-1",
        "L1",
        True,
        [],
        [],
        [],
        config_digest="0" * 64,
        coverage="standard",
    )
    code = main(["rerun", "run-1", "--config", str(tmp_path / "insidia.yaml"), "--quiet"])
    assert code == 2


def test_engine_install_names_each_engine(monkeypatch: object) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "insidia.engines._install_one",
        lambda name: f"{name} is already installed",
    )
    notes: list[str] = []
    message = install(("bandit",), progress=notes.append)
    assert notes[0].startswith("Installing bandit ")
    assert notes[1] == "bandit is already installed"
    assert "bandit is already installed" in message
