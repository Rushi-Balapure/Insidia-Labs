import hashlib
import json
from pathlib import Path

import pytest
from insidia.cli import main, scan_message
from insidia.config import load_project
from insidia.engines import install
from insidia.findings import Finding
from insidia.probes import Attempt
from insidia.runstore import local_time, read_manifest, write_run
from insidia.scan import ScanOutcome


def test_help_explains_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["-h"])
    assert caught.value.code == 0
    text = capsys.readouterr().out
    for line in (
        "write insidia.yaml in this directory",
        "check Python, the config file, and installed engines",
        "list engines or install the ones you name",
        "list, show, or validate a scan policy",
        "run the checks in the config file and write a report",
        "print or open the HTML report from a run",
        "scan again with the policy and config recorded for a run",
        "serve local MCP tools on stdin and stdout",
        "--config PATH",
        "--json",
        "--yes",
        "--quiet, -q",
        "--no-color",
    ):
        assert line in text


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


def test_scan_opens_the_report_only_when_asked(
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
    assert not opened
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "Report: " in out
    assert main(["scan", "--policy", "L1", "--open"]) == 1
    assert opened
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "The scan ran. Policy L1 did not pass. 1 finding. Opened" in out
    closed = scan_message("L1", True, 0, "report.html", False)
    assert closed == "The scan ran. Policy L1 passed. No findings. Report: report.html."
    thin = scan_message("L1", True, 0, "report.html", False, untested=12)
    assert "passed with no findings, but 12 checks were not tested" in thin
    run_id = "20261015T174011Z-371e29"
    stamped = scan_message("L1", True, 0, "report.html", False, run_id=run_id)
    assert stamped.startswith(f"Run {run_id} (started {local_time(run_id)})")


def test_global_options_work_before_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["--json", "engines"]) == 0
    assert capsys.readouterr().out.startswith('{"engines": ')
    assert main(["--config", "missing.yaml", "--json", "policy", "validate"]) == 2
    assert capsys.readouterr().out == '{"error": "missing missing.yaml"}\n'
    assert main(["engines", "--json"]) == 0
    assert capsys.readouterr().out.startswith('{"engines": ')


def test_global_options_work_after_nested_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["policy", "list", "--json"]) == 0
    listed = capsys.readouterr().out
    assert listed.startswith('{"policies": ')
    json.loads(listed)
    assert main(["policy", "show", "L3", "--json"]) == 0
    shown = capsys.readouterr().out
    assert "Not available yet" in shown
    json.loads(shown)
    assert main(["policy", "validate", "--json"]) == 0
    json.loads(capsys.readouterr().out)
    assert main(["policy", "show", "L2", "-q"]) == 0
    capsys.readouterr()
    assert main(["engines", "list", "--json"]) == 0
    assert capsys.readouterr().out.startswith('{"engines": ')
    assert main(["engines", "install", "--json"]) == 0
    json.loads(capsys.readouterr().out)
    assert main(["--json", "policy", "list"]) == 0
    json.loads(capsys.readouterr().out)
    with pytest.raises(SystemExit) as caught:
        main(["policy", "list", "--bogus"])
    assert caught.value.code == 2
    assert "unrecognized arguments: --bogus" in capsys.readouterr().err


def test_version_names_the_build(capsys: pytest.CaptureFixture[str]) -> None:
    from insidia import __version__, build_id

    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith(f"insidia {__version__}")
    if build_id():
        assert out.endswith(f"({build_id()})")


def test_run_ids_sort_in_utc_and_show_local_time() -> None:
    from insidia.runstore import local_time, new_run_id

    assert new_run_id()[15] == "Z"
    assert local_time("20261015T174011Z-371e29").startswith("2026-10-15")
    assert local_time("run-1") == ""


def test_rerun_refuses_a_run_without_a_recorded_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "insidia.yaml").write_text(_CHAT)
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
    assert "does not record its configuration" in capsys.readouterr().out


def test_run_stores_the_config_and_rerun_uses_that_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "configured-secret-value-xyz"
    monkeypatch.setenv("APP_TOKEN", secret)
    config = tmp_path / "insidia.yaml"
    config.write_text(
        _CHAT.replace(
            "    url: http://127.0.0.1:9/chat\n",
            "    url: http://127.0.0.1:9/chat\n"
            "    headers:\n"
            f"      Authorization: Bearer {secret}\n"
            "    auth:\n"
            "      header: Authorization\n"
            "      secret_ref: env:APP_TOKEN\n"
            "# planted AKIAIOSFODNN7EXAMPLE\n",
        )
    )
    seen: list[str] = []
    _stub_probes(monkeypatch, seen)
    assert main(["scan", "--config", str(config), "--quiet"]) == 0
    run_dir = next((tmp_path / ".insidia" / "runs").iterdir())
    manifest = read_manifest(run_dir)
    assert manifest is not None
    stored = (run_dir / "insidia.yaml").read_bytes()
    digest = hashlib.sha256(stored).hexdigest()
    assert manifest["config_digest"] == digest
    files = manifest["files"]
    assert isinstance(files, dict)
    assert files["insidia.yaml"] == digest
    text = stored.decode()
    assert secret not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "secret_ref: env:APP_TOKEN" in text
    assert secret not in json.dumps(manifest)
    recorded = load_project(run_dir / "insidia.yaml")
    assert recorded.targets[0].name == "chat"
    assert recorded.targets[0].headers["Authorization"] == "REDACTED"

    config.write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
  - host: example.com
    authorized: true
targets:
  ping:
    kind: web
    url: http://example.com/ping
    method: GET
"""
    )
    seen.clear()
    code = main(["rerun", run_dir.name, "--config", str(config), "--yes", "--quiet"])
    assert code == 0
    assert seen
    assert all(item.startswith("chat ") for item in seen)
    assert all("example.com" not in item for item in seen)


def test_rerun_yes_does_not_approve_a_new_non_local_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
  - host: example.com
    authorized: true
targets:
  ext:
    kind: web
    url: http://example.com/
    method: GET
"""
    )
    seen: list[str] = []
    _stub_probes(monkeypatch, seen)
    assert main(["scan", "--config", str(config), "--yes", "--quiet"]) == 0
    run_id = next((tmp_path / ".insidia" / "runs").iterdir()).name
    config.write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
  - host: example.com
    authorized: true
  - host: qa-out-of-scope.invalid
    authorized: true
targets:
  ext:
    kind: web
    url: http://example.com/
    method: GET
  extra:
    kind: web
    url: http://qa-out-of-scope.invalid/
    method: GET
"""
    )
    seen.clear()
    capsys.readouterr()
    refused = main(["rerun", run_id, "--config", str(config), "--quiet"])
    assert refused == 2
    assert "pass --yes" in capsys.readouterr().out
    assert seen == []
    code = main(["rerun", run_id, "--config", str(config), "--yes", "--quiet"])
    assert code == 0
    assert seen
    assert all(item.startswith("ext ") for item in seen)
    assert all("qa-out-of-scope.invalid" not in item for item in seen)


def test_repo_posture_row_is_under_the_target_and_run_shows_local_time(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text('token = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "insidia.yaml").write_text(
        """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  code:
    kind: repo
    path: src
"""
    )
    code = main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--no-color"])
    captured = capsys.readouterr()
    header = captured.err.index("\ncode\n")
    posture = captured.err.index("ai.agent_posture")
    assert header < posture
    assert "ai.agent_posture" not in captured.err[:header]
    run_id = next((tmp_path / ".insidia" / "runs").iterdir()).name
    started = local_time(run_id)
    assert f"Run {run_id} (started {started})" in captured.out
    assert code == 1


def test_incomplete_target_prints_its_own_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def preflight(target: object, *_args: object) -> str:
        if getattr(target, "name", "") == "dead":
            return "http://127.0.0.1:9/chat: unreachable"
        return ""

    monkeypatch.setattr("insidia.scan.preflight", preflight)
    monkeypatch.setattr("insidia.scan.run", lambda *_args, **_kwargs: Attempt())

    def run_case(name: str, body: str) -> tuple[int, str]:
        work = tmp_path / name
        work.mkdir()
        (work / "insidia.yaml").write_text(body)
        code = main(["scan", "--config", str(work / "insidia.yaml"), "--no-color"])
        return code, capsys.readouterr().err

    code, err = run_case("mixed", _APP_THEN_DEAD)
    assert code == 2
    assert err.index("\napp\n") < err.index("\ndead\n") < err.index("incomplete")

    code, err = run_case("reordered", _DEAD_THEN_APP)
    assert code == 2
    assert err.index("\ndead\n") < err.index("incomplete") < err.index("\napp\n")

    code, err = run_case("dead-only", _DEAD_ONLY)
    assert code == 2
    assert err.index("\ndead\n") < err.index("incomplete")


_APP_THEN_DEAD = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
  dead:
    kind: chat
    url: http://127.0.0.1:9/chat
"""

_DEAD_THEN_APP = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  dead:
    kind: chat
    url: http://127.0.0.1:9/chat
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
"""

_DEAD_ONLY = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  dead:
    kind: chat
    url: http://127.0.0.1:9/chat
"""


def _stub_probes(monkeypatch: pytest.MonkeyPatch, seen: list[str]) -> None:
    def preflight(target: object, *_args: object) -> str:
        seen.append(f"{target.name} {target.url}")  # type: ignore[attr-defined]
        return ""

    monkeypatch.setattr("insidia.scan.preflight", preflight)
    monkeypatch.setattr("insidia.scan.run", lambda *_args, **_kwargs: Attempt())


_CHAT = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  chat:
    kind: chat
    url: http://127.0.0.1:9/chat
"""


def test_mcp_allow_remote_is_a_launch_flag(monkeypatch: object) -> None:
    seen: dict[str, object] = {}

    def fake_serve(*_args: object, allow_remote: bool = False) -> int:
        seen["allow_remote"] = allow_remote
        return 0

    monkeypatch.setattr("insidia.cli.serve", fake_serve)  # type: ignore[attr-defined]
    assert main(["mcp"]) == 0
    assert seen["allow_remote"] is False
    assert main(["mcp", "--allow-remote"]) == 0
    assert seen["allow_remote"] is True


def test_allow_unverified_is_passed_to_install(monkeypatch: object) -> None:
    seen: dict[str, object] = {}

    def fake_install(*_args: object, **kwargs: object) -> str:
        seen.update(kwargs)
        return "ok"

    monkeypatch.setattr("insidia.cli.install", fake_install)  # type: ignore[attr-defined]
    assert main(["engines", "install", "nuclei", "--allow-unverified"]) == 0
    assert seen["allow_unverified"] is True


def test_out_of_scope_target_is_refused_before_any_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    contacted: list[str] = []

    def fetch(*_args: object, **_kwargs: object) -> tuple[int, dict[str, str], str]:
        contacted.append("fetch")
        raise AssertionError("a target was contacted")

    monkeypatch.setattr("insidia.transport.fetch", fetch)
    for name, body in (("local-first", _LOCAL_THEN_REMOTE), ("remote-first", _REMOTE_THEN_LOCAL)):
        contacted.clear()
        work = tmp_path / name
        work.mkdir()
        (work / "insidia.yaml").write_text(body)
        code = main(["scan", "--config", str(work / "insidia.yaml"), "--yes", "--quiet"])
        captured = capsys.readouterr()
        assert code == 2
        assert "example.com is not in scope" in captured.out
        assert "No target was contacted." in captured.out
        assert contacted == []
        assert not (work / ".insidia").exists()


_LOCAL_THEN_REMOTE = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  local:
    kind: web
    url: http://127.0.0.1:8090/hello
    method: GET
  ext:
    kind: web
    url: http://example.com/
    method: GET
"""

_REMOTE_THEN_LOCAL = """\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  ext:
    kind: web
    url: http://example.com/
    method: GET
  local:
    kind: web
    url: http://127.0.0.1:8090/hello
    method: GET
"""


def test_engine_install_names_each_engine(monkeypatch: object) -> None:
    def already(name: str, allow_unverified: bool = False) -> str:
        del allow_unverified
        return f"{name} is already installed"

    monkeypatch.setattr("insidia.engines._install_one", already)  # type: ignore[attr-defined]
    notes: list[str] = []
    message = install(("bandit",), progress=notes.append)
    assert notes[0].startswith("Installing bandit ")
    assert notes[1] == "bandit is already installed"
    assert "bandit is already installed" in message
