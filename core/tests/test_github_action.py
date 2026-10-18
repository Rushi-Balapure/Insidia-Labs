"""The scan action pins third-party steps and keeps inputs out of the shell."""

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_ACTION = _ROOT / "actions" / "scan" / "action.yml"
_EXAMPLE = _ROOT / ".github" / "workflows" / "insidia-scan.yml"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_PAYLOAD = "$(id)"


def _action() -> dict:
    return yaml.safe_load(_ACTION.read_text())


def _steps(document: dict) -> list[dict]:
    return document["runs"]["steps"]


def _scripts(document: dict) -> list[str]:
    return [step["run"] for step in _steps(document) if "run" in step]


def test_empty_version_is_rejected_before_the_scan() -> None:
    document = _action()
    version = document["inputs"]["version"]
    assert version["required"] is True
    assert "default" not in version

    saw_rejection = False
    for step in _steps(document):
        script = step.get("run", "")
        if "insidia scan" in script:
            break
        if "INSIDIA_VERSION" in script and "non-empty" in script and "exit 1" in script:
            saw_rejection = True
            if "uv tool install" in script:
                assert script.index("non-empty") < script.index("uv tool install")
    assert saw_rejection

    install = next(
        step for step in _steps(document) if "uv tool install" in step.get("run", "")
    )
    script = install["run"]
    assert script.index("non-empty") < script.index("uv tool install")
    assert "pip install" not in script
    assert "git+https" not in script
    assert install["env"]["INSIDIA_VERSION"] == "${{ inputs.version }}"


def test_run_scripts_do_not_interpolate_expressions() -> None:
    for script in _scripts(_action()):
        assert "${{" not in script


def test_third_party_actions_are_pinned_to_commits() -> None:
    uses = [step["uses"] for step in _steps(_action()) if "uses" in step]
    assert uses
    for value in uses:
        pin = value.rsplit("@", 1)[-1]
        assert _SHA.fullmatch(pin)


def test_permissions_are_contents_read_and_security_events_write() -> None:
    assert _action()["permissions"] == {
        "contents": "read",
        "security-events": "write",
    }


def test_policy_payload_is_only_referenced_through_the_environment() -> None:
    scan = next(step for step in _steps(_action()) if "insidia scan" in step.get("run", ""))
    script = scan["run"]
    assert _PAYLOAD not in script
    assert "${{" not in script
    assert '"$INSIDIA_POLICY"' in script
    assert "--yes" in script
    assert scan["env"]["INSIDIA_POLICY"] == "${{ inputs.policy }}"
    for script in _scripts(_action()):
        assert _PAYLOAD not in script


_VALID = "20260101T120000Z-abcdef"
_PLANTED = "99991231T235959Z-aaaaaa"
_REPORTS = ("results.sarif", "report.html", "findings.json")


def _scan_script() -> str:
    scan = next(step for step in _steps(_action()) if "insidia --json scan" in step.get("run", ""))
    return str(scan["run"])


def _collect_script() -> str:
    collect = next(step for step in _steps(_action()) if step.get("id") == "reports")
    return str(collect["run"])


def _fill(directory: Path, marker: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in _REPORTS:
        (directory / name).write_text(f"{marker}:{name}\n", encoding="utf-8")


def _run_collect(workspace: Path) -> tuple[subprocess.CompletedProcess[str], str]:
    output = workspace / "github-output.txt"
    output.unlink(missing_ok=True)
    env = os.environ.copy()
    env["GITHUB_WORKSPACE"] = str(workspace)
    env["GITHUB_OUTPUT"] = str(output)
    completed = subprocess.run(
        ["bash", "-c", _collect_script()],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    written = output.read_text(encoding="utf-8") if output.is_file() else ""
    return completed, written


def test_report_collection_keeps_only_scan_run_ids() -> None:
    script = _collect_script()
    folded = " ".join(script.split())
    assert r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$" in script
    assert "insidia-scan.json" in script
    assert "run_dir" in script
    assert '".insidia"' in script
    assert '"runs"' in script
    assert "find .insidia/runs" not in folded
    assert "sort" not in folded
    assert "tail" not in folded


def test_action_checkout_is_the_only_install_source() -> None:
    text = _ACTION.read_text()
    assert "insidia==" not in text
    assert "pypi" not in text.lower()

    install = next(
        step for step in _steps(_action()) if "uv tool install" in step.get("run", "")
    )
    script = install["run"]
    assert "${{" not in script
    assert "github.action_path" not in script
    assert install["env"]["INSIDIA_VERSION"] == "${{ inputs.version }}"
    assert install["env"]["INSIDIA_CORE"] == "${{ github.action_path }}/../../core"

    assert "insidia==" not in script
    install_lines = [line.strip() for line in script.splitlines() if "uv tool install" in line]
    assert install_lines == ['uv tool install --python 3.12 --force "$INSIDIA_CORE"']
    assert "pip install" not in script
    assert "--index-url" not in script

    missing = script.index('! -f "$INSIDIA_CORE/pyproject.toml"')
    compared = script.index('"$checkout_version" != "$INSIDIA_VERSION"')
    installed = script.index('uv tool install --python 3.12 --force "$INSIDIA_CORE"')
    missing_exit = script.index("exit 1", missing)
    assert ">&2" in script[missing:missing_exit]
    assert missing_exit < compared < script.index("uv python install 3.12") < installed
    mismatch = script[compared:installed]
    assert "error:" in mismatch
    assert ">&2" in mismatch
    assert "exit 1" in mismatch


def test_example_scans_only_the_local_fixture() -> None:
    text = _EXAMPLE.read_text()
    document = yaml.safe_load(text)
    assert "pull_request_target" not in text
    assert "git clone" not in text
    assert "127.0.0.1" in text
    assert "authorized:" not in text
    for step in document["jobs"]["scan"]["steps"]:
        if "run" in step:
            assert "${{" not in step["run"]
        if "uses" in step and not str(step["uses"]).startswith("./"):
            pin = str(step["uses"]).rsplit("@", 1)[-1]
            assert _SHA.fullmatch(pin)

    with (_ROOT / "core" / "pyproject.toml").open("rb") as handle:
        package_version = tomllib.load(handle)["project"]["version"]
    called = next(
        step
        for step in document["jobs"]["scan"]["steps"]
        if step.get("uses") == "./actions/scan"
    )
    assert called["with"]["version"] == package_version
    assert document["permissions"] == {
        "contents": "read",
        "security-events": "write",
    }


def test_scan_step_writes_json_from_insidia_json_scan(tmp_path: Path) -> None:
    command = next(
        line.strip() for line in _scan_script().splitlines() if "insidia --json scan" in line
    )
    assert command == (
        'insidia --json scan --policy "$INSIDIA_POLICY" --yes > insidia-scan.json'
    )
    assert _scan_script().index(command) < _scan_script().index('if [ "$code" -eq 0 ]')
    assert "insidia-scan.json" in _collect_script()
    assert "run_dir" in _collect_script()


@pytest.mark.parametrize(
    ("code", "fail_on_inconclusive", "expected"),
    [
        (0, "true", 0),
        (1, "true", 1),
        (2, "true", 2),
        (2, "false", 0),
    ],
)
def test_scan_writes_json_even_when_the_exit_code_is_not_zero(
    tmp_path: Path, code: int, fail_on_inconclusive: str, expected: int
) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    program = bindir / "insidia"
    program.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" > insidia-argv\n'
        "printf '%s\\n' '{\"run_dir\":\".insidia/runs/20260101T120000Z-abcdef\"}'\n"
        f"exit {code}\n",
        encoding="utf-8",
    )
    program.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["INSIDIA_POLICY"] = "L1"
    env["INSIDIA_FAIL_ON_INCONCLUSIVE"] = fail_on_inconclusive
    completed = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == expected, completed.stderr + completed.stdout
    saved = json.loads((tmp_path / "insidia-scan.json").read_text(encoding="utf-8"))
    assert saved["run_dir"] == f".insidia/runs/{_VALID}"
    assert (tmp_path / "insidia-argv").read_text(encoding="utf-8").splitlines() == [
        "--json",
        "scan",
        "--policy",
        "L1",
        "--yes",
    ]


def test_collect_reads_run_dir_and_ignores_a_later_planted_folder(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    valid = workspace / ".insidia" / "runs" / _VALID
    planted = workspace / ".insidia" / "runs" / _PLANTED
    _fill(valid, "scan")
    _fill(planted, "planted")
    (workspace / "insidia-scan.json").write_text(
        json.dumps({"run_dir": f".insidia/runs/{_VALID}"}) + "\n",
        encoding="utf-8",
    )

    completed, outputs = _run_collect(workspace)

    assert completed.returncode == 0, completed.stderr
    assert "sarif=true" in outputs
    assert "found=true" in outputs
    for name in _REPORTS:
        text = (workspace / "insidia-reports" / name).read_text(encoding="utf-8")
        assert text.startswith("scan:")
        assert "planted" not in text


def test_missing_scan_json_uploads_nothing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _fill(workspace / ".insidia" / "runs" / _PLANTED, "planted")
    _fill(workspace / ".insidia" / "runs" / _VALID, "older")

    completed, outputs = _run_collect(workspace)

    assert completed.returncode == 0, completed.stderr
    assert "sarif=false" in outputs
    assert "found=false" in outputs
    assert not (workspace / "insidia-reports" / "results.sarif").exists()


def test_run_dir_is_accepted_only_under_insidia_runs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    valid = workspace / ".insidia" / "runs" / _VALID
    _fill(valid, "scan")
    _fill(workspace / ".insidia" / "runs" / "not-a-run", "badname")
    _fill(workspace / "other" / _VALID, "outside")
    nested = workspace / ".insidia" / "runs" / "bucket" / _VALID
    _fill(nested, "nested")
    outside = tmp_path / "outside" / ".insidia" / "runs" / _VALID
    _fill(outside, "escaped")
    link = workspace / ".insidia" / "runs" / "20260102T120000Z-abcdef"
    link.symlink_to(valid, target_is_directory=True)

    def collect(raw: object) -> str:
        reports = workspace / "insidia-reports"
        if reports.exists():
            for child in reports.iterdir():
                child.unlink()
        body = {} if raw is None else {"run_dir": raw}
        (workspace / "insidia-scan.json").write_text(json.dumps(body), encoding="utf-8")
        completed, outputs = _run_collect(workspace)
        assert completed.returncode == 0, completed.stderr
        return outputs

    assert "sarif=true" in collect(f".insidia/runs/{_VALID}")
    assert (workspace / "insidia-reports" / "results.sarif").read_text(encoding="utf-8").startswith(
        "scan:"
    )
    assert "sarif=true" in collect(str(valid.resolve()))

    relative_escape = Path(os.path.relpath(outside, workspace)).as_posix()
    rejected = [
        None,
        "",
        ".insidia/runs/not-a-run",
        f"other/{_VALID}",
        f".insidia/runs/bucket/{_VALID}",
        str(outside),
        relative_escape,
        f".insidia/runs/{link.name}",
    ]
    for raw in rejected:
        outputs = collect(raw)
        assert "sarif=false" in outputs, raw
        assert "found=false" in outputs, raw
        assert not (workspace / "insidia-reports" / "results.sarif").exists(), raw


def test_collect_does_not_follow_a_report_symlink_out_of_the_run(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    valid = workspace / ".insidia" / "runs" / _VALID
    _fill(valid, "scan")
    planted = workspace / "planted.sarif"
    planted.write_text("planted-sarif\n", encoding="utf-8")
    sarif = valid / "results.sarif"
    sarif.unlink()
    sarif.symlink_to(planted)
    (workspace / "insidia-scan.json").write_text(
        json.dumps({"run_dir": f".insidia/runs/{_VALID}"}),
        encoding="utf-8",
    )

    completed, outputs = _run_collect(workspace)

    assert completed.returncode == 0, completed.stderr
    assert "sarif=false" in outputs
    assert "found=false" in outputs
    assert not (workspace / "insidia-reports" / "results.sarif").exists()
