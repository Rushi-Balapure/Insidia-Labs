"""The scan action pins third-party steps and keeps inputs out of the shell."""

import re
import tomllib
from pathlib import Path

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


def test_report_collection_keeps_only_scan_run_ids() -> None:
    collect = next(step for step in _steps(_action()) if step.get("id") == "reports")
    script = collect["run"]
    assert r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$" in script
    assert "find .insidia/runs -mindepth 1 -maxdepth 1 -type d | sort | tail" not in script


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
