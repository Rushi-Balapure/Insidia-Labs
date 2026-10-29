import io
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from insidia import __version__, upgrade
from insidia.cli import main
from insidia.errors import CliError
from insidia.upgrade import Release, detect_installer, install_command, parse_version


def _release(version: str) -> Release:
    return Release(tag=f"v{version}", version=version, url=f"https://example.test/v{version}")


def _bump(version: str) -> str:
    major, minor, patch = version.split(".")
    return f"{major}.{minor}.{int(patch) + 1}"


class _Runner:
    def __init__(self, code: int = 0) -> None:
        self.code = code
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        self.commands.append(command)
        return subprocess.CompletedProcess(command, self.code)


def test_parse_version_accepts_tags_and_rejects_other_text() -> None:
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("1.10.0") == (1, 10, 0)
    assert parse_version("1.10.0") > parse_version("1.9.9")  # type: ignore[operator]
    assert parse_version("v1.2") is None
    assert parse_version("latest") is None


def test_detect_installer_reads_the_environment_markers(tmp_path: Path) -> None:
    package = tmp_path / "site-packages" / "insidia"
    package.mkdir(parents=True)
    assert detect_installer(tmp_path, package) == "pip"
    (tmp_path / "pipx_metadata.json").write_text("{}")
    assert detect_installer(tmp_path, package) == "pipx"
    (tmp_path / "uv-receipt.toml").write_text("")
    assert detect_installer(tmp_path, package) == "uv"


def test_detect_installer_recognises_a_source_checkout(tmp_path: Path) -> None:
    package = tmp_path / "repo" / "core" / "insidia"
    package.mkdir(parents=True)
    (tmp_path / "repo" / "core" / "pyproject.toml").write_text("")
    (tmp_path / "repo" / ".git").mkdir()
    assert detect_installer(tmp_path, package) == "checkout"


def test_install_command_pins_the_release_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    spec = "git+https://github.com/Rushi-Balapure/Insidia-Labs-Argus@v2.0.0#subdirectory=core"
    assert install_command("uv", "v2.0.0") == ["/bin/uv", "tool", "install", "--force", spec]
    assert install_command("pipx", "v2.0.0") == ["/bin/pipx", "install", "--force", spec]
    with pytest.raises(CliError, match="git pull"):
        install_command("checkout", "v2.0.0")


def test_install_command_needs_the_installer_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: None)
    with pytest.raises(CliError, match="uv is not on PATH"):
        install_command("uv", "v2.0.0")


def test_check_reports_a_newer_release_without_installing() -> None:
    runner = _Runner()
    newer = _bump(__version__)
    document, text = upgrade.upgrade(
        check=True, force=False, latest=lambda: _release(newer), run=runner
    )
    assert document["update_available"] is True
    assert document["upgraded"] is False
    assert newer in text
    assert runner.commands == []


def test_upgrade_does_nothing_when_already_latest() -> None:
    runner = _Runner()
    document, text = upgrade.upgrade(
        check=False, force=False, latest=lambda: _release(__version__), run=runner
    )
    assert document["update_available"] is False
    assert "is the latest release" in text
    assert runner.commands == []


def test_upgrade_reinstalls_with_the_detected_installer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    newer = _bump(__version__)
    output = io.StringIO()
    document, text = upgrade.upgrade(
        check=False,
        force=False,
        output=output,
        latest=lambda: _release(newer),
        installer=lambda: "uv",
        run=runner,
        platform="linux",
    )
    assert document["upgraded"] is True
    assert document["installer"] == "uv"
    assert runner.commands[0][:4] == ["/bin/uv", "tool", "install", "--force"]
    assert runner.commands[0][-1].endswith(f"@v{newer}#subdirectory=core")
    assert f"Upgraded Insidia {__version__} to {newer}" in text


def test_force_reinstalls_the_current_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    document, _ = upgrade.upgrade(
        check=False,
        force=True,
        output=io.StringIO(),
        latest=lambda: _release(__version__),
        installer=lambda: "pipx",
        run=runner,
        platform="linux",
    )
    assert document["upgraded"] is True
    assert runner.commands[0][:3] == ["/bin/pipx", "install", "--force"]


def test_a_failed_install_names_the_command_to_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    with pytest.raises(CliError, match="uv exited with code 1. Retry by hand"):
        upgrade.upgrade(
            check=False,
            force=False,
            output=io.StringIO(),
            latest=lambda: _release(_bump(__version__)),
            installer=lambda: "uv",
            run=_Runner(code=1),
            platform="linux",
        )


def test_windows_prints_the_command_instead_of_replacing_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(upgrade.shutil, "which", lambda name: f"/bin/{name}")
    runner = _Runner()
    newer = _bump(__version__)
    document, text = upgrade.upgrade(
        check=False,
        force=False,
        latest=lambda: _release(newer),
        installer=lambda: "uv",
        run=runner,
        platform="win32",
    )
    assert runner.commands == []
    assert document["upgraded"] is False
    assert str(document["command"]).startswith("/bin/uv tool install --force ")
    assert str(document["command"]) in text


def test_pip_force_reinstalls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade.importlib.util, "find_spec", lambda name: object())
    assert "--force-reinstall" in install_command("pip", "v2.0.0", force=True)
    assert "--force-reinstall" not in install_command("pip", "v2.0.0")


def test_cli_upgrade_check_prints_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "insidia.cli.upgrade",
        lambda check, force: upgrade.upgrade(
            check=check, force=force, latest=lambda: _release(__version__)
        ),
    )
    assert main(["upgrade", "--check", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document == {
        "current": __version__,
        "latest": __version__,
        "update_available": False,
        "release": f"https://example.test/v{__version__}",
        "upgraded": False,
    }


def test_cli_upgrade_reports_a_github_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def offline() -> Release:
        raise CliError("could not check GitHub for the latest release: offline")

    monkeypatch.setattr(
        "insidia.cli.upgrade",
        lambda check, force: upgrade.upgrade(check=check, force=force, latest=offline),
    )
    assert main(["upgrade", "--json"]) == 2
    assert "offline" in json.loads(capsys.readouterr().out)["error"]
