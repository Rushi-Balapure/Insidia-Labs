import json
from pathlib import Path

import pytest
from insidia.doctor import diagnose
from insidia.engines import installed_engines, list_engines


def _fake_zap(root: Path) -> None:
    folder = root / "zap"
    folder.mkdir(parents=True)
    (folder / "zap.sh").write_text("#!/bin/sh\n")
    receipt = {"name": "zap", "program": "zap.sh", "version": "2.17.0"}
    (folder / "receipt.json").write_text(json.dumps(receipt))


def test_zap_without_java_is_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_zap(tmp_path / "toolchain")
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    monkeypatch.setattr("insidia.engines.shutil.which", lambda _name: None)
    monkeypatch.setattr("insidia.doctor.shutil.which", lambda _name: None)

    assert "zap" not in installed_engines()
    row = next(item for item in list_engines() if item["name"] == "zap")
    assert row["installed"] is False
    assert "Java" in str(row["note"])

    checks, code = diagnose(tmp_path / "missing.yaml")
    by_name = {str(check["name"]): check for check in checks}
    assert by_name["engine.zap"]["ok"] is False
    assert by_name["docker"]["ok"] is False
    assert by_name["docker"]["required"] is False
    assert code == 2


def test_zap_with_java_is_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_zap(tmp_path / "toolchain")
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    monkeypatch.setattr("insidia.engines.shutil.which", lambda name: f"/usr/bin/{name}")

    assert "zap" in installed_engines()
