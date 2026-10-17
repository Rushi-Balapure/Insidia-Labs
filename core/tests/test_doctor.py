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


def _models(path: Path, *, provider: str = "openai-compatible", judge: bool = True) -> None:
    judge_block = ""
    if judge:
        judge_block = """
  judge:
    provider: openai-compatible
    base_url: http://qa-out-of-scope.invalid/v1
    model: dummy
"""
    path.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
models:
  attacker:
    provider: {provider}
    base_url: http://127.0.0.1:9/v1
    model: dummy
{judge_block}
"""
    )


def test_doctor_fails_unreachable_and_out_of_scope_models(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main
    from insidia.errors import ProbeError

    config = tmp_path / "insidia.yaml"
    _models(config)
    seen: list[str] = []

    def fake_read(url: str, *_args: object, **_kwargs: object) -> str:
        seen.append(url)
        raise ProbeError("endpoint is unreachable")

    monkeypatch.setattr("insidia.doctor.read_url", fake_read)
    assert main(["--config", str(config), "doctor"]) == 2
    out = capsys.readouterr().out
    assert "✘ model.attacker:" in out
    assert "unreachable" in out
    assert "✘ model.judge:" in out
    assert "not in scope" in out
    assert seen == ["http://127.0.0.1:9/v1"]
    assert "unknown model provider" not in out


def test_doctor_rejects_an_unknown_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    config = tmp_path / "insidia.yaml"
    _models(config, provider="openai", judge=False)

    def explode(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("should not contact a model with an unknown provider")

    monkeypatch.setattr("insidia.doctor.read_url", explode)
    assert main(["--config", str(config), "--json", "doctor"]) == 2
    out = capsys.readouterr().out
    assert "unknown model provider openai" in out


def test_doctor_passes_with_no_models_and_a_reachable_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    empty = tmp_path / "insidia.yaml"
    empty.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
models: {}
"""
    )
    assert main(["--config", str(empty), "doctor"]) == 0
    assert "✘" not in capsys.readouterr().out

    _models(empty, judge=False)
    monkeypatch.setattr("insidia.doctor.read_url", lambda *_a, **_k: "ok")
    assert main(["--config", str(empty), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "✔ model.attacker:" in out
    assert "✘" not in out


def test_zap_with_java_is_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_zap(tmp_path / "toolchain")
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    monkeypatch.setattr("insidia.engines.shutil.which", lambda name: f"/usr/bin/{name}")

    assert "zap" in installed_engines()
