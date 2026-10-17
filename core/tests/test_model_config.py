"""Model secret_ref and provider names are rejected before a scan probes."""

from pathlib import Path

import pytest
from insidia.cli import main
from insidia.config import load_project
from insidia.errors import ConfigError


def _write(path: Path, secret_ref: str, provider: str = "openai-compatible") -> None:
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
    secret_ref: {secret_ref}
"""
    )


def test_malformed_secret_ref_is_rejected_at_load(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "insidia.yaml"
    _write(config, "INSIDIA_ATTACKER_KEY")
    with pytest.raises(ConfigError, match="secret_ref must look like env:NAME"):
        load_project(config)
    assert main(["--config", str(config), "policy", "validate"]) == 2
    assert main(["--config", str(config), "--yes", "--quiet", "scan"]) == 2
    assert "secret_ref must look like env:NAME" in capsys.readouterr().out


def test_unknown_provider_is_rejected_at_load(tmp_path: Path) -> None:
    config = tmp_path / "insidia.yaml"
    _write(config, "env:INSIDIA_ATTACKER_KEY", provider="openai")
    with pytest.raises(ConfigError, match="unknown model provider openai"):
        load_project(config)


def test_unset_model_secret_stops_the_scan_before_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("INSIDIA_ATTACKER_KEY", raising=False)
    config = tmp_path / "insidia.yaml"
    _write(config, "env:INSIDIA_ATTACKER_KEY")

    def explode(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("probe")

    monkeypatch.setattr("insidia.scan.preflight", explode)
    code = main(["--config", str(config), "--yes", "--quiet", "scan"])
    assert code == 2
    out = capsys.readouterr().out
    assert "environment variable INSIDIA_ATTACKER_KEY is not set" in out
    assert "Policy L1 passed" not in out


def test_unset_model_secret_fails_doctor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("INSIDIA_ATTACKER_KEY", raising=False)
    config = tmp_path / "insidia.yaml"
    _write(config, "env:INSIDIA_ATTACKER_KEY")
    assert main(["--config", str(config), "--quiet", "doctor"]) == 2
    out = capsys.readouterr().out
    assert "✘ model.attacker:" in out
    assert "INSIDIA_ATTACKER_KEY" in out
    assert "not set" in out


def test_set_model_secret_is_not_a_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("INSIDIA_ATTACKER_KEY", "qa-dummy-not-a-key")
    config = tmp_path / "insidia.yaml"
    _write(config, "env:INSIDIA_ATTACKER_KEY")
    project = load_project(config)
    assert project.attacker is not None
    assert project.attacker.secret_ref == "env:INSIDIA_ATTACKER_KEY"
    monkeypatch.setattr("insidia.scan.preflight", lambda *_a, **_k: "endpoint is unreachable")
    code = main(["--config", str(config), "--yes", "--quiet", "scan"])
    assert code == 2
    out = capsys.readouterr().out
    assert "qa-dummy-not-a-key" not in out
    assert "is not set" not in out


def test_config_without_models_still_loads(tmp_path: Path) -> None:
    config = tmp_path / "insidia.yaml"
    config.write_text(
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
    assert load_project(config).attacker is None
