"""insidia init --config writes the path you name, and refuses before progress."""

from pathlib import Path

import pytest
from insidia.cli import main
from insidia.config import load_project


def test_init_writes_the_config_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    assert main(["init", "--config", "sub/custom.yaml", "--url", "http://127.0.0.1:8081/chat"]) == 0
    written = tmp_path / "sub" / "custom.yaml"
    assert written.is_file()
    assert not (tmp_path / "insidia.yaml").exists()
    assert load_project(written).targets[0].url == "http://127.0.0.1:8081/chat"


def test_init_refuses_an_existing_file_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "insidia.yaml"
    target.write_text("keep\n")
    assert main(["init"]) == 2
    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert "Writing" not in captured.out
    assert "Writing" not in captured.err
    assert target.read_text() == "keep\n"
