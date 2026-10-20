"""insidia init --url writes the app you name, and only a local host."""

from pathlib import Path

import pytest
from insidia.cli import main
from insidia.config import load_project


def test_init_url_writes_a_chat_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--url", "http://127.0.0.1:8081/chat"]) == 0
    project = load_project(tmp_path / "insidia.yaml")
    target = project.targets[0]
    assert target.url == "http://127.0.0.1:8081/chat"
    assert target.kind == "chat"
    assert target.request_template is not None
    hosts = {item.host for item in project.scope}
    assert hosts == {"localhost", "127.0.0.1", "::1"}
    assert "http://127.0.0.1:8081/chat" in capsys.readouterr().out


def test_init_infers_kind_and_honours_an_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--url", "http://127.0.0.1:5000/hello"]) == 0
    assert load_project(tmp_path / "insidia.yaml").targets[0].kind == "web"
    (tmp_path / "insidia.yaml").unlink()
    assert main(["init", "--url", "http://localhost:5000/v1/widgets", "--kind", "api"]) == 0
    project = load_project(tmp_path / "insidia.yaml")
    assert project.targets[0].kind == "api"
    assert project.targets[0].url == "http://localhost:5000/v1/widgets"


def test_init_refuses_a_remote_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--url", "http://example.com/chat"]) == 2
    assert not (tmp_path / "insidia.yaml").exists()
    captured = capsys.readouterr()
    assert "example.com" in captured.out
    assert "authorized: true" in captured.out
    assert "Writing" not in captured.err


def test_init_without_url_tells_you_to_set_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    project = load_project(tmp_path / "insidia.yaml")
    assert project.targets[0].url == "http://127.0.0.1:8080/chat"
    out = capsys.readouterr().out
    assert "targets.app.url" in out
    assert "http://127.0.0.1:8080/chat" in out
    assert "insidia init --url http://127.0.0.1:PORT/path" in out
