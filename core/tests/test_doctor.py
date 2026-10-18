import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    assert "✘ target.app:" in out
    assert "✘ model.attacker:" in out
    assert "unreachable" in out
    assert "✘ model.judge:" in out
    assert "not in scope" in out
    assert seen == ["http://127.0.0.1:9/chat", "http://127.0.0.1:9/v1"]
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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    local_app: int,
) -> None:
    from insidia.cli import main

    empty = tmp_path / "insidia.yaml"
    empty.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:{local_app}/chat
models: {{}}
"""
    )
    assert main(["--config", str(empty), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "✔ target.app: reachable" in out
    assert "✘" not in out

    _models(empty, judge=False)
    monkeypatch.setattr("insidia.doctor.read_url", lambda *_a, **_k: "ok")
    assert main(["--config", str(empty), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "✔ model.attacker:" in out
    assert "✔ target.app: reachable" in out
    assert "✘" not in out


def test_docker_hint_names_engines_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

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
    monkeypatch.setattr("insidia.doctor.shutil.which", lambda _name: None)
    monkeypatch.setattr("insidia.doctor.read_url", lambda *_args, **_kwargs: "ok")
    assert main(["--config", str(config), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "insidia engines install --docker" in out
    assert "--engines docker" not in out

    with pytest.raises(SystemExit) as caught:
        main(["engines", "install", "--help"])
    assert caught.value.code == 0
    assert "--docker" in capsys.readouterr().out
    with pytest.raises(SystemExit) as caught:
        main(["scan", "--engines", "docker"])
    assert caught.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def local_app() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            raw = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _chat(path: Path, url: str, *, scope: str = "  - host: 127.0.0.1\n") -> None:
    path.write_text(
        f"""
version: 1
policy: L1
coverage: standard
scope:
{scope}targets:
  app:
    kind: chat
    url: {url}
models: {{}}
"""
    )


def test_doctor_fails_when_a_local_target_does_not_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    port = _closed_port()
    config = tmp_path / "insidia.yaml"
    _chat(config, f"http://127.0.0.1:{port}/chat")
    assert main(["--config", str(config), "doctor"]) == 2
    out = capsys.readouterr().out
    assert "✘ target.app:" in out
    assert f"127.0.0.1:{port}" in out
    assert "unreachable" in out or "target timed out" in out

    assert main(["--config", str(config), "--json", "doctor"]) == 2
    document = json.loads(capsys.readouterr().out)
    checks = {str(item["name"]): item for item in document["checks"]}
    assert checks["target.app"]["ok"] is False
    detail = str(checks["target.app"]["detail"])
    assert "unreachable" in detail or "target timed out" in detail


def test_doctor_json_marks_a_live_local_target_reachable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], local_app: int
) -> None:
    from insidia.cli import main

    config = tmp_path / "insidia.yaml"
    _chat(config, f"http://127.0.0.1:{local_app}/chat")
    assert main(["--config", str(config), "--json", "doctor"]) == 0
    document = json.loads(capsys.readouterr().out)
    checks = {str(item["name"]): item for item in document["checks"]}
    assert checks["target.app"] == {
        "name": "target.app",
        "ok": True,
        "detail": "reachable",
    }


def test_an_http_error_still_counts_as_the_target_answering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            raw = b"missing"
            self.send_response(404)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(server.server_address[1])
        config = tmp_path / "insidia.yaml"
        _chat(config, f"http://127.0.0.1:{port}/chat")
        assert main(["--config", str(config), "doctor"]) == 0
        assert "✔ target.app: reachable" in capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()


def test_doctor_does_not_contact_an_out_of_scope_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    config = tmp_path / "insidia.yaml"
    _chat(config, "http://127.0.0.1:9/chat", scope="  - host: localhost\n")
    contacted: list[str] = []

    def explode(url: str, *_args: object, **_kwargs: object) -> str:
        contacted.append(url)
        raise AssertionError(url)

    monkeypatch.setattr("insidia.doctor.read_url", explode)
    assert main(["--config", str(config), "doctor"]) == 2
    out = capsys.readouterr().out
    assert contacted == []
    assert "✘ target.app:" in out
    assert "127.0.0.1 is not in scope" in out


def test_doctor_does_not_contact_an_unauthorized_or_non_local_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    contacted: list[str] = []

    def explode(url: str, *_args: object, **_kwargs: object) -> str:
        contacted.append(url)
        raise AssertionError(url)

    monkeypatch.setattr("insidia.doctor.read_url", explode)
    blocked = tmp_path / "insidia.yaml"
    blocked.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
  - host: qa-out-of-scope.invalid
targets:
  app:
    kind: chat
    url: http://qa-out-of-scope.invalid/chat
models: {}
"""
    )
    assert main(["--config", str(blocked), "doctor"]) == 2
    out = capsys.readouterr().out
    assert contacted == []
    assert "✘ target.app:" in out
    assert "needs authorized: true" in out

    allowed = tmp_path / "remote.yaml"
    allowed.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: qa-out-of-scope.invalid
    authorized: true
targets:
  app:
    kind: chat
    url: http://qa-out-of-scope.invalid/chat
models: {}
"""
    )
    assert main(["--config", str(allowed), "doctor"]) == 0
    remote = capsys.readouterr().out
    assert contacted == []
    assert "authorized non-local host, not probed by doctor" in remote
    assert "is not local" not in remote


def test_repo_target_checks_the_path_and_makes_no_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    tree = tmp_path / "tree"
    tree.mkdir()
    config = tmp_path / "insidia.yaml"

    def explode(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("repo targets are not requested over HTTP")

    monkeypatch.setattr("insidia.doctor.read_url", explode)
    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  tree:
    kind: repo
    path: tree
models: {}
"""
    )
    assert main(["--config", str(config), "doctor"]) == 0
    assert "✔ target.tree: reachable" in capsys.readouterr().out

    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  tree:
    kind: repo
    path: missing
models: {}
"""
    )
    assert main(["--config", str(config), "doctor"]) == 2
    missing = capsys.readouterr().out
    assert "✘ target.tree:" in missing
    assert "does not exist" in missing

    config.write_text(
        """
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  tree:
    kind: repo
    path: /etc
models: {}
"""
    )
    assert main(["--config", str(config), "doctor"]) == 2
    outside = capsys.readouterr().out
    assert "outside the project" in outside


def test_zap_with_java_is_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_zap(tmp_path / "toolchain")
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    monkeypatch.setattr("insidia.engines.shutil.which", lambda name: f"/usr/bin/{name}")

    assert "zap" in installed_engines()


def test_doctor_accepts_an_authorized_non_local_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insidia.cli import main

    contacted: list[str] = []

    def explode(url: str, *_args: object, **_kwargs: object) -> str:
        contacted.append(url)
        raise AssertionError(url)

    monkeypatch.setattr("insidia.doctor.read_url", explode)
    config = tmp_path / "insidia.yaml"
    _chat(
        config,
        "http://qa-out-of-scope.invalid/chat",
        scope="  - host: qa-out-of-scope.invalid\n    authorized: true\n",
    )
    detail = "authorized non-local host, not probed by doctor"

    assert main(["--config", str(config), "doctor"]) == 0
    out = capsys.readouterr().out
    assert contacted == []
    assert detail in out
    assert "is not local" not in out

    assert main(["--config", str(config), "--json", "doctor"]) == 0
    raw = capsys.readouterr().out
    assert "is not local" not in raw
    document = json.loads(raw)
    checks = {str(item["name"]): item for item in document["checks"]}
    assert checks["target.app"]["ok"] is True
    assert checks["target.app"]["detail"] == detail
