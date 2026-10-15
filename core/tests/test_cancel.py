import json
from pathlib import Path

import pytest
from insidia.cli import main
from insidia.probes import Attempt

_CONFIG = """\
version: 1
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: chat
    url: http://127.0.0.1:9/chat
"""


def test_ctrl_c_saves_a_cancelled_run_and_exits_130(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = tmp_path / "insidia.yaml"
    config.write_text(_CONFIG)
    calls: list[str] = []

    def interrupt_second(*_args: object, **_kwargs: object) -> Attempt:
        calls.append("run")
        if len(calls) == 2:
            raise KeyboardInterrupt
        return Attempt()

    monkeypatch.setattr("insidia.scan.run", interrupt_second)
    assert main(["scan", "--config", str(config)]) == 130
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "Scan cancelled" in captured.err
    assert "Scan cancelled" in captured.out
    runs = list((tmp_path / ".insidia" / "runs").iterdir())
    assert len(runs) == 1
    manifest = json.loads((runs[0] / "manifest.json").read_text())
    assert manifest["execution_status"] == "cancelled"
