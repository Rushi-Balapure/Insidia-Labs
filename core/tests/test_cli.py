from pathlib import Path

from insidia.cli import main
from insidia.config import load_project


def test_init_doctor_and_policy(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    assert main(["init"]) == 0
    project = load_project(tmp_path / "insidia.yaml")
    assert project.policy == "L1"
    assert project.scope[0].host == "localhost"
    assert main(["init"]) == 2
    assert main(["doctor"]) == 0
    assert main(["policy", "list"]) == 0
    assert main(["policy", "validate"]) == 0
    assert main(["engines", "list"]) == 0
    assert main(["engines", "install"]) == 0
