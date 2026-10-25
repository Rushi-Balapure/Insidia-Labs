import re
import tomllib
from pathlib import Path

from insidia import __version__


def test_package_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert declared == __version__
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_changelog_has_notes_for_this_version() -> None:
    changelog = Path(__file__).resolve().parents[2] / "CHANGELOG.md"
    headings = re.findall(r"^## (\S+)$", changelog.read_text(encoding="utf-8"), re.MULTILINE)
    assert headings[0] == __version__


def test_wheel_notices_match_the_repo_copies() -> None:
    root = Path(__file__).resolve().parents[2]
    packaging = Path(__file__).resolve().parents[1] / "packaging"
    for name in ("NOTICE", "THIRD_PARTY_NOTICES.md"):
        assert (packaging / name).read_bytes() == (root / name).read_bytes()


def test_shipped_framework_maps_match_the_benchmark_copies() -> None:
    root = Path(__file__).resolve().parents[2]
    packaged = Path(__file__).resolve().parents[1] / "insidia" / "mappings"
    names = (
        "owasp-llm-2026.yaml",
        "owasp-asi-2026.yaml",
        "owasp-web.yaml",
        "owasp-api.yaml",
    )
    for name in names:
        packaged_bytes = (packaged / name).read_bytes()
        repo_bytes = (root / "benchmark" / "mappings" / name).read_bytes()
        assert packaged_bytes == repo_bytes


def test_shipped_report_logos_match_the_approved_brand_lockups() -> None:
    root = Path(__file__).resolve().parents[2]
    packaged = root / "core" / "insidia" / "brand"
    lockups = root / "brand" / "lockups"
    for variant, master in (
        ("dark", "insidia-labs-horizontal-dark-transparent.svg"),
        ("light", "insidia-labs-horizontal-light.svg"),
    ):
        assert (packaged / f"lockup-{variant}.svg").read_bytes() == (lockups / master).read_bytes()
