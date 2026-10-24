from pathlib import Path


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
