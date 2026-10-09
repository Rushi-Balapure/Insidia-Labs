from pathlib import Path


def test_wheel_notices_match_the_repo_copies() -> None:
    root = Path(__file__).resolve().parents[2]
    packaging = Path(__file__).resolve().parents[1] / "packaging"
    for name in ("NOTICE", "THIRD_PARTY_NOTICES.md"):
        assert (packaging / name).read_bytes() == (root / name).read_bytes()
