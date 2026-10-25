"""Insidia Labs CLI."""

import subprocess
from pathlib import Path

__version__ = "1.0.0"


def build_id() -> str:
    """The commit this copy came from: insidia/BUILD in a wheel, or git in a checkout."""
    here = Path(__file__).resolve().parent
    record = here / "BUILD"
    if record.is_file():
        return record.read_text(encoding="utf-8").strip()
    # Only this repository's checkout; an install inside another git project is not ours.
    if not (here.parent / "pyproject.toml").is_file() or not (here.parents[1] / ".git").exists():
        return ""
    try:
        found = subprocess.run(
            ["git", "describe", "--always", "--dirty", "--abbrev=12"],
            cwd=here,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return found.stdout.strip()


def version_text() -> str:
    build = build_id()
    return f"insidia {__version__} ({build})" if build else f"insidia {__version__}"
