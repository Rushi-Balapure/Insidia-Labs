"""Fail the build if a direct dependency is not on the license allowlist."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ALLOWED_PYTHON = {
    "alembic",
    "celery",
    "cryptography",
    "fastapi",
    "psycopg",
    "pydantic-settings",
    "sqlalchemy",
    "uvicorn",
    "pyyaml",
}

DENIED_MARKERS = ("gpl", "agpl", "sspl", "elastic", "bsl-1.1", "busl")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    names: set[str] = set()
    for relative in ("cloud/pyproject.toml", "core/pyproject.toml"):
        pyproject = tomllib.loads((root / relative).read_text())
        for spec in pyproject["project"]["dependencies"]:
            names.add(spec.split("[")[0].split(">=")[0].split(">")[0].strip().lower())
    unknown = names - ALLOWED_PYTHON
    if unknown:
        print("dependencies missing from the license allowlist:", ", ".join(sorted(unknown)))
        sys.exit(1)
    notices = (root / "THIRD_PARTY_NOTICES.md").read_text().lower()
    if "mpl-2.0" not in notices or "rabbitmq" not in notices:
        print("THIRD_PARTY_NOTICES.md must record the RabbitMQ MPL-2.0 attribution")
        sys.exit(1)
    for marker in DENIED_MARKERS:
        if marker in notices and "denied" not in notices:
            print(f"notice file looks like it accepts {marker}")
            sys.exit(1)
    print("license allowlist ok")


if __name__ == "__main__":
    main()
