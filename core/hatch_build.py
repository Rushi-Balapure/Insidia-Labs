"""Record the git commit a wheel was built from as insidia/BUILD."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        commit = _commit(Path(self.root))
        if not commit:
            return
        self._dir = tempfile.TemporaryDirectory(prefix="insidia-build-")
        record = Path(self._dir.name) / "BUILD"
        record.write_text(commit + "\n")
        build_data["force_include"][str(record)] = "insidia/BUILD"

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        held = getattr(self, "_dir", None)
        if held is not None:
            held.cleanup()


def _commit(root: Path) -> str:
    try:
        found = subprocess.run(
            ["git", "describe", "--always", "--dirty", "--abbrev=12"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return found.stdout.strip()
