"""Engine toolchain commands. Upstream engines are installed in a later release."""

from __future__ import annotations

import shutil

from insidia.errors import CliError
from insidia.registry import KNOWN_ENGINES


def list_engines() -> list[dict[str, object]]:
    return [
        {"name": name, "license": license_name, "installed": name == "insidia"}
        for name, license_name in KNOWN_ENGINES
    ]


def install(*, docker: bool) -> str:
    if docker:
        if shutil.which("docker") is None:
            raise CliError("docker is not installed")
        return "docker is available; engine images arrive with the engine adapters"
    return "built-in probes are already available; other engines arrive in a later release"
