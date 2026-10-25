"""Find the latest GitHub release and reinstall Insidia with the tool that installed it."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from insidia import __version__
from insidia.errors import CliError

REPO = "Rushi-Balapure/Insidia-Labs"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases"

_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class Release:
    tag: str
    version: str
    url: str


def parse_version(text: str) -> tuple[int, int, int] | None:
    found = _VERSION.fullmatch(text.strip())
    if found is None:
        return None
    major, minor, patch = (int(part) for part in found.groups())
    return major, minor, patch


def source(tag: str) -> str:
    return f"git+https://github.com/{REPO}@{tag}#subdirectory=core"


def fetch_latest(timeout: float = 10.0) -> Release:
    request = urllib.request.Request(
        LATEST_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"insidia/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise CliError(f"no release is published yet. See {RELEASES_URL}") from exc
        raise CliError(f"GitHub returned HTTP {exc.code} for the latest release") from exc
    except (OSError, ValueError) as exc:
        raise CliError(f"could not check GitHub for the latest release: {exc}") from exc
    tag = document.get("tag_name") if isinstance(document, dict) else None
    if not isinstance(tag, str) or parse_version(tag) is None:
        raise CliError(f"the latest release tag {tag!r} is not a version such as v1.0.0")
    url = document.get("html_url")
    return Release(
        tag=tag,
        version=tag.removeprefix("v"),
        url=url if isinstance(url, str) else f"{RELEASES_URL}/tag/{tag}",
    )


def detect_installer(prefix: Path | None = None, package: Path | None = None) -> str:
    """uv, pipx, pip, or checkout. A checkout is this repository run in place."""
    prefix = Path(sys.prefix) if prefix is None else prefix
    package = Path(__file__).resolve().parent if package is None else package
    if (package.parent / "pyproject.toml").is_file() and (package.parents[1] / ".git").exists():
        return "checkout"
    if (prefix / "uv-receipt.toml").is_file():
        return "uv"
    if (prefix / "pipx_metadata.json").is_file():
        return "pipx"
    return "pip"


def install_command(installer: str, tag: str) -> list[str]:
    spec = source(tag)
    if installer == "uv":
        return [_tool("uv"), "tool", "install", "--force", spec]
    if installer == "pipx":
        return [_tool("pipx"), "install", "--force", spec]
    if installer == "pip":
        if importlib.util.find_spec("pip") is None:
            raise CliError(
                "this copy was not installed with uv or pipx, and pip is not available. "
                f'Reinstall with: uv tool install --force "{spec}"'
            )
        return [sys.executable, "-m", "pip", "install", "--upgrade", spec]
    raise CliError(
        "this copy runs from a git checkout. Update it with git pull, "
        f'or install the release with: uv tool install --force "{spec}"'
    )


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise CliError(f"this copy was installed with {name}, but {name} is not on PATH")
    return found


def upgrade(
    *,
    check: bool,
    force: bool,
    output: IO[str] | None = None,
    latest: Callable[[], Release] = fetch_latest,
    installer: Callable[[], str] = detect_installer,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> tuple[dict[str, object], str]:
    """Return the JSON document and the text line for `insidia upgrade`."""
    release = latest()
    current = parse_version(__version__)
    newest = parse_version(release.version)
    available = current is None or (newest is not None and newest > current)
    document: dict[str, object] = {
        "current": __version__,
        "latest": release.version,
        "update_available": available,
        "release": release.url,
    }
    if check or (not available and not force):
        if available:
            text = (
                f"Insidia {release.version} is available (you have {__version__}). "
                "Run insidia upgrade to install it."
            )
        else:
            text = f"Insidia {__version__} is the latest release."
        document["upgraded"] = False
        return document, text
    how = installer()
    command = install_command(how, release.tag)
    document["installer"] = how
    target = sys.stderr if output is None else output
    print(f"Installing Insidia {release.version} with {how}.", file=target, flush=True)
    try:
        finished = run(command, stdout=target, stderr=target, check=False)
    except OSError as exc:
        raise CliError(f"could not run {command[0]}: {exc}") from exc
    if finished.returncode != 0:
        raise CliError(
            f"{how} exited with code {finished.returncode}. "
            f'Retry by hand with: {" ".join(command[:-1])} "{command[-1]}"'
        )
    document["upgraded"] = True
    return document, f"Upgraded Insidia {__version__} to {release.version}. {release.url}"
