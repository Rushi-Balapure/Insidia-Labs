"""Report whether this machine can run a local scan."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from insidia.config import Project, load_project
from insidia.errors import CliError
from insidia.scope import ScopeHost, check_url
from insidia.transport import read_url


def diagnose(config_path: Path) -> tuple[list[dict[str, object]], int]:
    checks: list[dict[str, object]] = []
    python_ok = sys.version_info >= (3, 12)
    checks.append({"name": "python", "ok": python_ok, "detail": sys.version.split()[0]})
    config_ok = False
    if config_path.is_file():
        try:
            project = load_project(config_path)
        except CliError as exc:
            checks.append({"name": "config", "ok": False, "detail": str(exc)})
        else:
            config_ok = True
            checks.append({"name": "config", "ok": True, "detail": str(config_path.name)})
            checks.extend(_model_checks(project))
    else:
        checks.append({"name": "config", "ok": False, "detail": f"missing {config_path.name}"})
    docker = shutil.which("docker")
    checks.append(
        {
            "name": "docker",
            "ok": True,
            "detail": "found" if docker else "not found; optional unless you use --engines docker",
        }
    )
    checks.append({"name": "engines", "ok": True, "detail": "built-in: insidia"})
    code = 0 if python_ok and config_ok else 2
    return checks, code


def _model_checks(project: Project) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for role in (project.attacker, project.judge):
        if role is None or role.base_url is None:
            continue
        try:
            check_url(role.base_url, project.scope)
        except CliError as exc:
            checks.append({"name": f"model.{role.name}", "ok": False, "detail": str(exc)})
            continue
        checks.append(
            {
                "name": f"model.{role.name}",
                "ok": _reachable(role.base_url, project.scope),
                "detail": role.base_url,
            }
        )
    return checks


def _reachable(url: str, scope: tuple[ScopeHost, ...]) -> bool:
    try:
        read_url(url, scope, method="GET", timeout=2)
    except CliError:
        return False
    return True
