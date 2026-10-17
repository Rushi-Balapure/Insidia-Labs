"""Report whether this machine can run a local scan."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from insidia.config import Project, load_project, resolve_secret
from insidia.errors import CliError
from insidia.scope import ScopeHost, check_url
from insidia.transport import read_url


def diagnose(config_path: Path) -> tuple[list[dict[str, object]], int]:
    checks: list[dict[str, object]] = []
    python_ok = sys.version_info >= (3, 12)
    checks.append({"name": "python", "ok": python_ok, "detail": sys.version.split()[0]})
    if config_path.is_file():
        try:
            project = load_project(config_path)
        except CliError as exc:
            checks.append({"name": "config", "ok": False, "detail": str(exc)})
        else:
            checks.append({"name": "config", "ok": True, "detail": str(config_path.name)})
            checks.extend(_model_checks(project))
    else:
        checks.append({"name": "config", "ok": False, "detail": f"missing {config_path.name}"})
    docker = shutil.which("docker")
    checks.append(
        {
            "name": "docker",
            "ok": docker is not None,
            "required": False,
            "detail": (
                "found"
                if docker
                else "not found; optional unless you use insidia engines install --docker"
            ),
        }
    )
    from insidia.engines import installed_engines, unusable_engines

    names = ", ".join(["insidia", *sorted(installed_engines())])
    checks.append({"name": "engines", "ok": True, "detail": f"installed: {names}"})
    for name, needs in sorted(unusable_engines().items()):
        checks.append(
            {
                "name": f"engine.{name}",
                "ok": False,
                "required": False,
                "detail": f"downloaded but cannot run: needs {needs}",
            }
        )
    code = 0 if _required_ok(checks) else 2
    return checks, code


def _required_ok(checks: list[dict[str, object]]) -> bool:
    return all(bool(check["ok"]) or check.get("required") is False for check in checks)


def _model_checks(project: Project) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for role in (project.attacker, project.judge):
        if role is None:
            continue
        if role.secret_ref:
            try:
                resolve_secret(role.secret_ref)
            except CliError as exc:
                checks.append(
                    {"name": f"model.{role.name}", "ok": False, "detail": str(exc)}
                )
                continue
        if role.base_url is None:
            continue
        try:
            check_url(role.base_url, project.scope)
        except CliError as exc:
            checks.append({"name": f"model.{role.name}", "ok": False, "detail": str(exc)})
            continue
        ok, detail = _probe_model(role.base_url, project.scope)
        checks.append({"name": f"model.{role.name}", "ok": ok, "detail": detail})
    return checks


def _probe_model(url: str, scope: tuple[ScopeHost, ...]) -> tuple[bool, str]:
    try:
        read_url(url, scope, method="GET", timeout=2)
    except CliError as exc:
        return False, str(exc)
    return True, url
