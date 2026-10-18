"""Report whether this machine can run a local scan."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from insidia.config import Project, Target, load_project, resolve_secret
from insidia.errors import CliError, HttpStatus
from insidia.scope import LOCAL_HOSTS, ScopeHost, check_url
from insidia.transport import read_url, repo_path


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
            checks.extend(_target_checks(project, config_path))
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


def _target_checks(project: Project, config_path: Path) -> list[dict[str, object]]:
    root = config_path.resolve().parent
    return [_target_check(target, project.scope, root) for target in project.targets]


def _target_check(
    target: Target, scope: tuple[ScopeHost, ...], root: Path
) -> dict[str, object]:
    """One scope-checked reachability probe. Non-local targets are not contacted."""
    name = f"target.{target.name}"
    if target.kind == "repo":
        return _repo_target(name, target, root)
    if target.url is None:
        if target.command:
            detail = f"{target.name}: local commands are not available in this release"
        else:
            detail = f"{target.name} needs a url"
        return {"name": name, "ok": False, "detail": detail}
    try:
        host = check_url(target.url, scope)
    except CliError as exc:
        return {"name": name, "ok": False, "detail": str(exc)}
    if host not in LOCAL_HOSTS:
        return {
            "name": name,
            "ok": True,
            "detail": "authorized non-local host, not probed by doctor",
        }
    ok, detail = _probe_target(target.url, scope)
    return {"name": name, "ok": ok, "detail": detail}


def _repo_target(name: str, target: Target, root: Path) -> dict[str, object]:
    try:
        path = repo_path(target, root)
    except CliError as exc:
        return {"name": name, "ok": False, "detail": str(exc)}
    if not path.exists():
        return {"name": name, "ok": False, "detail": f"{path} does not exist"}
    return {"name": name, "ok": True, "detail": "reachable"}


def _probe_target(url: str, scope: tuple[ScopeHost, ...]) -> tuple[bool, str]:
    """Same scope-checked GET as a model probe. An HTTP error still means it answered."""
    try:
        read_url(url, scope, method="GET", timeout=2)
    except HttpStatus:
        return True, "reachable"
    except CliError as exc:
        return False, f"{url}: {exc}"
    return True, "reachable"


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
