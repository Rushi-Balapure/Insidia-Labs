"""Child processes for engine installs and scans.

The environment is an allowlist. Proxy variables and the parent process's
secrets are not copied. A timeout kills the process group.
"""

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Mapping
from pathlib import Path

from insidia.errors import EngineFailed

_ALLOW = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
)
_PROXIES = frozenset({"http_proxy", "https_proxy", "all_proxy", "no_proxy"})


def child_env(extra: Mapping[str, str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in _ALLOW:
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in extra.items():
        if _blocked(key):
            continue
        env[key] = value
    return env


def _command_argv(program: str, args: tuple[str, ...]) -> list[str]:
    """Run a Windows console script with the venv interpreter.

    uv stamps ``garak.exe`` with the interpreter path from the staging
    directory. Publishing renames that directory, so the stamp no longer
    exists and the launcher exits before the probe runs. The sibling
    ``python.exe`` still points at the base interpreter, and it executes
    the script zip appended to the launcher.
    """
    return _argv_for(os.name, program, args)


def _argv_for(system: str, program: str, args: tuple[str, ...]) -> list[str]:
    path = Path(program)
    if system != "nt" or path.suffix.lower() != ".exe":
        return [program, *args]
    if path.name.lower() in {"python.exe", "pythonw.exe"}:
        return [program, *args]
    python = path.with_name("python.exe")
    if not python.is_file():
        return [program, *args]
    return [str(python), program, *args]


def run_command(
    argv: list[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str],
    timeout: float,
    name: str | None = None,
) -> tuple[int, str]:
    label = name or Path(argv[0]).name
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=child_env(env),
        shell=False,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        raise EngineFailed(f"{label} timed out") from None
    code = proc.returncode
    detail = stderr.decode("utf-8", errors="replace").strip()
    return (1 if code is None else code), detail[-400:]


def launch_installed(invocation: object, workspace: Path) -> None:
    from insidia.adapters import Invocation

    if not isinstance(invocation, Invocation):
        raise EngineFailed("launch received an unexpected invocation")
    program = Path(invocation.program)
    if not program.is_file():
        raise EngineFailed(f"{program.name} is not installed")
    try:
        code, detail = run_command(
            _command_argv(invocation.program, invocation.args),
            cwd=workspace,
            env=invocation.env,
            timeout=invocation.timeout,
            name=program.name,
        )
    except OSError as exc:
        raise EngineFailed(f"{program.name}: {exc}") from exc
    report = workspace / invocation.report
    if code != 0 and not report.is_file():
        extra = f": {detail}" if detail else ""
        raise EngineFailed(f"{program.name} exited {code}{extra}")


def _blocked(key: str) -> bool:
    lowered = key.lower()
    return lowered in _PROXIES or lowered.endswith("_proxy")


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
