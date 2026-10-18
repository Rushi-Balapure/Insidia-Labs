"""TC-F1 checks for the scan action. Static files and local runs only.

TC-F1-P1, TC-F1-P2, and TC-F1-N7 need a real GitHub Actions run and are not
executed here. TC-F1-N4 and the SARIF shape check are local proxies, not those
Actions runs.

Set TC_F1_ROOT to point the file checks at a copy of the tree.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import yaml
from insidia.cli import main

_PROXY = "http://127.0.0.1:9"
_NO_PROXY = "127.0.0.1,localhost"
_SHA = re.compile(r"^[0-9a-f]{40}$")
# QA plan step for TC-F1-N1: no inputs.* or github.* inside a run script.
_UNTRUSTED_RUN = re.compile(r"\$\{\{\s*(inputs|github)\.")
_EXPRESSION = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
_ONE_INPUT = re.compile(r"^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$")
_POLICY_PAYLOADS = ("$(id)", '"; echo pwned')
_BLANK_VERSIONS = ("", " ", "   ", "\t")
_SCAN_PERMISSIONS = {"contents": "read", "security-events": "write"}
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}

_P1_REASON = (
    "NOT AUTOMATABLE. TC-F1-P1 needs a real GitHub Actions run on "
    "Rushi-Balapure/Insidia-Labs, not a local shell replay. "
    "Trigger .github/workflows/insidia-scan.yml from a pull request or "
    "workflow_dispatch. The job must use ./actions/scan, install the version "
    "input, and run `insidia scan --policy L1 --yes` against a vulnerable "
    "fixture bound to 127.0.0.1 (the QA plan uses web.py on 127.0.0.1:8090; "
    "the checked-in example listens on 127.0.0.1:8765 and is not that fixture). "
    "The scan step must exit 1 and the job must fail. Save `gh run view <id> "
    "--log` and `gh run download <id>`. Artifacts must include non-empty "
    "report.html, findings.json, and results.sarif. The log must show that "
    "pinned version, and the scan must contact only 127.0.0.1."
)

_N7_REASON = (
    "NOT AUTOMATABLE. TC-F1-N7 needs a real GitHub Actions run on "
    "Rushi-Balapure/Insidia-Labs, not a local shell replay. On a pull request, "
    "set the ./actions/scan version input to a pin that does not match the "
    "action checkout core/pyproject.toml (for example 9.9.9 while that file is "
    "0.1.0). Trigger .github/workflows/insidia-scan.yml from the pull request "
    "or workflow_dispatch. The Install Insidia step must exit 1 with a clear "
    "non-empty error that the action core version does not match the input. "
    "`uv` must not run, and the log must not show `uv tool install "
    "insidia==<version>`, `pip install insidia`, or `pipx install insidia`. "
    "Save `gh run view <id> --log`. test_tc_f1_n6_missing_or_mismatched_core_does_not_call_uv "
    "is the local replay. It is not TC-F1-N7."
)

_P2_REASON = (
    "NOT AUTOMATABLE. TC-F1-P2 needs the TC-F1-P1 Actions run to have uploaded "
    "SARIF with github/codeql-action/upload-sarif, and code scanning enabled "
    "on Rushi-Balapure/Insidia-Labs. Then open Security → Code scanning alerts "
    "for the PR branch and tool Insidia, and run `gh api "
    "repos/Rushi-Balapure/Insidia-Labs/code-scanning/alerts?ref=refs/pull/<n>/merge`. "
    "Each alert needs a rule id that matches results.sarif, a location, and help "
    "text. Messages must be masked. The alert count must equal the SARIF result "
    "count. Capture a screenshot of that view. "
    "test_tc_f1_p2_sarif_shape_local_proxy only checks the SARIF file the CLI "
    "writes. It is not TC-F1-P2."
)


def _root() -> Path:
    override = os.environ.get("TC_F1_ROOT")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2]


def _load(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text())
    assert isinstance(loaded, dict)
    return loaded


def _action_path() -> Path:
    return _root() / "actions" / "scan" / "action.yml"


def _action() -> dict[str, Any]:
    return _load(_action_path())


def _workflow_paths() -> list[Path]:
    directory = _root() / ".github" / "workflows"
    paths = sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml"))
    assert paths, directory
    return paths


def _walk(node: object, visit: Any) -> None:
    if isinstance(node, dict):
        visit(node)
        for value in node.values():
            _walk(value, visit)
    elif isinstance(node, list):
        for item in node:
            _walk(item, visit)


def _run_scripts(document: object) -> list[str]:
    scripts: list[str] = []

    def visit(node: dict[str, Any]) -> None:
        run = node.get("run")
        if isinstance(run, str):
            scripts.append(run)

    _walk(document, visit)
    return scripts


def _uses(document: object) -> list[str]:
    found: list[str] = []

    def visit(node: dict[str, Any]) -> None:
        uses = node.get("uses")
        if isinstance(uses, str):
            found.append(uses)

    _walk(document, visit)
    return found


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps = document["runs"]["steps"]
    assert isinstance(steps, list)
    return steps


def _scan_step(document: dict[str, Any]) -> dict[str, Any]:
    for step in _steps(document):
        script = step.get("run", "")
        if isinstance(script, str) and "insidia scan" in script:
            return step
    raise AssertionError("action has no insidia scan run step")


def _steps_before_scan(document: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for step in _steps(document):
        if "run" not in step:
            continue
        script = step["run"]
        if not isinstance(script, str):
            continue
        if "insidia scan" in script:
            break
        found.append(step)
    assert found, "version is not checked before the scan step"
    return found


def _expand_run(script: str, inputs: Mapping[str, str]) -> str:
    """Insert ${{ }} the way GitHub expands a run script before bash starts."""

    def replace(match: re.Match[str]) -> str:
        body = match.group(1).strip()
        if body.startswith("inputs."):
            name = body.removeprefix("inputs.").strip()
            if name not in inputs:
                raise AssertionError(f"run script expands unknown input {name}")
            return inputs[name]
        if body.startswith("github."):
            return inputs.get(body, "$(id)")
        return match.group(0)

    return _EXPRESSION.sub(replace, script)


def _env_from_step(step: Mapping[str, Any], inputs: Mapping[str, str]) -> dict[str, str]:
    raw = step.get("env", {})
    assert isinstance(raw, dict)
    resolved: dict[str, str] = {}
    for key, value in raw.items():
        text = str(value).strip()
        match = _ONE_INPUT.fullmatch(text)
        if match:
            name = match.group(1)
            if name not in inputs:
                raise AssertionError(f"env {key} reads unknown input {name}")
            resolved[str(key)] = inputs[name]
        else:
            resolved[str(key)] = _expand_run(str(value), inputs)
    return resolved


def _require_bash() -> str:
    if sys.platform == "win32":
        pytest.skip("the action's bash steps are executed on Unix")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the action shell steps")
    return bash


def _offline_dirs(store: Path) -> None:
    for name in ("home", "engines", "uv-cache", "uv-tools", "xdg"):
        (store / name).mkdir(parents=True)


def _offline_env(store: Path, path_prefix: Path | None = None) -> dict[str, str]:
    _offline_dirs(store)
    env = os.environ.copy()
    for key in ("ALL_PROXY", "all_proxy", "INSIDIA_VULN_DB"):
        env.pop(key, None)
    env.update(
        {
            "HTTP_PROXY": _PROXY,
            "HTTPS_PROXY": _PROXY,
            "http_proxy": _PROXY,
            "https_proxy": _PROXY,
            "NO_PROXY": _NO_PROXY,
            "no_proxy": _NO_PROXY,
            "HOME": str(store / "home"),
            "INSIDIA_TOOLCHAIN": str(store / "engines"),
            "UV_CACHE_DIR": str(store / "uv-cache"),
            "UV_TOOL_DIR": str(store / "uv-tools"),
            "XDG_CACHE_HOME": str(store / "xdg"),
        }
    )
    if path_prefix is not None:
        env["PATH"] = str(path_prefix) + os.pathsep + env.get("PATH", "")
    return env


def _assert_nothing_fetched(store: Path) -> None:
    files = sorted(path for path in store.rglob("*") if path.is_file())
    assert not files, "fetched files: " + ", ".join(str(path) for path in files)


def _bash(
    bash: str, script: str, env: dict[str, str], work: Path
) -> subprocess.CompletedProcess[str]:
    path = work / "step.sh"
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return subprocess.run(
        [bash, "--noprofile", "--norc", str(path)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _blob(result: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(
        (
            f"exit={result.returncode}",
            "--- stdout ---",
            result.stdout,
            "--- stderr ---",
            result.stderr,
        )
    )


def _assert_not_executed(blob: str) -> None:
    if "uid=" in blob:
        raise AssertionError(f"command substitution ran:\n{blob}")
    if any(line.strip() == "pwned" for line in blob.splitlines()):
        raise AssertionError(f"payload command ran:\n{blob}")


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _tool_stub(directory: Path, log: Path, *, code: int = 99) -> None:
    directory.mkdir(parents=True)
    for name in ("uv", "pip", "pip3", "pipx"):
        _write_executable(
            directory / name,
            "#!/bin/sh\n"
            f"printf '%s\\n' {name} \"$*\" >> {shlex.quote(str(log))}\n"
            f"exit {code}\n",
        )




def _insidia_shim(directory: Path, connect_log: Path) -> None:
    guard = directory / "pyguard"
    guard.mkdir(parents=True)
    (guard / "sitecustomize.py").write_text(
        "import os\n"
        "import socket\n"
        "_log = os.environ.get('TC_F1_CONNECT_LOG', '')\n"
        "_dns = socket.getaddrinfo\n"
        "_connect = socket.socket.connect\n"
        "_allowed = {'127.0.0.1', 'localhost', '::1'}\n"
        "def _record(kind, host, port):\n"
        "    if not _log:\n"
        "        return\n"
        "    with open(_log, 'a', encoding='utf-8') as handle:\n"
        "        handle.write(f'{kind} {host} {port}\\n')\n"
        "def getaddrinfo(host, port, *args, **kwargs):\n"
        "    text = host.decode() if isinstance(host, bytes) else str(host)\n"
        "    if text not in _allowed:\n"
        "        _record('dns', text, port)\n"
        "        raise socket.gaierror(socket.EAI_NONAME, 'blocked')\n"
        "    return _dns(host, port, *args, **kwargs)\n"
        "def connect(self, address):\n"
        "    host, port = address[0], address[1]\n"
        "    if str(host) not in _allowed or int(port) == 9:\n"
        "        _record('connect', host, port)\n"
        "        raise OSError('blocked')\n"
        "    return _connect(self, address)\n"
        "socket.getaddrinfo = getaddrinfo\n"
        "socket.socket.connect = connect\n"
    )
    _write_executable(
        directory / "insidia",
        f"#!{sys.executable}\n"
        "import sys\n"
        "from insidia.cli import main\n"
        "raise SystemExit(main())\n",
    )


def _local_config(work: Path, body: str) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    path = work / "insidia.yaml"
    path.write_text(body)
    return path


class _NetGuard:
    """Record non-loopback DNS and connects, and refuse them before they happen."""

    def __init__(self) -> None:
        self.blocked: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_dns = socket.getaddrinfo
        real_connect = socket.socket.connect

        def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            text = host.decode() if isinstance(host, bytes) else str(host)
            if text not in _LOOPBACK:
                self.blocked.append(f"dns {text}")
                raise socket.gaierror(socket.EAI_NONAME, f"blocked {text}")
            return real_dns(host, port, *args, **kwargs)

        def connect(sock: socket.socket, address: Any) -> Any:
            if isinstance(address, tuple) and len(address) >= 2:
                host, port = str(address[0]), int(address[1])
                if host in _LOOPBACK and port != 9:
                    return real_connect(sock, address)
            self.blocked.append(f"connect {address!r}")
            raise OSError(f"blocked {address!r}")

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket.socket, "connect", connect)


def _bind_offline(monkeypatch: pytest.MonkeyPatch, store: Path) -> _NetGuard:
    _offline_dirs(store)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("http_proxy", _PROXY)
    monkeypatch.setenv("https_proxy", _PROXY)
    monkeypatch.setenv("NO_PROXY", _NO_PROXY)
    monkeypatch.setenv("no_proxy", _NO_PROXY)
    monkeypatch.setenv("HOME", str(store / "home"))
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(store / "engines"))
    monkeypatch.setenv("UV_CACHE_DIR", str(store / "uv-cache"))
    monkeypatch.setenv("UV_TOOL_DIR", str(store / "uv-tools"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(store / "xdg"))
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    monkeypatch.delenv("INSIDIA_VULN_DB", raising=False)
    guard = _NetGuard()
    guard.install(monkeypatch)
    return guard


def _assert_pinned(uses: str) -> None:
    if uses.startswith("./") and "@" not in uses:
        return
    pin = uses.rsplit("@", 1)[-1]
    assert _SHA.fullmatch(pin), f"unpinned uses: {uses}"


def _uses_in_text(text: str) -> list[str]:
    return re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", text)


def test_tc_f1_n1_run_scripts_do_not_expand_untrusted_expressions() -> None:
    """TC-F1-N1 static half. inputs.* and github.* stay out of every run script."""
    documents = [(_action_path(), _action())]
    documents.extend((path, _load(path)) for path in _workflow_paths())
    saw_script = False
    for path, document in documents:
        for script in _run_scripts(document):
            saw_script = True
            found = _UNTRUSTED_RUN.search(script)
            if found is not None:
                snippet = script[found.start() : found.end() + 32].splitlines()[0]
                raise AssertionError(f"{path}: untrusted expression in run script: {snippet}")
    assert saw_script


def test_tc_f1_n1_policy_payload_is_not_executed(tmp_path: Path) -> None:
    """TC-F1-N1 dynamic half. Policy reaches insidia as one argument.

    On 513e904 argparse rejects anything except L1, L2, or L3 before a scan
    (`invalid choice`, exit 2). The job still fails and the payload is not run.
    """
    bash = _require_bash()
    step = _scan_step(_action())
    for payload in _POLICY_PAYLOADS:
        work = tmp_path / f"run-{_POLICY_PAYLOADS.index(payload)}"
        work.mkdir()
        store = work / "empty"
        connect_log = work / "connect.log"
        bin_dir = work / "bin"
        _insidia_shim(bin_dir, connect_log)
        _local_config(
            work,
            "version: 1\npolicy: L1\ncoverage: standard\nscope:\n  - host: 127.0.0.1\n"
            "targets:\n  local:\n    kind: web\n    url: http://127.0.0.1:9/hello\n"
            "    method: GET\n",
        )
        inputs = {"policy": payload, "fail-on-inconclusive": "true"}
        script = _expand_run(str(step["run"]), inputs)
        env = _offline_env(store, bin_dir)
        env.update(_env_from_step(step, inputs))
        env["PYTHONPATH"] = str(bin_dir / "pyguard")
        env["TC_F1_CONNECT_LOG"] = str(connect_log)
        result = _bash(bash, script, env, work)
        blob = _blob(result)
        _assert_not_executed(blob)
        assert result.returncode == 2, blob
        assert payload in blob, blob
        rejected = "unknown policy" in blob or "invalid choice" in blob
        assert rejected, blob
        recorded = connect_log.read_text() if connect_log.exists() else ""
        assert recorded == "", recorded
        _assert_nothing_fetched(store)


def test_tc_f1_n2_blank_version_fails_before_install(tmp_path: Path) -> None:
    """TC-F1-N2. An empty or whitespace version fails before uv or pip runs."""
    bash = _require_bash()
    steps = _steps_before_scan(_action())
    log = tmp_path / "tools.log"
    bin_dir = tmp_path / "bin"
    _tool_stub(bin_dir, log)
    for version in _BLANK_VERSIONS:
        log.write_text("")
        for index, step in enumerate(steps):
            work = tmp_path / f"v{index}-{version!r}"
            work.mkdir()
            store = work / "empty"
            inputs = {"version": version}
            script = _expand_run(str(step["run"]), inputs)
            env = _offline_env(store, bin_dir)
            env.update(_env_from_step(step, inputs))
            result = _bash(bash, script, env, work)
            blob = _blob(result)
            called = log.read_text()
            assert called == "", f"install started for {version!r}:\n{called}"
            assert result.returncode == 1, f"version gate did not fail fast\n{blob}"
            assert "version" in blob.lower(), blob
            assert "pip install" not in blob
            assert "insidia==" not in blob
            _assert_nothing_fetched(store)


def _install_step(document: dict[str, Any]) -> dict[str, Any]:
    for step in _steps(document):
        script = step.get("run", "")
        if isinstance(script, str) and "uv tool install" in script:
            return step
    raise AssertionError("action has no install step")


def _tool_calls(log: str) -> list[tuple[str, str]]:
    lines = log.splitlines()
    return [(lines[index], lines[index + 1]) for index in range(0, len(lines) - 1, 2)]


def _index_insidia(tool: str, args: str) -> bool:
    """True when a recorded command installs the PyPI name insidia."""
    if tool not in {"uv", "pip", "pip3", "pipx"} or "install" not in args.split():
        return False
    for token in args.split():
        cleaned = token.strip("'\"")
        if cleaned == "insidia" or cleaned.startswith(("insidia==", "insidia[")):
            return True
    return False


def _owned_core_install(tool: str, args: str, core: Path, work: Path) -> bool:
    if tool != "uv" or "install" not in args.split():
        return False
    wanted = core.resolve()
    skip = {"tool", "install", "python", "3.12", "--python", "--force"}
    for token in args.split():
        cleaned = token.strip("'\"")
        if not cleaned or cleaned.startswith("-") or cleaned in skip:
            continue
        candidate = Path(cleaned)
        if not candidate.is_absolute():
            candidate = work / candidate
        try:
            if candidate.resolve() == wanted:
                return True
        except OSError:
            continue
    return False


# An install of the bare name, or insidia==<version>, from an index.
_BARE_INDEX_INSTALL = re.compile(
    r"""(?x)
    (?: \b(?:pip3?|pipx)\s+install\b | \buv\s+(?:tool\s+|pip\s+)?install\b )
    [^\n]*?
    (?:^|[\s"'=])insidia(?:==|\s|["']|$)
    """
)


def _index_install_lines(document: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    for script in _run_scripts(document):
        hits.extend(
            line.strip() for line in script.splitlines() if _BARE_INDEX_INSTALL.search(line)
        )
    return hits


def _action_install_claim(document: dict[str, Any]) -> str:
    scripts = "\n".join(_run_scripts(document))
    has_index = bool(_index_install_lines(document))
    has_core = "uv tool install" in scripts and (
        "INSIDIA_CORE" in scripts or "./core" in scripts
    )
    if has_index and has_core:
        return "checkout-then-pypi"
    if has_index:
        return "pypi"
    if has_core:
        return "checkout-only"
    return "unclear"


def _install_statements(text: str) -> list[str]:
    action_part = text.split("## Upload SARIF yourself", 1)[0]
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", action_part) if part.strip()]
    return [part for part in paragraphs if "pypi" in part.lower()]


def _statement_claim(statement: str) -> str:
    lowered = statement.lower()
    pypi_first = "from pypi when" in lowered or "when it is not on pypi" in lowered
    checkout_then_pypi = "tries pypi" in lowered or "pypi only when" in lowered
    checkout_only = (
        "never" in lowered
        and "pypi" in lowered
        and "checkout" in lowered
        and not pypi_first
        and not checkout_then_pypi
    )
    claims = [
        name
        for name, present in (
            ("pypi-first", pypi_first),
            ("checkout-then-pypi", checkout_then_pypi),
            ("checkout-only", checkout_only),
        )
        if present
    ]
    if len(claims) == 1:
        return claims[0]
    return "unclear"


def _guide_path() -> Path:
    return _root() / "docs" / "src" / "content" / "docs" / "guides" / "ci.md"


def test_tc_f1_n5_static_install_source_agrees() -> None:
    """TC-F1-N5. action.yml never installs insidia by bare name or index.

    The two install statements in guides/ci.md must not contradict each other
    or that action.
    """
    document = _action()
    problems: list[str] = []
    hits = _index_install_lines(document)
    if hits:
        problems.append(
            "action.yml installs insidia from PyPI by bare name or index: " + " | ".join(hits)
        )
    statements = _install_statements(_guide_path().read_text())
    if len(statements) != 2:
        problems.append(
            f"expected the two install statements in guides/ci.md, found {len(statements)}"
        )
    claims = [_statement_claim(statement) for statement in statements]
    if len(claims) == 2 and claims[0] != claims[1]:
        problems.append(
            "guides/ci.md install statements contradict each other: "
            f"{claims[0]} vs {claims[1]}"
        )
    action_claim = _action_install_claim(document)
    for claim, statement in zip(claims, statements, strict=False):
        if claim != action_claim:
            problems.append(
                f"guides/ci.md contradicts the action ({action_claim} vs {claim}): {statement}"
            )
    if problems:
        raise AssertionError("\n\n".join(problems))


def _replay_install(
    bash: str, work: Path, version: str, core_version: str | None
) -> tuple[subprocess.CompletedProcess[str], str, Path]:
    action_dir = work / "actions" / "scan"
    action_dir.mkdir(parents=True)
    core = work / "core"
    if core_version is not None:
        core.mkdir()
        (core / "pyproject.toml").write_text(
            f'[project]\nname = "insidia"\nversion = "{core_version}"\n'
        )
    log = work / "tools.log"
    bin_dir = work / "bin"
    _tool_stub(bin_dir, log, code=0)
    store = work / "empty"
    step = _install_step(_action())
    inputs = {"version": version, "github.action_path": str(action_dir)}
    script = _expand_run(str(step["run"]), inputs)
    env = _offline_env(store, bin_dir)
    env.update(_env_from_step(step, inputs))
    result = _bash(bash, script, env, work)
    recorded = log.read_text() if log.exists() else ""
    return result, recorded, core


def test_tc_f1_n6_missing_or_mismatched_core_does_not_call_uv(tmp_path: Path) -> None:
    """TC-F1-N6. No matching core exits 1 before uv runs.

    A missing core/ and a core/pyproject.toml version other than the input
    each fail with a clear non-empty error. The stub uv records arguments
    and must not be called.
    """
    bash = _require_bash()
    cases = (
        ("core-absent", None),
        ("version-mismatch", "9.9.9"),
    )
    problems: list[str] = []
    for label, core_version in cases:
        work = tmp_path / label
        result, recorded, _core = _replay_install(bash, work, "0.1.0", core_version)
        blob = _blob(result)
        calls = _tool_calls(recorded)
        uv_calls = [args for tool, args in calls if tool == "uv"]
        case_problems: list[str] = []
        if result.returncode != 1:
            case_problems.append(f"exit={result.returncode}, expected 1")
        if uv_calls:
            case_problems.append("uv was called: " + "; ".join(uv_calls))
        if not result.stderr.strip():
            case_problems.append("error message is empty")
        elif "error" not in result.stderr.lower():
            case_problems.append(f"error message is not clear: {result.stderr!r}")
        if case_problems:
            problems.append(f"{label}: " + "; ".join(case_problems) + "\n" + blob)
        else:
            try:
                _assert_nothing_fetched(work / "empty")
            except AssertionError as exc:
                problems.append(f"{label}: {exc}")
    if problems:
        raise AssertionError("\n\n".join(problems))


def test_tc_f1_p5_matching_version_installs_the_action_core(tmp_path: Path) -> None:
    """TC-F1-P5. A matching version installs the action checkout core.

    uv may install Python. The only package it installs is that core path.
    A bare insidia== spec is a failure.
    """
    bash = _require_bash()
    work = tmp_path / "match"
    result, recorded, core = _replay_install(bash, work, "0.1.0", "0.1.0")
    blob = _blob(result)
    assert result.returncode == 0, blob
    calls = _tool_calls(recorded)
    uv_calls = [args for tool, args in calls if tool == "uv"]
    assert uv_calls, f"uv was not called\n{blob}"
    for tool, args in calls:
        if _index_insidia(tool, args):
            raise AssertionError(f"bare insidia spec: {tool} {args}\n{blob}")
    package = [
        (tool, args)
        for tool, args in calls
        if not (tool == "uv" and args.split()[:2] == ["python", "install"])
        and "install" in args.split()
    ]
    assert package, f"uv did not install the action core\n{recorded}\n{blob}"
    for tool, args in package:
        if not _owned_core_install(tool, args, core, work):
            raise AssertionError(
                f"uv installed something other than the action core: {tool} {args}"
            )
    _assert_nothing_fetched(work / "empty")


def test_tc_f1_n3_uses_are_pinned_and_scan_workflow_permissions_are_minimal() -> None:
    """TC-F1-N3. SHA-pin every uses. Permissions are the workflow's, not action.yml.

    GitHub ignores a permissions block inside a composite action. The scan
    workflow must grant exactly contents: read and security-events: write.
    """
    action_uses = _uses(_action())
    assert action_uses
    for uses in action_uses:
        _assert_pinned(uses)
    sarif_workflows = 0
    for path in _workflow_paths():
        document = _load(path)
        uses_values = _uses(document)
        for uses in uses_values:
            _assert_pinned(uses)
        if not any(uses == "./actions/scan" or "upload-sarif" in uses for uses in uses_values):
            continue
        sarif_workflows += 1
        permissions = document.get("permissions")
        assert permissions == _SCAN_PERMISSIONS, f"{path} permissions {permissions!r}"
        jobs = document.get("jobs")
        assert isinstance(jobs, dict)
        for name, job in jobs.items():
            assert isinstance(job, dict)
            if "permissions" in job:
                assert job["permissions"] == _SCAN_PERMISSIONS, f"{path} job {name}"
    assert sarif_workflows >= 1


def test_tc_f1_p3_exit_codes_and_fail_on_inconclusive_default(tmp_path: Path) -> None:
    """TC-F1-P3. Exit 0 passes, exit 1 fails, exit 2 follows fail-on-inconclusive.

    The input default is true, so an inconclusive scan fails the job.
    """
    bash = _require_bash()
    document = _action()
    assert "fail-on-2" not in document["inputs"]
    default = document["inputs"]["fail-on-inconclusive"]["default"]
    assert default == "true", f"fail-on-inconclusive default must be true, found {default!r}"
    step = _scan_step(document)
    assert step["env"]["INSIDIA_FAIL_ON_INCONCLUSIVE"] == "${{ inputs.fail-on-inconclusive }}"
    cases = (
        (0, "true", 0, False),
        (0, "false", 0, False),
        (1, "true", 1, False),
        (1, "false", 1, False),
        (2, default, 2, False),
        (2, "false", 0, True),
    )
    for code, flag, expected, warning in cases:
        work = tmp_path / f"code-{code}-{flag}"
        work.mkdir()
        store = work / "empty"
        bin_dir = work / "bin"
        bin_dir.mkdir()
        _write_executable(
            bin_dir / "insidia",
            "#!/bin/sh\nprintf '%s\\n' \"insidia-argv:$*\"\n" + f"exit {code}\n",
        )
        inputs = {"policy": "L1", "fail-on-inconclusive": flag}
        script = _expand_run(str(step["run"]), inputs)
        env = _offline_env(store, bin_dir)
        env.update(_env_from_step(step, inputs))
        result = _bash(bash, script, env, work)
        blob = _blob(result)
        assert result.returncode == expected, blob
        assert (result.returncode != 0) is (expected != 0)
        assert "insidia-argv:scan --policy L1 --yes" in result.stdout, blob
        if warning:
            assert "scan was inconclusive" in result.stderr, blob
            assert "fail-on-inconclusive is false" in result.stderr, blob
        else:
            assert "inconclusive" not in result.stderr, blob
        _assert_nothing_fetched(store)


def test_tc_f1_p4_docs_describe_the_action_and_the_manual_upload() -> None:
    """TC-F1-P4. The CI guide documents the action and keeps manual SARIF upload."""
    path = _root() / "docs" / "src" / "content" / "docs" / "guides" / "ci.md"
    text = path.read_text()
    if "## Upload SARIF yourself" not in text:
        raise AssertionError(f"{path}: manual SARIF upload section is missing")
    action_part, manual_part = text.split("## Upload SARIF yourself", 1)
    assert "actions/scan" in action_part
    assert "fail-on-inconclusive" in action_part
    assert "version:" in action_part
    assert "policy:" in action_part
    assert "contents: read" in action_part
    assert "security-events: write" in action_part
    assert "uses: github/codeql-action/upload-sarif@" in manual_part
    uses_values = _uses_in_text(text)
    assert uses_values
    for uses in uses_values:
        _assert_pinned(uses)


_OUT_OF_SCOPE = "qa-out-of-scope.invalid"


def _scope_config(host_in_scope: bool, target_host: str) -> str:
    scope_host = target_host if host_in_scope else "127.0.0.1"
    return (
        "version: 1\npolicy: L1\ncoverage: standard\nscope:\n"
        f"  - host: {scope_host}\n"
        "targets:\n  app:\n    kind: web\n"
        f"    url: http://{target_host}/admin\n"
        "    method: GET\n"
    )


def _assert_scope_refusal(code: int, output: str, message: str) -> None:
    assert code == 2, output
    assert message in output, output
    assert _OUT_OF_SCOPE in output


def test_tc_f1_n4_local_scope_guard_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Partial local proxy for TC-F1-N4, not the full Actions case.

    The full case runs the example workflow on GitHub Actions for a 127.0.0.1
    service and for qa-out-of-scope.invalid, then checks the job result and
    artifacts. This runs `insidia scan --yes` locally. --yes does not authorize
    a host. The out-of-scope name is refused before any DNS lookup.
    """
    store = tmp_path / "empty"
    guard = _bind_offline(monkeypatch, store)
    refused = (
        (False, "not in scope"),
        (True, "needs authorized: true"),
    )
    for in_scope, message in refused:
        label = re.sub(r"[^a-z0-9]+", "-", message)
        config = _local_config(tmp_path / label, _scope_config(in_scope, _OUT_OF_SCOPE))
        code = main(["scan", "--config", str(config), "--yes", "--quiet"])
        output = capsys.readouterr().out
        _assert_scope_refusal(code, output, message)
    assert guard.blocked == [], guard.blocked
    _assert_nothing_fetched(store)

    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(self.path)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    assert server.server_address[0] == "127.0.0.1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    try:
        local = tmp_path / "local"
        local.mkdir()
        _local_config(
            local,
            "version: 1\npolicy: L1\ncoverage: standard\nscope:\n  - host: 127.0.0.1\n"
            "targets:\n  local:\n    kind: web\n"
            f"    url: http://127.0.0.1:{port}/ping\n    method: GET\n    timeout: 2\n"
            "    rate_limit:\n      rps: 100\n      concurrency: 4\n    query:\n"
            '      host: "{{payload}}"\n',
        )
        code = main(["scan", "--config", str(local / "insidia.yaml"), "--yes", "--quiet"])
        output = capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert seen, "scope guard refused the 127.0.0.1 fixture before any request"
    assert "not in scope" not in output
    assert "needs authorized" not in output
    assert code in {0, 1, 2}
    assert guard.blocked == [], guard.blocked
    _assert_nothing_fetched(store)


@pytest.mark.skip(reason=_P1_REASON)
def test_tc_f1_p1_live_github_actions_run_not_automated() -> None:
    """TC-F1-P1 is a live Actions run. Do not fake the job result or artifacts."""
    raise AssertionError("TC-F1-P1 must not be faked locally")


@pytest.mark.skip(reason=_P2_REASON)
def test_tc_f1_p2_live_code_scanning_not_automated() -> None:
    """TC-F1-P2 is the code scanning UI. Do not fake alerts."""
    raise AssertionError("TC-F1-P2 must not be faked locally")


@pytest.mark.skip(reason=_N7_REASON)
def test_tc_f1_n7_version_mismatch_on_actions_runner_not_automated() -> None:
    """TC-F1-N7 is a version mismatch on a real Actions runner. Do not fake it."""
    raise AssertionError("TC-F1-N7 must not be faked locally")


@contextmanager
def _vulnerable_server() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            query = parse_qs(urlparse(self.path).query)
            value = next(iter(query.values()), [""])[0]
            if any(mark in value for mark in (";", "&&", "|", "$(", "`")):
                body = b"uid=1000(app) gid=1000(app) groups=1000(app)\n"
            else:
                body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    assert server.server_address[0] == "127.0.0.1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _assert_sarif_shape(document: dict[str, Any]) -> None:
    assert document.get("version") == "2.1.0"
    assert "sarif-2.1.0" in str(document.get("$schema", ""))
    runs = document.get("runs")
    assert isinstance(runs, list) and len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    rules = driver["rules"]
    assert isinstance(rules, list) and rules
    rule_ids: set[str] = set()
    for rule in rules:
        rule_id = rule["id"]
        assert isinstance(rule_id, str) and rule_id
        help_text = rule["help"]["text"]
        assert isinstance(help_text, str) and help_text.strip()
        rule_ids.add(rule_id)
    results = runs[0]["results"]
    assert isinstance(results, list) and results
    for result in results:
        assert result["ruleId"] in rule_ids
        locations = result["locations"]
        assert isinstance(locations, list) and locations
        uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
        assert isinstance(uri, str) and uri
        message = result["message"]["text"]
        assert isinstance(message, str) and message.strip()


def test_tc_f1_p2_sarif_shape_local_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Partial local proxy for TC-F1-P2. This is the CLI SARIF file, not code scanning.

    A live P2 checks GitHub code scanning alerts. This only checks that a local
    scan writes SARIF 2.1.0 with rule ids, locations, and help text.
    """
    store = tmp_path / "empty"
    guard = _bind_offline(monkeypatch, store)
    with _vulnerable_server() as port:
        config = _local_config(
            tmp_path,
            "version: 1\npolicy: L1\ncoverage: standard\nscope:\n  - host: 127.0.0.1\n"
            "targets:\n  ping:\n    kind: web\n"
            f"    url: http://127.0.0.1:{port}/ping\n    method: GET\n    timeout: 2\n"
            "    rate_limit:\n      rps: 100\n      concurrency: 4\n    query:\n"
            '      host: "{{payload}}"\n',
        )
        code = main(["scan", "--config", str(config), "--policy", "L1", "--yes", "--quiet"])
    assert code == 1
    runs = tmp_path / ".insidia" / "runs"
    directory = max(path for path in runs.iterdir() if path.is_dir())
    sarif_path = directory / "results.sarif"
    text = sarif_path.read_text()
    assert text.strip()
    _assert_sarif_shape(json.loads(text))
    assert guard.blocked == [], guard.blocked
    _assert_nothing_fetched(store)
