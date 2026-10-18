import hashlib
import io
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import types
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from insidia.adapters import (
    ADAPTERS,
    Adapter,
    Invocation,
    RelayAdapter,
    RelayEndpoint,
    RepoPath,
    ScopedUrl,
)
from insidia.catalog import SPECS, STATIC_PROMPT
from insidia.config import Project, load_project
from insidia.engines import (
    PINNED_SHA256,
    _download,
    _github,
    _mirrored_download_url,
    _publish,
    install,
)
from insidia.errors import CliError, EngineFailed
from insidia.policy import get_policy
from insidia.probes import run
from insidia.process import _argv_for, child_env, launch_installed, run_command
from insidia.registry import capabilities, select
from insidia.scope import ScopeHost
from tests.support import start_fixture, stop_fixture, target

PHASE_1B = (
    "garak",
    "promptfoo",
    "pyrit",
    "deepteam",
    "mcp-scanner",
    "skillspector",
    "nuguard",
    "zap",
    "nuclei",
    "dalfox",
    "katana",
    "httpx",
    "trivy",
    "osv-scanner",
    "gitleaks",
    "bandit",
    "gosec",
)
PINS = {
    "garak": "0.17.0",
    "promptfoo": "0.124.0",
    "pyrit": "1.1.0",
    "deepteam": "1.0.9",
    "mcp-scanner": "4.8.5",
    "skillspector": "2.12.0",
    "nuguard": "0.9.15",
    "zap": "2.17.0",
    "nuclei": "3.11.1",
    "dalfox": "3.2.3",
    "katana": "1.8.0",
    "httpx": "1.12.0",
    "trivy": "0.75.0",
    "osv-scanner": "2.6.0",
    "gitleaks": "8.30.1",
    "bandit": "1.9.4",
    "gosec": "2.29.0",
}
RELAY = ("garak", "promptfoo", "pyrit", "deepteam")
WEB = ("zap", "nuclei", "dalfox", "katana", "httpx")
REPO = (
    "mcp-scanner",
    "skillspector",
    "nuguard",
    "trivy",
    "osv-scanner",
    "gitleaks",
    "bandit",
    "gosec",
)
LOCAL = (ScopeHost("127.0.0.1", False),)
QUERY = (("module", "web"), ("fn", "ssti"), ("q", "{{payload}}"))
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


@pytest.fixture(autouse=True)
def _no_off_loopback_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default engine tests stay on loopback. A live download has to opt in."""
    real = socket.create_connection

    def create_connection(
        address: tuple[str, int] | tuple[str, int, int, int],
        *args: object,
        **kwargs: object,
    ) -> socket.socket:
        host = address[0]
        if host not in _LOOPBACK:
            raise AssertionError(f"refusing non-loopback connection to {host}")
        return real(address, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "create_connection", create_connection)


def _engine(name: str) -> Adapter:
    found = [item for item in ADAPTERS if item.engine == name]
    assert len(found) == 1
    return found[0]


def _project() -> Project:
    return Project(Path("insidia.yaml"), 1, "L1", "standard", LOCAL, (), None, None)


def _package(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__path__ = []  # type: ignore[attr-defined]
    return module


def _exec_main(script: Path, modules: dict[str, types.ModuleType]) -> None:
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        exec(compile(script.read_text(), str(script), "exec"), {"__name__": "__main__"})
    finally:
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _record_urlopen(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    posts: list[object] = []

    class _Body:
        def read(self) -> bytes:
            return b'{"text": "ok"}'

        def __enter__(self) -> "_Body":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def urlopen(request: object, timeout: float = 30) -> _Body:
        posts.append(request)
        return _Body()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return posts


def _web_report(engine: str, body: str) -> str:
    url = "http://127.0.0.1:8080/call?q=%7B%7B7*7%7D%7D"
    raw = f"HTTP/1.1 200 OK\r\nDate: Tue, 06 Oct 2026 12:00:49 GMT\r\n\r\n{body}"
    if engine == "nuclei":
        document: object = {
            "template-id": "insidia-web-ssti",
            "timestamp": "2026-10-06T12:00:49Z",
            "request": f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "response": raw,
        }
    elif engine == "zap":
        document = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "40012",
                            "name": "Cross Site Scripting (Reflected)",
                            "instances": [{"uri": url, "response-body": "49"}],
                        },
                        {
                            "pluginid": "90035",
                            "name": "Server Side Template Injection",
                            "instances": [{"uri": url, "response-body": body}],
                        },
                    ]
                }
            ]
        }
    elif engine == "dalfox":
        document = {
            "findings": [
                {
                    "type": "R",
                    "message_str": "Reflected",
                    "cwe": "CWE-79",
                    "payload": "{{7*7}}",
                    "data": url,
                    "response": raw,
                },
                {
                    "type": "V",
                    "message_str": "SSTI template evaluated",
                    "cwe": "CWE-1336",
                    "payload": "{{7*7}}",
                    "data": url,
                    "response": raw,
                },
            ]
        }
    elif engine == "httpx":
        document = {
            "timestamp": "2026-10-06T12:00:49.000000000Z",
            "url": url,
            "request": f"GET {url} HTTP/1.1\r\n\r\n",
            "response": raw,
        }
    else:
        document = {
            "request": {"endpoint": url},
            "response": {"status_code": 200, "body": body},
        }
    return json.dumps(document)


def _repo_report(engine: str) -> object:
    reports: dict[str, object] = {
        "mcp-scanner": [
            {
                "tool_name": "send_email",
                "is_safe": False,
                "findings": {
                    "yara_analyzer": {
                        "severity": "HIGH",
                        "threat_names": ["PROMPT_INJECTION"],
                        "total_findings": 1,
                    },
                    "behavioral_analyzer": {
                        "severity": "SAFE",
                        "threat_names": [],
                        "total_findings": 0,
                    },
                },
            }
        ],
        "skillspector": {"issues": [{"id": "SS-001", "category": "exec", "severity": "HIGH"}]},
        "nuguard": {
            "findings": [
                {"finding_id": "nga-NGA-003-cf6bf33a", "severity": "high", "title": "Secrets"},
                {"finding_id": "nga-NGA-009-aaaa1111", "severity": "low", "title": "Minor"},
            ]
        },
        "trivy": {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "requests"}
                    ],
                }
            ]
        },
        "osv-scanner": {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "left-pad", "version": "1.0.0"},
                            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc"}],
                            "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"]}],
                        }
                    ],
                }
            ]
        },
        "gitleaks": [{"RuleID": "aws-access-key", "Secret": "AKIAIOSFODNN7EXAMPLE"}],
        "bandit": {
            "results": [
                {
                    "test_id": "B101",
                    "issue_text": "Use of assert detected.",
                    "filename": "a.py",
                }
            ]
        },
        "gosec": {
            "Issues": [
                {
                    "rule_id": "G401",
                    "details": "Use of weak cryptographic primitive",
                    "file": "main.go",
                }
            ]
        },
    }
    return reports[engine]


def _blob(workspace: Path, invocation: Invocation) -> str:
    text = " ".join((invocation.program, *invocation.args, *invocation.env.values()))
    for path in workspace.rglob("*"):
        if path.is_file():
            text += "\n" + path.read_text()
    return text


def test_every_phase_1b_engine_has_an_adapter() -> None:
    names = {adapter.engine for adapter in ADAPTERS}
    assert [name for name in PHASE_1B if name not in names] == []
    assert {spec.name: spec.version for spec in SPECS} == PINS


def test_relay_configs_send_secret_to_the_loopback_only(tmp_path: Path) -> None:
    endpoint = RelayEndpoint(
        "http://127.0.0.1:9/send", "relay-token", "http://127.0.0.1:1234/v1", "local-model"
    )
    for name in RELAY:
        workspace = tmp_path / name
        workspace.mkdir()
        adapter = _engine(name)
        assert isinstance(adapter, RelayAdapter)
        invocation = adapter.prepare(adapter.probes[0], endpoint, workspace)
        blob = _blob(workspace, invocation)
        assert "sandbox.internal" not in blob
        assert "http://127.0.0.1:9/send" in blob
        if name == "deepteam":
            assert 'model_callback("secret")' not in blob
        else:
            assert "secret" in blob


def test_garak_raises_parallel_requests(tmp_path: Path) -> None:
    adapter = _engine("garak")
    assert isinstance(adapter, RelayAdapter)
    invocation = adapter.prepare(
        adapter.probes[0],
        RelayEndpoint("http://127.0.0.1:9/send", "relay-token"),
        tmp_path,
    )
    assert invocation.args[invocation.args.index("--parallel_requests") + 1] == "8"
    assert '"parallel_requests": 8' in (tmp_path / "generator.json").read_text()
    prompts = json.loads((tmp_path / "probe.json").read_text())["test"]["Blank"]["prompts"]
    assert prompts == [STATIC_PROMPT]


def test_promptfoo_disables_remote_generation_and_telemetry(tmp_path: Path) -> None:
    adapter = _engine("promptfoo")
    assert isinstance(adapter, RelayAdapter)
    invocation = adapter.prepare(
        adapter.probes[0],
        RelayEndpoint("http://127.0.0.1:9/send", "relay-token"),
        tmp_path,
    )
    assert invocation.env["PROMPTFOO_DISABLE_REMOTE_GENERATION"] == "true"
    assert invocation.env["PROMPTFOO_DISABLE_TELEMETRY"] == "1"
    assert invocation.env["PROMPTFOO_DISABLE_SHARING"] == "1"
    assert invocation.env["PROMPTFOO_DISABLE_UPDATE"] == "1"


def test_pyrit_is_single_turn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _engine("pyrit")
    assert isinstance(adapter, RelayAdapter)
    adapter.prepare(
        adapter.probes[0],
        RelayEndpoint("http://127.0.0.1:9/send", "relay-token"),
        tmp_path,
    )
    script = tmp_path / "single_turn.py"
    monkeypatch.setenv("INSIDIA_RELAY_URL", "http://127.0.0.1:9/send")
    monkeypatch.setenv("INSIDIA_RELAY_TOKEN", "relay-token")
    sent: list[tuple[str, str]] = []
    timeouts: list[float] = []
    posts = _record_urlopen(monkeypatch)

    class HTTPTarget:
        def __init__(
            self,
            http_request: str,
            callback_function: object = None,
            use_tls: bool = True,
            timeout: float = 5,
        ) -> None:
            self.http_request = http_request
            timeouts.append(timeout)

    class PromptSendingAttack:
        def __init__(self, *, objective_target: HTTPTarget) -> None:
            self.objective_target = objective_target

        async def execute_async(self, *, objective: str, **kwargs: object) -> None:
            sent.append((objective, self.objective_target.http_request))

    async def initialize_pyrit_async(*args: object, **kwargs: object) -> None:
        return None

    attack = _package("pyrit.executor.attack")
    attack.PromptSendingAttack = PromptSendingAttack
    target = _package("pyrit.prompt_target")
    target.HTTPTarget = HTTPTarget
    setup = _package("pyrit.setup")
    setup.IN_MEMORY = "InMemory"
    setup.initialize_pyrit_async = initialize_pyrit_async
    modules = {
        "pyrit": _package("pyrit"),
        "pyrit.executor": _package("pyrit.executor"),
        "pyrit.executor.attack": attack,
        "pyrit.prompt_target": target,
        "pyrit.setup": setup,
    }
    _exec_main(script, modules)
    assert [item[0] for item in sent] == ["secret"]
    assert "http://127.0.0.1:9/send" in sent[0][1]
    assert "{PROMPT}" in sent[0][1]
    assert timeouts == [180]
    assert posts == []
    for banned in ("Crescendo", "TAP", "PAIR"):
        assert banned not in script.read_text()


def test_deepteam_callback_posts_the_static_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _engine("deepteam")
    assert isinstance(adapter, RelayAdapter)
    invocation = adapter.prepare(
        adapter.probes[0],
        RelayEndpoint(
            "http://127.0.0.1:9/send", "relay-token", "http://127.0.0.1:1234/v1", "local-model"
        ),
        tmp_path,
    )
    assert invocation.env["INSIDIA_MODEL_URL"] == "http://127.0.0.1:1234/v1"
    assert invocation.env["INSIDIA_MODEL_NAME"] == "local-model"
    assert "INSIDIA_MODEL_KEY" not in invocation.env
    assert invocation.env["DEEPTEAM_TELEMETRY_OPT_OUT"] == "YES"
    script = tmp_path / "callback.py"
    monkeypatch.setenv("INSIDIA_MODEL_NAME", "local-model")
    posts = _record_urlopen(monkeypatch)
    entered: list[object] = []
    models: list[object] = []

    def red_team(**kwargs: object) -> None:
        entered.append(kwargs.get("model_callback"))
        models.extend([kwargs.get("simulator_model"), kwargs.get("evaluation_model")])

    class DeepEvalBaseLLM:
        def __init__(self, model: str | None = None) -> None:
            self.name = model
            self.model = self.load_model()

    class Bias:
        def __init__(self, types: object = None) -> None:
            self.types = types

    class Base64:
        def __init__(self) -> None:
            return None

    deepteam = _package("deepteam")
    deepteam.red_team = red_team
    attacks = _package("deepteam.attacks")
    single = _package("deepteam.attacks.single_turn")
    single.Base64 = Base64
    vulnerabilities = _package("deepteam.vulnerabilities")
    vulnerabilities.Bias = Bias
    deepeval = _package("deepeval")
    deepeval_models = _package("deepeval.models")
    deepeval_models.DeepEvalBaseLLM = DeepEvalBaseLLM
    _exec_main(
        script,
        {
            "deepeval": deepeval,
            "deepeval.models": deepeval_models,
            "deepteam": deepteam,
            "deepteam.attacks": attacks,
            "deepteam.attacks.single_turn": single,
            "deepteam.vulnerabilities": vulnerabilities,
        },
    )
    assert len(entered) == 1
    assert getattr(entered[0], "__name__", "") == "model_callback"
    assert len(models) == 2
    assert models[0] is models[1]
    assert getattr(models[0], "name", "") == "local-model"
    assert posts == []
    for banned in ("Crescendo", "TAP", "PAIR"):
        assert banned not in script.read_text()


def test_deepteam_is_skipped_without_an_openai_compatible_attacker(tmp_path: Path) -> None:
    adapter = _engine("deepteam")
    assert isinstance(adapter, RelayAdapter)
    assert adapter.probes[0].requires_model is True
    with pytest.raises(EngineFailed, match="attacker"):
        adapter.prepare(
            adapter.probes[0], RelayEndpoint("http://127.0.0.1:9/send", "relay-token"), tmp_path
        )


def test_nuclei_template_keeps_the_expression_encoded(tmp_path: Path) -> None:
    adapter = _engine("nuclei")
    view = ScopedUrl("http://127.0.0.1:8080/call", QUERY)
    adapter.prepare(adapter.probes[0], view, tmp_path)  # type: ignore[arg-type]
    template = (tmp_path / "ssti.yaml").read_text()
    assert "%7B%7B7*7%7D%7D" in template
    assert "{{7*7}}" not in template
    assert "module=web" in template
    assert "fn=ssti" in template


def test_web_engines_receive_the_query_template(tmp_path: Path) -> None:
    view = ScopedUrl("http://127.0.0.1:8080/call", QUERY)
    for name in WEB:
        workspace = tmp_path / name
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], view, workspace)  # type: ignore[arg-type]
        blob = _blob(workspace, invocation)
        assert "module=web" in blob
        assert "fn=ssti" in blob


# Flags that tell the tool to follow a redirect onto another host.
_OFF_SCOPE_REDIRECT = {
    "httpx": ("-fr", "-follow-redirects"),
    "dalfox": ("-F", "--follow-redirects"),
    "nuclei": ("-fr", "-follow-redirects", "-fhr", "-follow-host-redirects"),
}


def test_crawlers_do_not_follow_redirects_off_scope(tmp_path: Path) -> None:
    view = ScopedUrl("http://127.0.0.1:8080/call", QUERY)
    for name, banned in _OFF_SCOPE_REDIRECT.items():
        workspace = tmp_path / name
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], view, workspace)  # type: ignore[arg-type]
        for flag in banned:
            assert flag not in invocation.args
        if name == "nuclei":
            assert "-dr" in invocation.args
    katana_dir = tmp_path / "katana"
    katana_dir.mkdir()
    katana = _engine("katana").prepare(_engine("katana").probes[0], view, katana_dir)  # type: ignore[attr-defined]
    assert "-dr" in katana.args
    assert katana.args[katana.args.index("-fs") + 1] == "fqdn"
    scope = katana.args[katana.args.index("-cs") + 1]
    assert scope.startswith(r"^http://127\.0\.0\.1:8080")
    zap_dir = tmp_path / "zap"
    zap_dir.mkdir()
    zap = _engine("zap").prepare(_engine("zap").probes[0], view, zap_dir)  # type: ignore[attr-defined]
    plan = (zap_dir / "plan.yaml").read_text()
    assert "contexts:" in plan
    assert "proxy:" not in plan
    assert "proxy" not in zap.args


def test_projectdiscovery_engines_disable_update_checks(tmp_path: Path) -> None:
    view = ScopedUrl("http://127.0.0.1:8080/call", QUERY)
    names = {
        spec.name
        for spec in SPECS
        if any(f"/projectdiscovery/{spec.name}/" in url for url in PINNED_SHA256)
    }
    assert names == {"nuclei", "katana", "httpx"}
    for name in sorted(names):
        workspace = tmp_path / name
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], view, workspace)  # type: ignore[arg-type]
        assert "-disable-update-check" in invocation.args


def test_repo_engines_are_pointed_at_the_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INSIDIA_VULN_DB", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in REPO:
        workspace = tmp_path / name
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], RepoPath(repo), workspace)  # type: ignore[arg-type]
        assert any(str(repo) in arg for arg in invocation.args)
        if name == "trivy":
            assert "--skip-version-check" in invocation.args
            assert "--skip-db-update" in invocation.args
            assert "--skip-java-db-update" in invocation.args
        if name == "osv-scanner":
            assert "--offline" in invocation.args


def test_vuln_db_engines_stay_offline_unless_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.delenv("INSIDIA_VULN_DB", raising=False)
    for name, offline in (("trivy", "--skip-db-update"), ("osv-scanner", "--offline")):
        workspace = tmp_path / f"default-{name}"
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], RepoPath(repo), workspace)  # type: ignore[arg-type]
        assert offline in invocation.args
        if name == "trivy":
            assert "--skip-java-db-update" in invocation.args
    for value in ("", "true", "yes", "0"):
        monkeypatch.setenv("INSIDIA_VULN_DB", value)
        workspace = tmp_path / f"rejected-{value or 'empty'}"
        workspace.mkdir()
        adapter = _engine("osv-scanner")
        invocation = adapter.prepare(adapter.probes[0], RepoPath(repo), workspace)  # type: ignore[arg-type]
        assert "--offline" in invocation.args
    monkeypatch.setenv("INSIDIA_VULN_DB", "1")
    for name, offline in (("trivy", "--skip-db-update"), ("osv-scanner", "--offline")):
        workspace = tmp_path / f"opt-in-{name}"
        workspace.mkdir()
        adapter = _engine(name)
        invocation = adapter.prepare(adapter.probes[0], RepoPath(repo), workspace)  # type: ignore[arg-type]
        assert offline not in invocation.args
        if name == "trivy":
            assert "--skip-java-db-update" not in invocation.args
            assert "--skip-version-check" in invocation.args


def test_echoed_payload_with_a_timestamp_is_not_ssti(tmp_path: Path) -> None:
    echo = "echo {{7*7}} at 12:49"
    for name in WEB:
        report = tmp_path / f"{name}.json"
        report.write_text(_web_report(name, echo))
        adapter = _engine(name)
        assert adapter.parse(report, adapter.probes[0]) == []  # type: ignore[attr-defined]


def test_evaluated_template_body_is_ssti_for_detectors_only(tmp_path: Path) -> None:
    for name in WEB:
        report = tmp_path / f"{name}.json"
        report.write_text(_web_report(name, "49"))
        adapter = _engine(name)
        hits = adapter.parse(report, adapter.probes[0])  # type: ignore[attr-defined]
        if name in {"httpx", "katana"}:
            assert hits == []
        else:
            assert [hit.evidence for hit in hits] == ["49"]


def test_repo_parser_reads_each_engine_shape(tmp_path: Path) -> None:
    expected = {
        "mcp-scanner": "PROMPT_INJECTION",
        "skillspector": "SS-001",
        "nuguard": "NGA-003",
        "trivy": "CVE-2024-0001",
        "osv-scanner": "GHSA-aaaa-bbbb-cccc",
        "gitleaks": "aws-access-key",
        "bandit": "B101",
        "gosec": "G401",
    }
    for name, rule in expected.items():
        report = tmp_path / f"{name}.json"
        report.write_text(json.dumps(_repo_report(name)))
        adapter = _engine(name)
        hits = adapter.parse(report, adapter.probes[0])  # type: ignore[attr-defined]
        assert [hit.evidence for hit in hits] == [rule]
        assert "AKIA" not in hits[0].response
    leaked = json.dumps(_repo_report("gitleaks"))
    for name in ("bandit", "trivy"):
        report = tmp_path / f"foreign-{name}.json"
        report.write_text(leaked)
        adapter = _engine(name)
        with pytest.raises(EngineFailed, match="unexpected|error"):
            adapter.parse(report, adapter.probes[0])  # type: ignore[attr-defined]
    empty = tmp_path / "empty.json"
    empty.write_text("[]")
    assert _engine("gitleaks").parse(empty, _engine("gitleaks").probes[0]) == []  # type: ignore[attr-defined]


def test_nuclei_report_cannot_rename_the_engine(tmp_path: Path) -> None:
    class Launch:
        def __call__(self, invocation: Invocation, workspace: Path) -> None:
            (workspace / invocation.report).write_text(
                json.dumps(
                    {
                        "engine": "someone-else",
                        "request": "GET /call?q=%7B%7B7*7%7D%7D HTTP/1.1\r\n\r\n",
                        "response": "HTTP/1.1 200 OK\r\n\r\n49",
                    }
                )
                + "\n"
            )

    adapter = _engine("nuclei")
    web = target(kind="web", url="http://127.0.0.1:8080/call")
    hits = run(
        adapter,
        adapter.probes[0],
        web,
        _project(),
        tmp_path,
        get_policy("L1").control("web.ssti"),
        launch=Launch(),
    )
    assert [(hit.engine, hit.evidence) for hit in hits.hits] == [("nuclei", "49")]


def test_availability_follows_a_receipt_written_in_this_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    assert next(item.available for item in capabilities() if item.engine == "nuclei") is False
    binary = tmp_path / "nuclei" / "bin"
    binary.mkdir(parents=True)
    (binary / "nuclei").write_bytes(b"")
    (tmp_path / "nuclei" / "receipt.json").write_text(
        json.dumps({"name": "nuclei", "version": "3.11.1", "program": "bin/nuclei"})
    )
    assert next(item.available for item in capabilities() if item.engine == "nuclei") is True
    chosen = select("web.ssti", "thorough", model_available=False)
    assert [item.engine for item in chosen] == ["insidia", "nuclei"]


def test_zap_install_warns_when_java_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))

    def already(name: str, allow_unverified: bool = False) -> str:
        del allow_unverified
        return f"installed {name} 2.17.0"

    monkeypatch.setattr("insidia.engines._install_one", already)
    monkeypatch.setattr("insidia.engines.shutil.which", lambda _name: None)
    message = install(("zap",))
    assert message.startswith("installed zap 2.17.0")
    assert "warning: needs Java 17 or later on PATH" in message

    monkeypatch.setattr("insidia.engines.shutil.which", lambda name: f"/usr/bin/{name}")
    assert "Java" not in install(("zap",))


def test_bare_install_does_not_download(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "tools"))
    assert install() == "built-in probes are already available; name an engine to install it"
    assert not (tmp_path / "tools").exists()


def test_named_install_with_a_receipt_does_not_restage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    stage = tmp_path / "stage"
    (stage / "bin").mkdir(parents=True)
    (stage / "bin" / "nuclei").write_bytes(b"nuclei")
    _publish(
        stage,
        tmp_path / "nuclei",
        {"name": "nuclei", "version": "3.11.1", "program": "bin/nuclei"},
    )
    assert install(("nuclei",)) == "nuclei 3.11.1 is already installed"
    assert not (tmp_path / ".nuclei.staging").exists()


def test_run_command_starts_the_engine_with_stdin_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    class _Process:
        returncode = 0

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            return b"", b""

    def _popen(argv: list[str], **kwargs: object) -> _Process:
        seen.update(kwargs)
        seen["argv"] = argv
        return _Process()

    monkeypatch.setattr("insidia.process.subprocess.Popen", _popen)
    code, detail = run_command(["katana", "-u", "http://127.0.0.1"], None, {}, 30, name="katana")
    assert code == 0
    assert detail == ""
    assert seen["stdin"] is subprocess.DEVNULL


def test_child_process_drops_proxies_and_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    out = tmp_path / "env.json"
    script = tmp_path / "env.py"
    script.write_text(f"import json, os\njson.dump(dict(os.environ), open({str(out)!r}, 'w'))\n")
    invocation = Invocation(
        sys.executable,
        (str(script),),
        "report.json",
        env={"PROMPTFOO_DISABLE_TELEMETRY": "1", "ALL_PROXY": "http://nope"},
    )
    launch_installed(invocation, tmp_path)
    saved = json.loads(out.read_text())
    assert "HTTPS_PROXY" not in saved
    assert "ALL_PROXY" not in saved
    assert "OPENAI_API_KEY" not in saved
    assert saved["PROMPTFOO_DISABLE_TELEMETRY"] == "1"
    assert "http_proxy" not in {key.lower() for key in saved}


def test_timeout_kills_the_process_group(tmp_path: Path) -> None:
    script = tmp_path / "sleep.py"
    script.write_text("import time\ntime.sleep(30)\n")
    invocation = Invocation(sys.executable, (str(script),), "report.json", timeout=0.5)
    with pytest.raises(EngineFailed, match="timed out"):
        launch_installed(invocation, tmp_path)


def test_child_env_allowlist_drops_a_proxy() -> None:
    env = child_env({"PROMPTFOO_DISABLE_UPDATE": "1", "http_proxy": "http://proxy"})
    assert env["PROMPTFOO_DISABLE_UPDATE"] == "1"
    assert "http_proxy" not in env


def test_child_env_keeps_the_windows_system_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    assert child_env({})["SYSTEMROOT"] == r"C:\Windows"


def test_windows_script_launcher_uses_the_venv_python(tmp_path: Path) -> None:
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    python = scripts / "python.exe"
    garak = scripts / "garak.exe"
    python.write_bytes(b"")
    garak.write_bytes(b"")
    assert _argv_for("nt", str(garak), ("--probe", "test.Blank")) == [
        str(python),
        str(garak),
        "--probe",
        "test.Blank",
    ]
    assert _argv_for("nt", str(python), ("-c", "pass")) == [str(python), "-c", "pass"]
    nuclei = tmp_path / "nuclei.exe"
    nuclei.write_bytes(b"")
    assert _argv_for("nt", str(nuclei), ("-u", "http://127.0.0.1")) == [
        str(nuclei),
        "-u",
        "http://127.0.0.1",
    ]
    assert _argv_for("posix", str(garak), ("--probe", "test.Blank")) == [
        str(garak),
        "--probe",
        "test.Blank",
    ]


def test_broken_engine_leaves_builtin_probes_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tools = tmp_path / "tools"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tools))
    binary = tools / "garak" / "bin" / "garak"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"")
    binary.chmod(0o644)
    (tools / "garak" / "receipt.json").write_text(
        json.dumps({"name": "garak", "version": "0.17.0", "program": "bin/garak"})
    )
    (tools / "nuclei").mkdir()
    (tools / "nuclei" / "receipt.json").write_text("{")
    assert next(item.available for item in capabilities() if item.engine == "nuclei") is False
    port = _free_port()
    process = start_fixture(port)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz")
        _write(tmp_path, port)
        from insidia.scan import execute

        outcome = execute(load_project(tmp_path / "insidia.yaml"), tmp_path, coverage="thorough")
    finally:
        stop_fixture(process)
    assert {item.engine for item in outcome.findings} == {"insidia"}
    assert {item.attack for item in outcome.findings} == {"ai.data_leakage", "web.ssti"}
    assert any(item.startswith("garak:") for item in outcome.skips)


def test_thorough_without_tools_still_runs_the_builtin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "empty"))
    port = _free_port()
    process = start_fixture(port)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz")
        _write(tmp_path, port)
        from insidia.scan import execute

        outcome = execute(load_project(tmp_path / "insidia.yaml"), tmp_path, coverage="thorough")
    finally:
        stop_fixture(process)
    assert {item.engine for item in outcome.findings} == {"insidia"}
    assert {item.attack for item in outcome.findings} == {"ai.data_leakage", "web.ssti"}


def _nuclei_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("nuclei", b"#!/bin/sh\n")
    return buffer.getvalue()


def test_a_pinned_digest_is_checked_before_extract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    _refuse_off_loopback(monkeypatch)
    spec = next(item for item in SPECS if item.name == "nuclei")
    canonical = _github(spec)
    payload = _nuclei_zip()
    monkeypatch.setattr(
        "insidia.engines.PINNED_SHA256",
        {canonical: hashlib.sha256(payload).hexdigest()},
    )
    with _local_mirror(payload) as (mirror, requested):
        monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", mirror)
        assert urllib.parse.urlsplit(mirror).hostname == "127.0.0.1"
        assert install(("nuclei",)).startswith("installed nuclei")
    assert requested
    assert all(path.startswith("/projectdiscovery/nuclei/") for path in requested)
    program = tmp_path / "nuclei" / "bin" / "nuclei"
    assert program.is_file()
    if os.name != "nt":
        assert program.stat().st_mode & 0o111


def test_a_digest_mismatch_is_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    _refuse_off_loopback(monkeypatch)
    spec = next(item for item in SPECS if item.name == "nuclei")
    canonical = _github(spec)
    monkeypatch.setattr("insidia.engines.PINNED_SHA256", {canonical: "0" * 64})
    with _local_mirror(_nuclei_zip()) as (mirror, requested):
        monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", mirror)
        with pytest.raises(CliError, match="failed SHA-256 verification"):
            install(("nuclei",), allow_unverified=True)
    assert requested
    assert all(path.startswith("/projectdiscovery/nuclei/") for path in requested)
    assert not (tmp_path / "nuclei").exists()
    assert not (tmp_path / ".nuclei.staging").exists()


def test_a_missing_pin_needs_allow_unverified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    _refuse_off_loopback(monkeypatch)
    monkeypatch.setattr("insidia.engines.PINNED_SHA256", {})
    with _local_mirror(_nuclei_zip()) as (mirror, requested):
        monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", mirror)
        with pytest.raises(CliError, match="--allow-unverified"):
            install(("nuclei",))
        assert not (tmp_path / "nuclei").exists()
        assert urllib.parse.urlsplit(mirror).hostname == "127.0.0.1"
        assert install(("nuclei",), allow_unverified=True).startswith("installed nuclei")
    assert requested
    assert all(path.startswith("/projectdiscovery/nuclei/") for path in requested)
    program = tmp_path / "nuclei" / "bin" / "nuclei"
    assert program.is_file()
    if os.name != "nt":
        assert program.stat().st_mode & 0o111


def _linux_amd64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")


def _refuse_off_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test before a bug can fetch a real engine binary."""
    real_build = urllib.request.build_opener

    def build(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
        opener = real_build(*handlers)
        original = opener.open

        def open_url(
            fullurl: object,
            data: object = None,
            timeout: float | None = None,
        ) -> object:
            raw = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else str(fullurl)
            host = urllib.parse.urlsplit(raw).hostname
            if host != "127.0.0.1":
                raise AssertionError(f"refusing non-loopback engine download: {raw}")
            if timeout is None:
                return original(fullurl, data=data)
            return original(fullurl, data=data, timeout=timeout)

        opener.open = open_url  # type: ignore[method-assign]
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", build)


@contextmanager
def _local_mirror(payload: bytes) -> Iterator[tuple[str, list[str]]]:
    requested: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            requested.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    assert isinstance(port, int)
    try:
        yield f"http://127.0.0.1:{port}", requested
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_github_urls_stay_canonical_without_a_mirror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    seen = 0
    for spec in SPECS:
        try:
            url = _github(spec)
        except CliError:
            continue
        seen += 1
        assert url.startswith("https://github.com/")
    assert seen >= 9


def test_a_mirror_rewrites_only_the_github_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    canonical = "https://github.com/org/name/releases/download/v1/file.zip"
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    assert _mirrored_download_url(canonical) == canonical
    monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", "http://127.0.0.1:9/")
    assert _mirrored_download_url(canonical) == (
        "http://127.0.0.1:9/org/name/releases/download/v1/file.zip"
    )
    monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", "ftp://127.0.0.1/engines")
    with pytest.raises(CliError, match="http or https"):
        _mirrored_download_url(canonical)
    monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", "http://127.0.0.1:9")
    with pytest.raises(CliError, match="https://github.com"):
        _mirrored_download_url("https://download.pytorch.org/whl/cpu/torch.whl")
    with pytest.raises(CliError, match="https://github.com"):
        _mirrored_download_url("https://github.com.evil/nuclei.zip")


def test_a_non_http_mirror_is_refused_before_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", "file:///tmp/engines")
    _linux_amd64(monkeypatch)

    def fail_open(*args: object, **kwargs: object) -> object:
        raise AssertionError("download started")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fail_open)
    with pytest.raises(CliError, match="http or https"):
        install(("nuclei",))
    assert not (tmp_path / "nuclei").exists()
    assert not (tmp_path / ".nuclei.staging").exists()


def test_a_mirror_does_not_fetch_a_non_github_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", "http://127.0.0.1:9")

    def fail_open(*args: object, **kwargs: object) -> object:
        raise AssertionError("download started")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fail_open)
    with pytest.raises(CliError, match="https://github.com"):
        _download("https://download.pytorch.org/whl/cpu/torch.whl", tmp_path / "torch")
    assert not (tmp_path / "torch").exists()


def test_a_tampered_mirror_archive_fails_sha256(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    _refuse_off_loopback(monkeypatch)
    spec = next(item for item in SPECS if item.name == "nuclei")
    canonical = _github(spec)
    payload = _nuclei_zip()
    monkeypatch.setattr(
        "insidia.engines.PINNED_SHA256",
        {canonical: hashlib.sha256(payload).hexdigest()},
    )

    def fail_extract(*args: object, **kwargs: object) -> None:
        raise AssertionError("archive was extracted")

    monkeypatch.setattr("insidia.engines._extract", fail_extract)
    with _local_mirror(b"tampered-archive") as (mirror, requested):
        monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", mirror)
        assert _github(spec) == canonical
        with pytest.raises(CliError, match="failed SHA-256 verification"):
            install(("nuclei",), allow_unverified=True)
    assert requested
    assert all(path.startswith("/projectdiscovery/nuclei/") for path in requested)
    assert not (tmp_path / "nuclei").exists()
    assert not (tmp_path / ".nuclei.staging").exists()


def test_a_mirror_archive_matching_the_pin_installs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _linux_amd64(monkeypatch)
    _refuse_off_loopback(monkeypatch)
    spec = next(item for item in SPECS if item.name == "nuclei")
    canonical = _github(spec)
    payload = _nuclei_zip()
    monkeypatch.setattr(
        "insidia.engines.PINNED_SHA256",
        {canonical: hashlib.sha256(payload).hexdigest()},
    )
    with _local_mirror(payload) as (mirror, requested):
        monkeypatch.setenv("INSIDIA_ENGINE_MIRROR", mirror)
        assert _github(spec) == canonical
        assert install(("nuclei",)).startswith("installed nuclei")
    assert requested
    assert all(path.startswith("/projectdiscovery/nuclei/") for path in requested)
    program = tmp_path / "nuclei" / "bin" / "nuclei"
    assert program.is_file()
    if os.name != "nt":
        assert program.stat().st_mode & 0o111


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_every_linux_download_has_a_pin(monkeypatch: pytest.MonkeyPatch, machine: str) -> None:
    from insidia.engines import PINNED_SHA256

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: machine)
    archived = [
        spec
        for spec in SPECS
        if spec.name
        in {
            "nuclei",
            "dalfox",
            "katana",
            "httpx",
            "trivy",
            "osv-scanner",
            "gitleaks",
            "gosec",
            "zap",
        }
    ]
    missing = [spec.name for spec in archived if _github(spec) not in PINNED_SHA256]
    assert missing == []


def test_nuclei_archive_follows_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = next(item for item in SPECS if item.name == "nuclei")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    assert _github(spec).endswith("nuclei_3.11.1_linux_amd64.zip")
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    assert _github(spec).endswith("nuclei_3.11.1_macOS_arm64.zip")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    assert _github(spec).endswith("nuclei_3.11.1_windows_amd64.zip")


_GARAK_STUB = """\
#!/usr/bin/env python3
import json
import sys
import urllib.request
from urllib.parse import urlsplit


def _flag(name: str) -> str:
    return sys.argv[sys.argv.index(name) + 1]


generator = json.loads(open(_flag("--generator_option_file"), encoding="utf-8").read())
probe = json.loads(open(_flag("--probe_option_file"), encoding="utf-8").read())
rest = generator["rest"]["RestGenerator"]
prompts = probe["test"]["Blank"]["prompts"]
if len(prompts) != 1:
    raise SystemExit("garak fixture relays one prompt")
host = urlsplit(str(rest["uri"])).hostname
if host not in {"127.0.0.1", "localhost", "::1"}:
    raise SystemExit("garak fixture refuses a non-loopback relay")
headers = {
    str(key): value
    for key, value in rest["headers"].items()
    if isinstance(value, str)
}
body = json.dumps({"prompt": prompts[0]}).encode()
request = urllib.request.Request(str(rest["uri"]), data=body, headers=headers, method="POST")
with urllib.request.urlopen(request, timeout=30) as response:
    response.read()
"""

_PROMPTFOO_STUB = """\
#!/usr/bin/env python3
import json
import os
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

url = os.environ["INSIDIA_RELAY_URL"]
host = urlsplit(url).hostname
if host not in {"127.0.0.1", "localhost", "::1"}:
    raise SystemExit("promptfoo fixture refuses a non-loopback relay")
prompts = [line for line in Path("prompt.txt").read_text(encoding="utf-8").splitlines() if line]
if len(prompts) != 1:
    raise SystemExit("promptfoo fixture relays one prompt")
body = json.dumps({"prompt": prompts[0]}).encode()
request = urllib.request.Request(
    url,
    data=body,
    headers={
        "Authorization": "Bearer " + os.environ["INSIDIA_RELAY_TOKEN"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    response.read()
"""

_NUCLEI_STUB = """\
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
destination = Path(args[args.index("-o") + 1])
raw = "HTTP/1.1 200 OK" + chr(13) + chr(10) + chr(13) + chr(10) + "49"
destination.write_text(json.dumps({"response": raw}) + chr(10), encoding="utf-8")
"""


def _stage_engine(root: Path, name: str, relative: str, script: str) -> None:
    binary = root / name / relative
    binary.parent.mkdir(parents=True)
    text = script.replace("#!/usr/bin/env python3\n", f"#!{sys.executable}\n", 1)
    binary.write_text(text)
    binary.chmod(0o755)
    (root / name / "receipt.json").write_text(
        json.dumps({"name": name, "version": PINS[name], "program": relative}) + "\n"
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows cannot execute the extensionless POSIX engine stubs",
)
def test_thorough_scan_cross_validates_without_a_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tools = tmp_path / "toolchain"
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tools))
    monkeypatch.delenv("INSIDIA_ENGINE_MIRROR", raising=False)
    _stage_engine(tools, "garak", "bin/garak", _GARAK_STUB)
    _stage_engine(tools, "promptfoo", "bin/promptfoo", _PROMPTFOO_STUB)
    _stage_engine(tools, "nuclei", "bin/nuclei", _NUCLEI_STUB)
    assert tools.is_relative_to(tmp_path)
    port = _free_port()
    process = start_fixture(port)
    try:
        _wait(f"http://127.0.0.1:{port}/healthz")
        _write(tmp_path, port)
        from insidia.scan import execute

        outcome = execute(load_project(tmp_path / "insidia.yaml"), tmp_path, coverage="thorough")
    finally:
        stop_fixture(process)
    document = json.loads((outcome.run_dir / "findings.json").read_text())
    leak = next(item for item in document if item["attack"] == "ai.data_leakage")
    web = next(item for item in document if item["attack"] == "web.ssti")
    benchmark = json.loads((outcome.run_dir / "benchmark.json").read_text())
    leak_rows = [
        row
        for row in benchmark["controls"]
        if row.get("id") == "ai.data_leakage" and row.get("target") == "sandbox-chat"
    ]
    assert leak["engine"] == "insidia"
    assert leak["cross_validated"] is False, outcome.skips
    assert leak["engines"] == ["insidia"], outcome.skips
    assert leak["reported_by"] == 1, outcome.skips
    assert any("garak sent only 1 prompt" in row.get("detail", "") for row in leak_rows)
    assert web["engine"] == "insidia"
    assert web["cross_validated"] is False, outcome.skips
    assert web["reported_by"] >= 2, outcome.skips
    assert "insidia" in web["engines"]
    assert "nuclei" in web["engines"] or "zap" in web["engines"]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait(url: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("sandbox did not start")


def _write(root: Path, port: int) -> None:
    (root / "insidia.yaml").write_text(
        f"""
version: 1
policy: L1
coverage: thorough
scope:
  - host: 127.0.0.1
targets:
  sandbox-chat:
    kind: chat
    url: http://127.0.0.1:{port}/call
    method: GET
    query:
      module: chatbot
      fn: data_leakage
      q: "{{{{prompt}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
  sandbox-web:
    kind: web
    url: http://127.0.0.1:{port}/call
    method: GET
    query:
      module: web
      fn: ssti
      q: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
"""
    )


def test_nuguard_runs_offline_and_without_a_model(tmp_path: Path) -> None:
    adapter = _engine("nuguard")
    invocation = adapter.prepare(adapter.probes[0], RepoPath(tmp_path), tmp_path)  # type: ignore[attr-defined]
    script = (tmp_path / "nuguard_run.py").read_text()
    for flag in ("--no-llm", "--no-osv", "--supply-chain-verify", "off"):
        assert flag in script
    assert invocation.env["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
    assert "OPENAI_API_KEY" not in invocation.env
