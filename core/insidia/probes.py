"""Run one probe through its engine adapter. The adapter value names the engine."""

from __future__ import annotations

import hmac
import json
import random
import secrets
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TypeGuard

from insidia.adapters import (
    ORACLES,
    Adapter,
    BuiltIn,
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RelayEndpoint,
    RepoPath,
    ReportAdapter,
    ScopedUrl,
    has_standalone,
)
from insidia.config import Project, Target, resolve_secret
from insidia.errors import CliError, ConfigError, EngineFailed, ProbeError, ScopeError
from insidia.policy import Control
from insidia.process import launch_installed
from insidia.scope import ScopeHost, check_url
from insidia.transport import BoundBudget, current_budget, exchange, repo_path

Launch = Callable[[Invocation, Path], None]


@dataclass(frozen=True)
class ProbeHit:
    target: str
    family: str
    engine: str
    probe: str
    response: str
    severity: str
    confidence: str
    track: str
    taxonomy: tuple[str, ...]
    remediation: str
    upstream: str = ""
    evidence: str = ""
    location: str = ""


@dataclass(frozen=True)
class Attempt:
    """Observations from one engine, plus an error if that engine did not finish."""

    hits: tuple[ProbeHit, ...] = ()
    error: str = ""


def run(
    adapter: Adapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
    *,
    launch: Launch = launch_installed,
) -> Attempt:
    if target.kind not in spec.target_kinds:
        return Attempt()
    match adapter:
        case BuiltIn():
            found, error = _judge(adapter, spec, target, project.scope, root)
        case RelayAdapter():
            found, error = _relay(adapter, spec, target, project, root, launch)
        case ReportAdapter() if _over_url(adapter):
            found, error = _report(adapter, spec, _scoped_url(target, project.scope), launch)
        case ReportAdapter() if _over_repo(adapter):
            found, error = _report(adapter, spec, RepoPath(repo_path(target, root)), launch)
        case _:
            raise CliError(f"{adapter.engine}: no adapter arm")
    hits = tuple(
        ProbeHit(
            target.name,
            spec.family,
            adapter.engine,
            spec.probe,
            hit.response,
            hit.severity or control.severity,
            hit.confidence or "high",
            control.track,
            control.taxonomy,
            control.remediation,
            hit.upstream,
            hit.evidence,
            hit.location,
        )
        for hit in found
    )
    return Attempt(hits, error)


_REPO_SOURCE = {
    "code.sast_sinks": "sinks.py",
    "code.secrets": "sinks.py",
    "deps.sca": "requirements.txt",
}


def _judge(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str]:
    if spec.family == "web.ssti" and target.kind != "repo":
        return _paired_ssti(target, scope, root)
    oracle = ORACLES[spec.family]
    if target.kind == "repo":
        return _judge_repo(adapter, spec, target, root), ""
    hits: list[EngineHit] = []
    for payload in adapter.corpus[spec]:
        try:
            response = exchange(target, payload, scope, root)
        except ProbeError as exc:
            return hits, str(exc)
        evidence = oracle(payload, response, target)
        if evidence is not None:
            hits.append(EngineHit(spec.upstream, payload, response, evidence))
    return hits, ""


def _paired_ssti(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str]:
    """A fresh product must appear in the attack response and not in the baseline."""

    left = random.randint(13, 97)
    right = random.randint(13, 97)
    product = str(left * right)
    attack = "{{" + f"{left}*{right}" + "}}"
    fixed = "{{7*7}}"
    try:
        baseline = exchange(target, "baseline", scope, root)
        rendered = exchange(target, attack, scope, root)
        planted = exchange(target, fixed, scope, root)
    except ProbeError as exc:
        return [], str(exc)
    if (
        attack not in rendered
        and has_standalone(product, rendered)
        and not has_standalone(product, baseline)
    ):
        return [EngineHit("insidia-ssti-arith", attack, rendered, product)], ""
    if (
        fixed not in planted
        and has_standalone("49", planted)
        and not has_standalone("49", baseline)
    ):
        return [EngineHit("insidia-ssti-arith", fixed, planted, "49")], ""
    return [], ""


def _judge_repo(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    root: Path,
) -> list[EngineHit]:
    source = repo_path(target, root) / _REPO_SOURCE[spec.family]
    if not source.is_file():
        raise EngineFailed(f"{source.name} is not in this repository")
    text = source.read_text(encoding="utf-8")
    oracle = ORACLES[spec.family]
    hits: list[EngineHit] = []
    for payload in adapter.corpus[spec]:
        evidence = oracle(payload, text, target)
        if evidence is not None:
            hits.append(EngineHit(spec.upstream, payload, text, evidence))
    return hits


def _report[View: (ScopedUrl, RepoPath)](
    adapter: ReportAdapter[View],
    spec: ProbeSpec,
    view: View,
    launch: Launch,
) -> tuple[list[EngineHit], str]:
    with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
        workspace = Path(name).resolve()
        invocation = adapter.prepare(spec, view, workspace)
        report = (workspace / invocation.report).resolve()
        if workspace not in report.parents:
            raise ScopeError(f"{adapter.engine} report path leaves its workspace")
        try:
            launch(invocation, workspace)
        except EngineFailed as exc:
            return [], str(exc)
        try:
            return adapter.parse(report, spec), ""
        except EngineFailed as exc:
            return [], str(exc)


def _relay(
    adapter: RelayAdapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    launch: Launch,
) -> tuple[list[EngineHit], str]:
    token = secrets.token_hex(16)
    pairs: list[tuple[str, str]] = []
    budget = current_budget()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth, f"Bearer {token}"):
                self.send_response(401)
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            if length > 1_000_000:
                self.send_response(413)
                self.end_headers()
                return
            try:
                body = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            prompt = body.get("prompt") if isinstance(body, dict) else None
            if not isinstance(prompt, str):
                self.send_response(400)
                self.end_headers()
                return
            try:
                with BoundBudget(budget):
                    response = exchange(target, prompt, project.scope, root)
            except (CliError, OSError):
                self.send_response(502)
                self.end_headers()
                return
            pairs.append((prompt, response))
            payload = json.dumps({"text": response}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                # The engine gave up before the target answered. Nothing to send to.
                return

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = _with_model(RelayEndpoint(f"http://127.0.0.1:{port}/send", token), project)
        with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
            workspace = Path(name).resolve()
            invocation = adapter.prepare(spec, endpoint, workspace)
            failed: EngineFailed | None = None
            try:
                launch(invocation, workspace)
            except EngineFailed as exc:
                failed = exc
            oracle = ORACLES[spec.family]
            hits: list[EngineHit] = []
            for prompt, response in pairs:
                evidence = oracle(prompt, response, target)
                if evidence is not None:
                    hits.append(EngineHit(spec.upstream, prompt, response, evidence))
            if failed is not None:
                return hits, str(failed)
            if not pairs:
                return [], "engine finished without contacting the target"
            return hits, ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _with_model(endpoint: RelayEndpoint, project: Project) -> RelayEndpoint:
    """Hand the user's own attacker model to engines that must call one."""
    role = project.attacker
    if role is None or role.provider != "openai-compatible":
        return endpoint
    if role.base_url is None or role.model is None:
        return endpoint
    check_url(role.base_url, project.scope)
    key = resolve_secret(role.secret_ref) if role.secret_ref else None
    return RelayEndpoint(
        endpoint.url,
        endpoint.token,
        role.base_url.rstrip("/"),
        role.model,
        key,
    )


def _scoped_url(target: Target, scope: tuple[ScopeHost, ...]) -> ScopedUrl:
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    check_url(target.url, scope)
    return ScopedUrl(target.url, tuple(target.query.items()))


def _over_url(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[ScopedUrl]]:
    return adapter.view is ScopedUrl


def _over_repo(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[RepoPath]]:
    return adapter.view is RepoPath
