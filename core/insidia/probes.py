"""Run one probe through its engine adapter. The adapter value names the engine."""

from __future__ import annotations

import hmac
import json
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
)
from insidia.config import Project, Target
from insidia.errors import CliError, ConfigError, EngineFailed, ScopeError
from insidia.policy import Control
from insidia.process import launch_installed
from insidia.scope import ScopeHost, check_url
from insidia.transport import exchange, repo_path

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


def run(
    adapter: Adapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
    *,
    launch: Launch = launch_installed,
) -> list[ProbeHit]:
    if target.kind not in spec.target_kinds:
        return []
    match adapter:
        case BuiltIn():
            found = _judge(adapter, spec, target, project.scope, root)
        case RelayAdapter():
            found = _relay(adapter, spec, target, project, root, launch)
        case ReportAdapter() if _over_url(adapter):
            found = _report(adapter, spec, _scoped_url(target, project.scope), launch)
        case ReportAdapter() if _over_repo(adapter):
            found = _report(adapter, spec, RepoPath(repo_path(target, root)), launch)
        case _:
            raise CliError(f"{adapter.engine}: no adapter arm")
    return [
        ProbeHit(
            target.name,
            spec.family,
            adapter.engine,
            spec.probe,
            hit.response,
            control.severity,
            "high",
            control.track,
            control.taxonomy,
            control.remediation,
            hit.upstream,
            hit.evidence,
        )
        for hit in found
    ]


def _judge(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> list[EngineHit]:
    oracle = ORACLES[spec.family]
    hits: list[EngineHit] = []
    for payload in adapter.corpus[spec]:
        response = exchange(target, payload, scope, root)
        evidence = oracle(payload, response, target)
        if evidence is not None:
            hits.append(EngineHit(spec.upstream, payload, response, evidence))
    return hits


def _report[View: (ScopedUrl, RepoPath)](
    adapter: ReportAdapter[View],
    spec: ProbeSpec,
    view: View,
    launch: Launch,
) -> list[EngineHit]:
    with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
        workspace = Path(name).resolve()
        invocation = adapter.prepare(spec, view, workspace)
        report = (workspace / invocation.report).resolve()
        if workspace not in report.parents:
            raise ScopeError(f"{adapter.engine} report path leaves its workspace")
        launch(invocation, workspace)
        return adapter.parse(report, spec)


def _relay(
    adapter: RelayAdapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    launch: Launch,
) -> list[EngineHit]:
    token = secrets.token_hex(16)
    pairs: list[tuple[str, str]] = []

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
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = RelayEndpoint(f"http://127.0.0.1:{port}/send", token)
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
            if hits:
                return hits
            if failed is not None:
                raise failed
            return []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
