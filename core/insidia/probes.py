"""Run one probe through its engine adapter. The adapter value names the engine."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
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
    RepoPath,
    ReportAdapter,
    ScopedUrl,
)
from insidia.config import Project, Target
from insidia.errors import CliError, ConfigError, ScopeError
from insidia.policy import Control
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


def _not_installed(invocation: Invocation, workspace: Path) -> None:
    raise CliError(f"{invocation.program} is not installed")


def run(
    adapter: Adapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
    *,
    launch: Launch = _not_installed,
) -> list[ProbeHit]:
    if target.kind not in spec.target_kinds:
        return []
    match adapter:
        case BuiltIn():
            found = _judge(adapter, spec, target, project.scope, root)
        case RelayAdapter():
            raise CliError(f"{adapter.engine}: relay engines are not available in this release")
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


def _scoped_url(target: Target, scope: tuple[ScopeHost, ...]) -> ScopedUrl:
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    check_url(target.url, scope)
    return ScopedUrl(target.url)


def _over_url(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[ScopedUrl]]:
    return adapter.view is ScopedUrl


def _over_repo(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[RepoPath]]:
    return adapter.view is RepoPath
