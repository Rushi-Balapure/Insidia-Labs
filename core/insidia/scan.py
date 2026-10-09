"""Run the selected probes and write the run directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from insidia.adapters import find
from insidia.config import Project, Target
from insidia.errors import CliError, EngineFailed
from insidia.findings import Finding, normalize
from insidia.policy import Policy, get_policy
from insidia.probes import ProbeHit, run
from insidia.providers import build_provider
from insidia.registry import select
from insidia.runstore import new_run_id, write_run
from insidia.scope import check_url, needs_confirmation
from insidia.transport import repo_path


@dataclass(frozen=True)
class ScanOutcome:
    run_id: str
    run_dir: Path
    passed: bool
    findings: list[Finding]
    skips: list[str]


def execute(
    project: Project,
    root: Path,
    *,
    policy_name: str | None = None,
    coverage: str | None = None,
    assume_yes: bool = False,
) -> ScanOutcome:
    if needs_confirmation(project.scope) and not assume_yes:
        raise CliError("a non-local host is in scope; pass --yes to scan it")
    policy = get_policy(policy_name or project.policy)
    mode = coverage or project.coverage
    if project.attacker is not None:
        build_provider(project.attacker, project.scope)
    if project.judge is not None:
        build_provider(project.judge, project.scope)
    model_available = project.attacker is not None
    hits: list[ProbeHit] = []
    controls: list[dict[str, str]] = []
    skips: list[str] = []
    for target in project.targets:
        _guard(target, project, root)
        if _grpc(target):
            skips.append(f"{target.name}: gRPC probes are not available in this CLI yet")
            continue
        families = policy.families(target.kind)
        if not families:
            skips.append(f"{target.name}: no {policy.name} controls for {target.kind}")
            continue
        for family in families:
            chosen = select(family, mode, model_available=model_available)
            if not chosen:
                skips.append(f"{target.name}: {family} has no runnable probe")
                controls.append(_recorded(policy, family, target.name, "skipped"))
                continue
            failed = False
            for capability in chosen:
                adapter, spec = find(capability.probe)
                try:
                    found = run(adapter, spec, target, project, root, policy.control(family))
                except EngineFailed as exc:
                    skips.append(f"{capability.engine}: {exc}")
                    continue
                hits.extend(found)
                failed = failed or bool(found)
            result = "fail" if failed else "pass"
            controls.append(_recorded(policy, family, target.name, result))
    if not any(item["result"] != "skipped" for item in controls):
        detail = "; ".join(skips) or "the policy did not run any controls for these targets"
        raise CliError(detail)
    findings = normalize(hits)
    passed = not any(item["result"] == "fail" for item in controls)
    run_id = new_run_id()
    run_dir = write_run(root, run_id, policy.name, passed, findings, controls, skips)
    return ScanOutcome(run_id, run_dir, passed, findings, skips)


def _recorded(policy: Policy, family: str, target: str, result: str) -> dict[str, str]:
    return {
        "id": family,
        "target": target,
        "result": result,
        "taxonomy": ",".join(policy.control(family).taxonomy),
    }


def _grpc(target: Target) -> bool:
    return bool(target.url and (target.api == "grpc" or target.url.startswith("grpc:")))


def _guard(target: Target, project: Project, root: Path) -> None:
    if target.kind == "repo":
        repo_path(target, root)
        return
    if target.command:
        raise CliError(f"{target.name}: local commands are not available in this release")
    if target.url is None:
        raise CliError(f"{target.name} needs a url")
    check_url(target.url, project.scope)
