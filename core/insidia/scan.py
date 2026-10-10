"""Run the selected probes and write the run directory."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from insidia.adapters import find
from insidia.config import Project, Target
from insidia.errors import CliError, EngineFailed, ProbeError
from insidia.findings import Finding, normalize
from insidia.policy import Policy, get_policy
from insidia.probes import ProbeHit, run
from insidia.providers import build_provider
from insidia.registry import select
from insidia.results import (
    COMPLETE,
    ERROR,
    NOT_APPLICABLE,
    UNSUPPORTED,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)
from insidia.runstore import new_run_id, write_run
from insidia.scope import check_url, needs_confirmation
from insidia.transport import bind_budget, repo_path, reset_budget
from insidia.ui import Event, short


@dataclass(frozen=True)
class ScanOutcome:
    run_id: str
    run_dir: Path
    passed: bool
    findings: list[Finding]
    skips: list[str]
    execution_status: str = "complete"
    policy_verdict: str = ""

    def exit_code(self) -> int:
        verdict = self.policy_verdict or ("pass" if self.passed else "fail")
        return exit_for(self.execution_status, verdict)


def execute(
    project: Project,
    root: Path,
    *,
    policy_name: str | None = None,
    coverage: str | None = None,
    assume_yes: bool = False,
    progress: Callable[[Event], None] | None = None,
) -> ScanOutcome:
    if needs_confirmation(project.scope) and not assume_yes:
        raise CliError("a non-local host is in scope; pass --yes to scan it")
    policy = get_policy(policy_name or project.policy)
    if policy.name != "L1":
        raise CliError(
            f"policy {policy.name} is not available yet. "
            "It runs the same checks as L1, so it is not a higher assurance level. Use L1."
        )
    mode = coverage or project.coverage
    if project.attacker is not None:
        build_provider(project.attacker, project.scope)
    if project.judge is not None:
        build_provider(project.judge, project.scope)
    model_available = project.attacker is not None
    hits: list[ProbeHit] = []
    records: list[CheckRecord] = []
    controls: list[dict[str, str]] = []
    skips: list[str] = []
    count = len(project.targets)
    _say(
        progress,
        Event(
            "start",
            detail=(
                f"scan · policy {policy.name} · coverage {mode} · "
                f"{count} target{'' if count == 1 else 's'}"
            ),
        ),
    )
    token = bind_budget(project.targets)
    try:
        return _run_targets(
            project,
            root,
            policy,
            mode,
            model_available,
            hits,
            records,
            controls,
            skips,
            progress,
        )
    finally:
        reset_budget(token)


def _run_targets(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    model_available: bool,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
) -> ScanOutcome:
    for target in project.targets:
        _guard(target, project, root)
        if _grpc(target):
            reason = "gRPC probes are not available in this CLI yet"
            skips.append(f"{target.name}: {reason}")
            records.append(CheckRecord(target.name, "grpc", "", UNSUPPORTED, reason))
            _say(
                progress,
                Event("end", target.name, "grpc", result="inconclusive", detail=reason),
            )
            continue
        families = policy.families(target.kind)
        if not families:
            reason = f"no {policy.name} controls for {target.kind}"
            skips.append(f"{target.name}: {reason}")
            records.append(CheckRecord(target.name, target.kind, "", NOT_APPLICABLE, reason))
            _say(
                progress,
                Event(
                    "end",
                    target.name,
                    target.kind,
                    result="inconclusive",
                    detail=reason,
                ),
            )
            continue
        for family in families:
            chosen = select(family, mode, model_available=model_available)
            if not chosen:
                reason = "no engine installed for this check"
                skips.append(f"{target.name}: {family} has no runnable probe")
                records.append(CheckRecord(target.name, family, "", UNSUPPORTED, reason))
                controls.append(_recorded(policy, family, target.name, "inconclusive"))
                _say(
                    progress,
                    Event("end", target.name, family, result="inconclusive", detail=reason),
                )
                continue
            names = tuple(capability.engine for capability in chosen)
            _say(progress, Event("begin", target.name, family, names))
            began = time.monotonic()
            family_records: list[CheckRecord] = []
            reasons: list[str] = []
            for capability in chosen:
                adapter, spec = find(capability.probe)
                try:
                    found = run(adapter, spec, target, project, root, policy.control(family))
                except (EngineFailed, ProbeError) as exc:
                    reason = short(str(exc))
                    reasons.append(reason)
                    skips.append(f"{capability.engine}: {exc}")
                    family_records.append(
                        CheckRecord(target.name, family, capability.engine, ERROR, reason)
                    )
                    _say(
                        progress,
                        Event(
                            "note",
                            target.name,
                            family,
                            detail=f"{capability.engine}: {reason}",
                        ),
                    )
                    continue
                hits.extend(found)
                family_records.append(
                    CheckRecord(
                        target.name,
                        family,
                        capability.engine,
                        COMPLETE,
                        finding_count=len(found),
                    )
                )
            records.extend(family_records)
            result = _family_result(family_records)
            controls.append(_recorded(policy, family, target.name, result))
            _say(
                progress,
                Event(
                    "end",
                    target.name,
                    family,
                    names,
                    result,
                    reasons[0] if result == "inconclusive" else "",
                    time.monotonic() - began,
                ),
            )
    execution_status, policy_verdict = aggregate(records)
    findings = normalize(hits)
    passed = legacy_passed(execution_status, policy_verdict)
    run_id = new_run_id()
    _say(progress, Event("write", detail="Writing the report…"))
    run_dir = write_run(
        root,
        run_id,
        policy.name,
        passed,
        findings,
        controls,
        skips,
        execution_status=execution_status,
        policy_verdict=policy_verdict,
        config_digest=hashlib.sha256(project.path.read_bytes()).hexdigest(),
        coverage=mode,
    )
    return ScanOutcome(
        run_id,
        run_dir,
        passed,
        findings,
        skips,
        execution_status,
        policy_verdict,
    )


def _say(progress: Callable[[Event], None] | None, event: Event) -> None:
    if progress is not None:
        progress(event)


def _family_result(records: list[CheckRecord]) -> str:
    _status, verdict = aggregate(records)
    if verdict == "fail":
        return "fail"
    if _status == "complete" and verdict == "pass":
        return "pass"
    return "inconclusive"


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
