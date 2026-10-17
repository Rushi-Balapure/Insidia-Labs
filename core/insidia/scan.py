"""Run the selected probes and write the run directory."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from insidia.adapters import find
from insidia.config import Project, Target
from insidia.errors import CliError, EngineFailed, ProbeError, ScopeError
from insidia.findings import Finding, normalize
from insidia.mask import bind_secrets, mask
from insidia.policy import Policy, get_policy
from insidia.probes import ProbeHit, run
from insidia.registry import select, unlock_hint
from insidia.results import (
    CANCELLED,
    COMPLETE,
    ERROR,
    LIMITED,
    NOT_APPLICABLE,
    UNSUPPORTED,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)
from insidia.runstore import _format_epoch, config_snapshot, new_run_id, not_tested, write_run
from insidia.scope import check_url, needs_confirmation, unauthorized_host
from insidia.transport import bind_budget, current_budget, preflight, repo_path, reset_budget
from insidia.ui import Event, short

# Printed only when INSIDIA_VULN_DB=1. The default argv keeps these engines offline.
_NETWORK_DB = {
    "trivy": (
        "trivy downloads a vulnerability database from mirror.gcr.io and ghcr.io "
        "because INSIDIA_VULN_DB=1"
    ),
    "osv-scanner": (
        "osv-scanner downloads a vulnerability database from api.osv.dev "
        "because INSIDIA_VULN_DB=1"
    ),
}


@dataclass(frozen=True)
class ScanOutcome:
    run_id: str
    run_dir: Path
    passed: bool
    findings: list[Finding]
    skips: list[str]
    execution_status: str = "complete"
    policy_verdict: str = ""
    untested: int = 0
    notes: tuple[str, ...] = ()
    started_at: str = ""

    def exit_code(self) -> int:
        verdict = self.policy_verdict or ("pass" if self.passed else "fail")
        return exit_for(self.execution_status, verdict)


def execute(
    project: Project,
    root: Path,
    policy_name: str | None = None,
    coverage: str | None = None,
    assume_yes: bool = False,
    progress: Callable[[Event], None] | None = None,
) -> ScanOutcome:
    blocked = unauthorized_host(project.scope)
    if blocked is not None:
        raise ScopeError(f"{blocked} needs authorized: true in scope")
    if needs_confirmation(project.scope) and not assume_yes:
        raise CliError("a non-local host is in scope; pass --yes to scan it")
    policy = get_policy(policy_name or project.policy)
    if policy.name != "L1":
        raise CliError(
            f"policy {policy.name} is not available yet. "
            "It runs the same checks as L1, so it is not a higher assurance level. Use L1."
        )
    _require_model_secrets(project)
    mode = coverage or project.coverage
    _validate_targets(project, root)
    secrets = _configured_secrets(project)
    bind_secrets(secrets)
    snapshot = config_snapshot(project.path.read_bytes(), secrets)
    # Scope only. L1 does not connect to a configured attacker or judge.
    for role in (project.attacker, project.judge):
        if role is not None and role.base_url is not None:
            check_url(role.base_url, project.scope)
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
    started = time.time()
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
            snapshot,
            started,
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
    config_text: bytes,
    started_epoch: float,
) -> ScanOutcome:
    notes: list[str] = []
    try:
        _scan_targets(
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
            notes,
        )
    except KeyboardInterrupt:
        reason = "cancelled by the user"
        skips.append(f"scan: {reason}")
        records.append(CheckRecord("", "scan", "", CANCELLED, reason))
        _say(progress, Event("cancel", detail="Scan cancelled. Saving what finished…"))
    return _finish(
        project,
        root,
        policy,
        mode,
        hits,
        records,
        controls,
        skips,
        progress,
        config_text,
        notes,
        started_epoch,
    )


def _scan_targets(
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
    notes: list[str],
) -> None:
    for target in project.targets:
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
        try:
            unreachable = preflight(target, project.scope, root) if families else ""
        except ScopeError as exc:
            # Contact already started. Keep earlier targets and finish the run.
            _record_refused_redirect(target, exc, skips, records, progress)
            continue
        if unreachable:
            reason = short(mask(unreachable), limit=140)
            skips.append(f"{target.name}: {reason}")
            records.append(CheckRecord(target.name, "target", "", ERROR, reason))
            hint = (
                " Start the app, or point url in insidia.yaml at it."
                if ("unreachable" in reason)
                else ""
            )
            _say(
                progress,
                Event(
                    "end",
                    target.name,
                    "target",
                    result="inconclusive",
                    detail=f"{reason}. Its {len(families)} checks did not run.{hint}",
                ),
            )
            continue
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
                reason = unlock_hint(family, model_available)
                skips.append(f"{target.name}: {family} has no runnable probe; {reason}")
                records.append(CheckRecord(target.name, family, "", LIMITED, reason))
                controls.append(_recorded(policy, family, target.name, "not tested", reason))
                _say(
                    progress,
                    Event("end", target.name, family, result="not tested", detail=reason),
                )
                continue
            names = tuple(capability.engine for capability in chosen)
            _say(progress, Event("begin", target.name, family, names, sent=_counter(target)))
            began = time.monotonic()
            family_records: list[CheckRecord] = []
            reasons: list[str] = []
            for capability in chosen:
                note = _NETWORK_DB.get(capability.engine)
                if os.environ.get("INSIDIA_VULN_DB") != "1":
                    note = None
                if note is not None and note not in notes:
                    notes.append(note)
                    _say(progress, Event("note", detail=note))
                adapter, spec = find(capability.probe)
                reason_limit = 90
                try:
                    attempt = run(adapter, spec, target, project, root, policy.control(family))
                except ScopeError as exc:
                    # A hop refused mid-check is this check's result, not a scan abort.
                    attempt_hits: tuple[ProbeHit, ...] = ()
                    error = _refused_redirect(target, exc)
                    untested = ""
                    reason_limit = 300
                except (EngineFailed, ProbeError) as exc:
                    attempt_hits = ()
                    error = str(exc)
                    untested = ""
                else:
                    attempt_hits = attempt.hits
                    error = attempt.error
                    untested = attempt.untested
                # A relay under the prompt minimum stays out of engines and reported_by.
                if not untested:
                    hits.extend(attempt_hits)
                if error:
                    reason = short(mask(error), limit=reason_limit)
                    reasons.append(reason)
                    skips.append(f"{capability.engine}: {reason}")
                    family_records.append(
                        CheckRecord(
                            target.name,
                            family,
                            capability.engine,
                            ERROR,
                            reason,
                            finding_count=len(attempt_hits),
                        )
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
                family_records.append(
                    CheckRecord(
                        target.name,
                        family,
                        capability.engine,
                        LIMITED if untested else COMPLETE,
                        short(mask(untested)) if untested else "",
                        finding_count=len(attempt_hits),
                    )
                )
            records.extend(family_records)
            result = _family_result(family_records)
            detail = _detail(result, reasons, family_records)
            controls.append(_recorded(policy, family, target.name, result, detail))
            # A limited run is too shallow to credit, even when one prompt hit.
            finished = tuple(
                record.engine
                for record in family_records
                if record.state == COMPLETE and record.engine
            )
            shown = f"{', '.join(finished)} · {detail}" if finished and detail else detail
            _say(
                progress,
                Event(
                    "end",
                    target.name,
                    family,
                    finished,
                    result,
                    shown,
                    time.monotonic() - began,
                ),
            )


def _counter(target: Target) -> Callable[[], int] | None:
    table = current_budget()
    if table is None or target.name not in table:
        return None
    limiter = table[target.name][0]
    base = limiter.sent
    return lambda: limiter.sent - base


def _finish(
    project: Project,
    root: Path,
    policy: Policy,
    mode: str,
    hits: list[ProbeHit],
    records: list[CheckRecord],
    controls: list[dict[str, str]],
    skips: list[str],
    progress: Callable[[Event], None] | None,
    config_text: bytes,
    notes: list[str],
    started_epoch: float,
) -> ScanOutcome:
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
        coverage=mode,
        config_text=config_text,
        targets=_target_facts(project),
        started_epoch=started_epoch,
        scope_hosts=tuple(item.host for item in project.scope),
    )
    return ScanOutcome(
        run_id,
        run_dir,
        passed,
        findings,
        skips,
        execution_status,
        policy_verdict,
        not_tested(controls),
        tuple(notes),
        started_at=_format_epoch(started_epoch),
    )


def _say(progress: Callable[[Event], None] | None, event: Event) -> None:
    if progress is not None:
        progress(event)


def _require_model_secrets(project: Project) -> None:
    """Fail before any probe when a configured model key is missing."""
    from insidia.config import resolve_secret

    for role in (project.attacker, project.judge):
        if role is not None and role.secret_ref:
            resolve_secret(role.secret_ref)


def _configured_secrets(project: Project) -> tuple[str, ...]:
    from insidia.config import resolve_secret

    found: list[str] = []
    for target in project.targets:
        if target.auth is None:
            continue
        try:
            found.append(resolve_secret(target.auth.secret_ref))
        except CliError:
            continue
    return tuple(found)


def _detail(result: str, reasons: list[str], records: list[CheckRecord]) -> str:
    if result == "inconclusive" and reasons:
        return reasons[0]
    if result == "not tested":
        return next((record.reason for record in records if record.reason), "")
    limited = [record.reason for record in records if record.state == LIMITED and record.reason]
    if limited:
        return "; ".join(dict.fromkeys(limited))
    return ""


def _family_result(records: list[CheckRecord]) -> str:
    _status, verdict = aggregate(records)
    if verdict == "fail":
        return "fail"
    if _status == "complete" and verdict == "pass":
        return "pass"
    if _status == "complete":
        return "not tested"
    return "inconclusive"


def _target_facts(project: Project) -> tuple[tuple[str, str, str], ...]:
    """Name, kind, and endpoint (method plus URL, or the repo path) for the report."""
    facts: list[tuple[str, str, str]] = []
    for target in project.targets:
        if target.kind == "repo":
            endpoint = target.path or ""
        elif target.url:
            endpoint = f"{target.method} {target.url}"
        else:
            endpoint = ""
        facts.append((target.name, target.kind, endpoint))
    return tuple(facts)


def _recorded(
    policy: Policy, family: str, target: str, result: str, detail: str = ""
) -> dict[str, str]:
    row = {
        "id": family,
        "target": target,
        "result": result,
        "taxonomy": ",".join(policy.control(family).taxonomy),
    }
    if detail:
        row["detail"] = detail
    return row


def _refused_redirect(target: Target, exc: ScopeError) -> str:
    """Names the target and the hop a mid-scan redirect refusal would not request."""
    return f"{target.name}: {exc}"


def _record_refused_redirect(
    target: Target,
    exc: ScopeError,
    skips: list[str],
    records: list[CheckRecord],
    progress: Callable[[Event], None] | None,
) -> None:
    reason = short(mask(_refused_redirect(target, exc)), limit=300)
    skips.append(reason)
    records.append(CheckRecord(target.name, "target", "", ERROR, reason))
    _say(
        progress,
        Event("end", target.name, "target", result="inconclusive", detail=reason),
    )


def _validate_targets(project: Project, root: Path) -> None:
    """Refuse a bad target before any of them is contacted."""
    for target in project.targets:
        try:
            _guard(target, project, root)
        except ScopeError as exc:
            raise ScopeError(f"{exc}. No target was contacted.") from exc


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
