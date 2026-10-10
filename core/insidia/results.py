"""Execution state and policy verdict. A finished scan is not the same as a pass."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

SCHEMA_VERSION = "2.0"

QUEUED = "queued"
RUNNING = "running"
COMPLETE = "complete"
ERROR = "error"
UNSUPPORTED = "unsupported"
NOT_APPLICABLE = "not_applicable"
CANCELLED = "cancelled"

PASS = "pass"
FAIL = "fail"
INCONCLUSIVE = "inconclusive"

RUN_COMPLETE = "complete"
RUN_INCOMPLETE = "incomplete"
RUN_CANCELLED = "cancelled"


@dataclass(frozen=True)
class CheckRecord:
    """One engine attempt for one target and capability."""

    target: str
    family: str
    engine: str
    state: str
    reason: str = ""
    finding_count: int = 0


def aggregate(records: Sequence[CheckRecord]) -> tuple[str, str]:
    """Return run execution status and policy verdict.

    A finding fails the policy even when another required check did not finish.
    No applicable check, or a required check that did not finish, is inconclusive.
    """

    applicable = [record for record in records if record.state != NOT_APPLICABLE]
    findings = sum(record.finding_count for record in records)
    unfinished = [record for record in applicable if record.state != COMPLETE]
    if findings:
        verdict = FAIL
    elif not applicable or unfinished:
        verdict = INCONCLUSIVE
    else:
        verdict = PASS
    if any(record.state == CANCELLED for record in records):
        status = RUN_CANCELLED
    elif unfinished or not applicable:
        status = RUN_INCOMPLETE
    else:
        status = RUN_COMPLETE
    return status, verdict


def exit_for(execution_status: str, policy_verdict: str) -> int:
    """0 is a finished pass. 1 is a finished fail. 2 is anything incomplete."""

    if execution_status == RUN_CANCELLED:
        return 130
    if execution_status != RUN_COMPLETE:
        return 2
    if policy_verdict == FAIL:
        return 1
    if policy_verdict == PASS:
        return 0
    return 2


def legacy_passed(execution_status: str, policy_verdict: str) -> bool:
    """True only for the exit-0 case. Older readers treat this as the whole result."""

    return exit_for(execution_status, policy_verdict) == 0
