"""Accessible presentation helpers for offline scan reports."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import escape


def status_badge(result: str, *, uppercase: bool = False) -> str:
    """Keep an explicit label alongside each status color and symbol."""
    css = {
        "pass": "pass",
        "pass (low assurance)": "low",
        "fail": "fail",
        "info": "info",
        "not tested": "nt",
    }.get(result, "nt")
    label = result.upper() if uppercase else result
    if result == "pass (low assurance)" and uppercase:
        label = "PASS (low assurance)"
    return f'<span class="res res-{css}">{escape(label or "not tested")}</span>'


@dataclass(frozen=True)
class CheckCounts:
    """Check outcomes, counted independently of framework mappings and findings."""

    passed: int
    failed: int
    info: int
    untested: int
    low_assurance: int = 0

    @property
    def tested(self) -> int:
        return self.passed + self.failed + self.info

    @property
    def total(self) -> int:
        return self.tested + self.untested


def check_counts(controls: Sequence[Mapping[str, str | int]]) -> CheckCounts:
    passed = sum(row.get("result") == "pass" for row in controls)
    failed = sum(row.get("result") == "fail" for row in controls)
    info = sum(row.get("result") == "info" for row in controls)
    weak = sum(
        row.get("result") == "pass" and row.get("assurance") == "low" for row in controls
    )
    return CheckCounts(passed, failed, info, len(controls) - passed - failed - info, weak)


def verdict_strip(execution: str, policy: str, verdict: str, counts: CheckCounts) -> str:
    execution_css = "pass" if execution == "complete" else "nt"
    policy_css = "pass" if verdict == "pass" and execution == "complete" else "nt"
    if verdict == "fail":
        policy_css = "fail"
    coverage_css = "nt" if counts.untested or not counts.total else "info"
    coverage = f"{counts.tested} of {counts.total} checks tested"
    cells = (
        ("Execution", execution, execution_css),
        (f"Policy {policy}", verdict, policy_css),
        ("Coverage", coverage if counts.total else "No checks recorded", coverage_css),
    )
    body = "".join(
        f'<div><dt>{escape(label)}</dt><dd><span class="res res-{css}">'
        f"{escape(value)}</span></dd></div>" for label, value, css in cells
    )
    return f'<dl class="verdict-strip">{body}</dl>'
