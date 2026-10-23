"""Accessible presentation helpers for offline scan reports."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import escape

from insidia.score import Score, coverage


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


def summary_metrics(counts: CheckCounts, findings: int) -> str:
    cells = (
        ("Findings", findings, "failed" if findings else "neutral"),
        ("Checks tested", f"{counts.tested} / {counts.total}", "neutral"),
        ("Passed checks", counts.passed, "passed"),
        ("Failed checks", counts.failed, "failed"),
        ("Not tested", counts.untested, "untested"),
    )
    body = "".join(
        f'<div class="metric metric-{css}"><dt>{label}</dt><dd>{value}</dd></div>'
        for label, value, css in cells
    )
    note = f"{counts.low_assurance} passed checks have low assurance."
    if counts.info:
        note += f" {counts.info} tested checks are informational."
    return f'<dl class="metrics">{body}</dl><p class="note">{note}</p>'


def stacked_bar(segments: Sequence[tuple[str, int, str]], *, unit: str) -> str:
    """A proportional bar with a complete textual alternative, including zero counts."""
    total = sum(count for _label, count, _css in segments)
    description = "; ".join(f"{label}: {count}" for label, count, _css in segments)
    bars = "".join(
        f'<span class="segment segment-{css}" style="width:{count / total * 100:.4f}%">'
        "</span>" for _label, count, css in segments if count and total
    )
    return (
        f'<div class="stacked-bar" role="img" aria-label="{escape(unit)}: '
        f'{escape(description)}"><div class="bar-track" aria-hidden="true">{bars}</div></div>'
    )


def framework_bar(score: Score) -> str:
    segments = (
        ("Passed", score.passed, "pass"),
        ("Failed", score.failed, "fail"),
        ("Not tested", score.not_tested, "nt"),
    )
    total = score.passed + score.failed + score.not_tested
    tested = score.passed + score.failed
    return (
        stacked_bar(segments, unit="Framework items")
        + f'<small class="muted">{tested} / {total} items tested</small>'
    )



def framework_groups(controls: Sequence[Mapping[str, str | int]], scores: Sequence[Score]) -> str:
    rows = coverage(controls)
    groups = []
    for score in scores:
        items = [row for row in rows if row[0].startswith(f"{score.framework}:")]
        summary = (
            f"{escape(score.title)} · {score.passed} passed · {score.failed} failed · "
            f"{score.not_tested} not tested"
        )
        groups.append(
            f'<details class="framework-group" open><summary>{summary}</summary>'
            f"{framework_item_table(items)}</details>"
        )
    return "\n".join(groups)


def framework_item_table(rows: Sequence[tuple[str, str, str]]) -> str:
    body = []
    for control_id, title, result in rows:
        outcome = "pass" if result.startswith("pass") else result
        body.append(
            f'<tr class="coverage-row" data-result="{escape(outcome)}">'
            f'<td data-l="Control">{escape(control_id)}</td>'
            f'<td data-l="Title">{escape(title)}</td>'
            f'<td data-l="Result">{status_badge(result)}</td></tr>'
        )
    return (
        '<table class="framework-items"><thead><tr><th>Control</th><th>Title</th>'
        f'<th>Result</th></tr></thead><tbody>\n{"\n".join(body)}\n</tbody></table>'
    )
