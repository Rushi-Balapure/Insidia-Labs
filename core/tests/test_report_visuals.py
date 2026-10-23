"""Behavioral checks for report summaries and accessible offline charts."""

import pytest
from insidia.report_ui import (
    CheckCounts,
    check_counts,
    framework_chart,
    outcomes_chart,
    severity_chart,
    verdict_strip,
)
from insidia.report_ui import (
    tested_chart as render_tested_chart,
)
from insidia.score import Score


def test_check_counts_do_not_count_taxonomy_tags_as_checks() -> None:
    rows: list[dict[str, str | int]] = [
        {"result": "pass", "taxonomy": "owasp-web:A01,owasp-web:A02", "assurance": "low"},
        {"result": "fail", "taxonomy": "owasp-web:A01"},
        {"result": "info"},
        {"result": "not tested"},
        {"result": "unknown"},
    ]
    counts = check_counts(rows)
    assert (counts.total, counts.tested, counts.passed, counts.failed) == (5, 3, 1, 1)
    assert (counts.info, counts.untested, counts.low_assurance) == (1, 2, 1)


def test_incomplete_execution_never_has_a_green_policy_verdict() -> None:
    html = verdict_strip("incomplete", "L1<script>", "pass", check_counts([]))
    assert "res-pass" not in html
    assert "No checks recorded" in html
    assert "L1&lt;script&gt;" in html
    assert "<script>" not in html


@pytest.mark.parametrize(
    ("counts", "label", "dash"),
    [
        (CheckCounts(8, 0, 0, 32), "20%", "20.0000 100"),
        (CheckCounts(1, 1, 0, 0), "100%", "100.0000 100"),
        (CheckCounts(0, 0, 0, 4), "0%", "0.0000 100"),
        (CheckCounts(0, 0, 0, 0), "—", "0.0000 100"),
    ],
)
def test_tested_chart_handles_empty_and_boundary_counts(
    counts: CheckCounts, label: str, dash: str
) -> None:
    html = render_tested_chart(counts)
    assert f"<strong>{label}</strong>" in html
    assert f'stroke-dasharray="{dash}"' in html
    assert f"Checks tested: {counts.tested} of {counts.total}" in html
    assert "nan" not in html and "<script" not in html


def test_outcome_chart_retains_informational_and_low_assurance_counts() -> None:
    html = outcomes_chart(CheckCounts(2, 1, 3, 4, 1))
    assert "Passed: 2; Failed: 1; Not tested: 4; Informational: 3" in html
    assert "1 of the passed checks have low assurance" in html
    assert "width:20.0000%" in html
    assert "width:30.0000%" in html
    assert "<strong>10</strong> recorded checks" in html


def test_framework_chart_uses_item_counts_and_escapes_titles() -> None:
    html = framework_chart([Score("web", "Web <script>", 1, 2, 7, 1)])
    assert "Web &lt;script&gt;" in html
    assert "3 / 10 items tested" in html
    assert "Framework items: Passed: 2; Failed: 1; Not tested: 7" in html
    assert "2 passed · 1 failed · 7 not tested · 1 low assurance" in html
    assert "<script>" not in html


def test_severity_chart_preserves_all_findings_and_handles_zero() -> None:
    import re

    html = severity_chart(["critical", "high", "high", "informational", "unspecified"])
    counts = [int(value) for value in re.findall(r'data-count="(\d+)"', html)]
    assert counts == [1, 2, 0, 0, 2]
    assert sum(counts) == 5
    assert "width:50.0000%" in html
    empty = severity_chart([])
    assert "No findings to chart" in empty
    assert "0 findings total" in empty
    assert "nan" not in empty
