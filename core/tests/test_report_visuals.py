"""Behavioral checks for report summaries and accessible offline charts."""

import pytest
from insidia.report_ui import (
    CheckCounts,
    check_counts,
    verdict_strip,
)
from insidia.report_ui import (
    tested_chart as render_tested_chart,
)


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
