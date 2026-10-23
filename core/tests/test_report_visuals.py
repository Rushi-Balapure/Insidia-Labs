"""Behavioral checks for report summaries and accessible offline charts."""

from insidia.report_ui import check_counts, verdict_strip


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
    assert 'res-pass' not in html
    assert "No checks recorded" in html
    assert "L1&lt;script&gt;" in html
    assert "<script>" not in html
