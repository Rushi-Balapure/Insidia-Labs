"""Behavioral checks for report summaries and accessible offline charts."""

from pathlib import Path

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
        (CheckCounts(9999, 0, 0, 1), "&gt;99.9%", "99.9900 100"),
        (CheckCounts(1, 0, 0, 9999), "&lt;0.1%", "0.0100 100"),
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
    assert "Passed checks with low assurance: 1" in html
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
    assert "Total findings: 0" in empty
    assert "nan" not in empty


def test_generated_report_separates_check_totals_from_framework_items(tmp_path: Path) -> None:
    from insidia.runstore import write_run

    controls: list[dict[str, str | int]] = [
        {"id": "one", "result": "pass", "taxonomy": "owasp-web:A03", "target": "demo"},
        {"id": "two", "result": "pass", "taxonomy": "owasp-web:A03", "target": "demo"},
        {"id": "unknown", "result": "unknown", "target": "demo"},
    ]
    directory = write_run(tmp_path, "sample", "L1", True, [], controls, [])
    html = (directory / "report.html").read_text()
    assert "Checks tested: 2 of 3; not tested: 1" in html
    assert "1 / 10 items tested" in html
    assert "Insidia ran 2 of 3 checks" in html
    assert 'id="check-filter-nt"' in html
    assert 'id="framework-filter-nt"' in html
    from insidia.report_script import REPORT_SCRIPT

    assert html.count("<script") == 1
    assert f"<script data-report-ui>{REPORT_SCRIPT}</script>" in html
    assert "<link" not in html and "<img" not in html


def test_full_brand_lockups_are_embedded_with_unique_svg_references(tmp_path: Path) -> None:
    import re
    from xml.etree import ElementTree

    from insidia.runstore import write_run

    directory = write_run(tmp_path, "brand-example", "L1", True, [], [], [])
    html = (directory / "report.html").read_text()
    header = html.split("<header>", 1)[1].split("</header>", 1)[0]
    assert header.count('aria-label="Insidia Labs"') == 2
    assert 'class="report-logo report-logo-dark"' in header
    assert 'class="report-logo report-logo-light"' in header
    ids = re.findall(r'\bid="([^"]+)"', header)
    assert len(ids) == len(set(ids))
    for reference in re.findall(r'url\(#([^)]+)\)|href="#([^"]+)"', header):
        assert (reference[0] or reference[1]) in ids
    for svg in re.findall(r"<svg\b.*?</svg>", header, re.S):
        root = ElementTree.fromstring(svg)
        assert root.attrib["viewBox"] == "0 0 8718 2445"
        assert not list(root.iter("{http://www.w3.org/2000/svg}image"))
        assert not list(root.iter("{http://www.w3.org/2000/svg}text"))


def test_navigation_opens_separate_report_views_in_the_offline_document(tmp_path: Path) -> None:
    import re

    from insidia.runstore import write_run

    directory = write_run(tmp_path, "page-example", "L1", True, [], [], [])
    html = (directory / "report.html").read_text()
    pages = re.findall(r'<section class="report-page" data-page="([^"]+)"[^>]*>', html)
    assert pages == [
        "summary",
        "findings",
        "remediation",
        "targets",
        "coverage",
        "frameworks",
        "scaninfo",
    ]
    nav = html.split('<nav aria-label="Report sections">', 1)[1].split("</nav>", 1)[0]
    assert re.findall(r'href="\?page=([^"]+)"', nav) == pages
    assert 'href="#' not in nav
    assert html.count('aria-labelledby="summary"') == 1
    assert html.count('aria-labelledby="findings" hidden') == 1
    assert ".report-page[hidden] { display: block !important; }" in html


def test_check_details_expand_outside_tables_and_keep_complete_reasons(tmp_path: Path) -> None:
    from insidia.runstore import write_run

    reason = "Long recorded limitation " * 80 + "<script>alert(1)</script>"
    controls: list[dict[str, str | int]] = [
        {"id": "demo.check", "target": "demo", "result": "not tested", "detail": reason}
    ]
    directory = write_run(tmp_path, "accordion-example", "L1", True, [], controls, [])
    html = (directory / "report.html").read_text()
    checks = html.split('<div class="coverage-checks">', 1)[1].split("</details>", 1)[0]
    assert '<details class="check-accordion coverage-row"' in checks
    assert "</summary>" in checks and '<div class="accordion-body">' in checks
    assert "<table" not in checks
    assert "Long recorded limitation " * 80 in checks
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in checks


