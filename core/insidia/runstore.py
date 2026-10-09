"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict
from pathlib import Path

from insidia import __version__
from insidia.findings import Finding
from insidia.score import Score, coverage, score_frameworks

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Insidia scan {run_id}</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; margin: 2rem; color: #1d1d1f; background: #f5f5f7; }}
table {{ border-collapse: collapse; width: 100%; background: #fff; }}
th, td {{ text-align: left; border-bottom: 1px solid #d2d2d7; padding: 0.4rem; }}
code {{ font-family: ui-monospace, monospace; }}
@media (prefers-color-scheme: dark) {{
  body {{ color: #f5f5f7; background: #1d1d1f; }}
  table {{ background: #2c2c2e; }}
  th, td {{ border-bottom-color: #424245; }}
}}
</style>
</head>
<body>
<h1>Insidia scan</h1>
<p>This report is test evidence mapped to framework ids. It is not a certification.</p>
<p>Policy {policy}. {result}. {count} finding(s).</p>
<h2>Scores</h2>
<table>
<thead><tr><th>Framework</th><th>Failed</th><th>Passed</th><th>Not tested</th></tr></thead>
<tbody>
{scores}
</tbody>
</table>
<h2>Coverage</h2>
<table>
<thead><tr><th>Control</th><th>Title</th><th>Result</th></tr></thead>
<tbody>
{coverage}
</tbody>
</table>
<h2>Findings</h2>
<table>
<thead>
<tr>
<th>Target</th><th>Engine</th><th>Probe</th><th>Severity</th>
<th>Evidence</th><th>Fix this</th><th>Re-run</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def new_run_id() -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{secrets.token_hex(3)}"


def write_run(
    root: Path,
    run_id: str,
    policy: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str]],
    skips: list[str],
) -> Path:
    directory = root / ".insidia" / "runs" / run_id
    directory.mkdir(parents=True, exist_ok=False)
    payload = [finding.as_json() for finding in findings]
    (directory / "findings.json").write_text(json.dumps(payload, indent=2) + "\n")
    (directory / "results.sarif").write_text(json.dumps(_sarif(findings), indent=2) + "\n")
    scores = score_frameworks(controls)
    benchmark = {
        "policy": policy,
        "passed": passed,
        "controls": controls,
        "skips": skips,
        "scores": [asdict(score) for score in scores],
    }
    (directory / "benchmark.json").write_text(json.dumps(benchmark, indent=2) + "\n")
    rows = "\n".join(_row(finding, policy) for finding in findings)
    if not rows:
        rows = "<tr><td colspan=\"7\">None</td></tr>"
    html = _HTML.format(
        run_id=_escape(run_id),
        policy=_escape(policy),
        result="Passed" if passed else "Failed",
        count=len(findings),
        scores=_score_rows(scores),
        coverage=_coverage_rows(controls),
        rows=rows,
    )
    (directory / "report.html").write_text(html)
    return directory


def latest_run(root: Path) -> Path | None:
    runs = root / ".insidia" / "runs"
    if not runs.is_dir():
        return None
    names = sorted(path.name for path in runs.iterdir() if path.is_dir())
    if not names:
        return None
    return runs / names[-1]


def _score_rows(scores: tuple[Score, ...]) -> str:
    lines = []
    for score in scores:
        cells = (
            _escape(score.title),
            str(score.failed),
            str(score.passed),
            str(score.not_tested),
        )
        lines.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
    return "\n".join(lines)


def _coverage_rows(controls: list[dict[str, str]]) -> str:
    lines = []
    for control_id, title, result in coverage(controls):
        cells = (_escape(control_id), _escape(title), _escape(result))
        lines.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
    return "\n".join(lines)


def _row(finding: Finding, policy: str) -> str:
    engines = ", ".join(finding.engines) if finding.engines else finding.engine
    rerun = f"insidia scan --policy {policy}"
    cells = (
        finding.target,
        engines,
        finding.probe,
        finding.severity,
        finding.response,
        finding.remediation,
        rerun,
    )
    return "<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in cells) + "</tr>"


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sarif(findings: list[Finding]) -> dict[str, object]:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in findings:
        if finding.probe not in seen:
            seen.add(finding.probe)
            rules.append({"id": finding.probe, "name": finding.attack})
        results.append(
            {
                "ruleId": finding.probe,
                "level": "error" if finding.severity == "high" else "warning",
                "message": {"text": f"{finding.engine}: {finding.attack} on {finding.target}"},
                "properties": {"engine": finding.engine},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Insidia", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
