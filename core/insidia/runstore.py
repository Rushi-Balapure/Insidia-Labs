"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from insidia import __version__
from insidia.findings import Finding

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Insidia scan {run_id}</title>
<style>
body {{ font: 16px/1.5 sans-serif; margin: 2rem; color: #1d1d1f; background: #fff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; border-bottom: 1px solid #d2d2d7; padding: 0.4rem; }}
</style>
</head>
<body>
<h1>Insidia scan</h1>
<p>Policy {policy}. {result}. {count} finding(s).</p>
<table>
<thead><tr><th>Target</th><th>Engine</th><th>Probe</th><th>Severity</th><th>Evidence</th></tr></thead>
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
    benchmark = {
        "policy": policy,
        "passed": passed,
        "controls": controls,
        "skips": skips,
    }
    (directory / "benchmark.json").write_text(json.dumps(benchmark, indent=2) + "\n")
    rows = "\n".join(_row(finding) for finding in findings)
    if not rows:
        rows = "<tr><td colspan=\"5\">None</td></tr>"
    html = _HTML.format(
        run_id=_escape(run_id),
        policy=_escape(policy),
        result="Passed" if passed else "Failed",
        count=len(findings),
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


def _row(finding: Finding) -> str:
    cells = (
        finding.target,
        finding.engine,
        finding.probe,
        finding.severity,
        finding.response,
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
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "insidia", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
