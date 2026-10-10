"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict
from pathlib import Path

from insidia import __version__
from insidia.errors import CliError
from insidia.findings import Finding
from insidia.results import SCHEMA_VERSION, legacy_passed
from insidia.score import Score, coverage, score_frameworks

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Insidia scan {run_id}</title>
<style>
body {{
  font: 16px/1.5 system-ui, sans-serif;
  margin: 0;
  color: #101028;
  background: #F6F6FB;
}}
header {{
  display: flex;
  gap: 1rem;
  align-items: center;
  padding: 1.5rem 2rem;
  color: #fff;
  background: #101028;
}}
header svg {{ width: 48px; height: 48px; }}
header h1 {{ margin: 0; font-size: 1.5rem; font-weight: 600; }}
.brand {{ margin: 0; color: #B2B2D1; font-size: 0.85rem; letter-spacing: 0.04em; }}
main {{ padding: 1.5rem 2rem 3rem; }}
.status {{
  margin: 0 0 1.5rem;
  padding: 1rem 1.25rem;
  background: #fff;
  border-left: 4px solid #ED7B39;
  border-radius: 8px;
}}
.status.pass {{ border-left-color: #101028; }}
.note {{ color: #454573; }}
h2 {{ margin: 2rem 0 0.5rem; font-size: 1.1rem; }}
table {{ border-collapse: collapse; width: 100%; background: #fff; border-radius: 8px; }}
th, td {{
  text-align: left;
  border-bottom: 1px solid #2E2E56;
  padding: 0.55rem 0.7rem;
  vertical-align: top;
}}
th {{ color: #454573; font-weight: 600; }}
code {{ font-family: ui-monospace, monospace; }}
@media (prefers-color-scheme: dark) {{
  body {{ color: #F6F6FB; background: #101028; }}
  .status, table {{ background: #181839; }}
  .status {{ border-left-color: #ED7B39; }}
  .status.pass {{ border-left-color: #F6C13F; }}
  .note, th {{ color: #B2B2D1; }}
  th, td {{ border-bottom-color: #2E2E56; }}
}}
</style>
</head>
<body>
<header>
{mark}
<div>
<p class="brand">Insidia Labs</p>
<h1>Scan report</h1>
</div>
</header>
<main>
<p class="status {status}">{headline}</p>
<p class="note">This report is test evidence mapped to framework ids. It is not a certification.</p>
<h2>Scores</h2>
<p class="note">Failed means a check saw a problem. Passed means it did not.
Not tested means this scan did not run that item.</p>
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
<p class="note">Each row is one issue. Fix this is the change to make.
Re-run repeats the same policy.</p>
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
</main>
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
    *,
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    config_digest: str = "",
    coverage: str = "standard",
) -> Path:
    runs = root / ".insidia" / "runs"
    staging = runs / f".{run_id}.partial"
    directory = runs / run_id
    if staging.exists():
        raise CliError(f"run {run_id} is already being written")
    staging.mkdir(parents=True)
    verdict = policy_verdict or ("pass" if passed else "fail")
    passed = legacy_passed(execution_status, verdict)
    payload = [finding.as_json() for finding in findings]
    (staging / "findings.json").write_text(json.dumps(payload, indent=2) + "\n")
    (staging / "results.sarif").write_text(json.dumps(_sarif(findings), indent=2) + "\n")
    scores = score_frameworks(controls)
    benchmark = {
        "schema_version": SCHEMA_VERSION,
        "policy": policy,
        "passed": passed,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "controls": controls,
        "skips": skips,
        "scores": [asdict(score) for score in scores],
    }
    (staging / "benchmark.json").write_text(json.dumps(benchmark, indent=2) + "\n")
    rows = "\n".join(_row(finding, run_id) for finding in findings)
    if not rows:
        rows = '<tr><td colspan="7">None</td></tr>'
    headline = verdict_text(
        policy,
        passed,
        len(findings),
        execution_status=execution_status,
        policy_verdict=verdict,
    )
    html = _HTML.format(
        run_id=_escape(run_id),
        status="pass" if passed else "fail",
        headline=_escape(headline),
        scores=_score_rows(scores),
        coverage=_coverage_rows(controls),
        rows=rows,
        mark=_mark(),
    )
    (staging / "report.html").write_text(html)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "policy": policy,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "config_digest": config_digest,
        "coverage": coverage,
        "files": {
            name: hashlib.sha256((staging / name).read_bytes()).hexdigest()
            for name in ("findings.json", "results.sarif", "benchmark.json", "report.html")
        },
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    staging.rename(directory)
    return directory


def verdict_text(
    policy: str,
    passed: bool,
    findings: int,
    *,
    execution_status: str = "complete",
    policy_verdict: str | None = None,
) -> str:
    verdict = policy_verdict or ("pass" if passed else "fail")
    label = "finding" if findings == 1 else "findings"
    if execution_status != "complete":
        if verdict == "fail":
            return (
                f"The scan did not finish. Policy {policy} did not pass. "
                f"{findings} {label}. Execution {execution_status}."
            )
        return (
            f"The scan did not finish. Policy {policy} is inconclusive. "
            f"Execution {execution_status}."
        )
    if verdict == "pass":
        return f"The scan ran. Policy {policy} passed. No findings."
    if verdict == "inconclusive":
        return f"The scan ran. Policy {policy} is inconclusive."
    return f"The scan ran. Policy {policy} did not pass. {findings} {label}."


def _mark() -> str:
    return (Path(__file__).resolve().parent / "brand" / "mark.svg").read_text().strip()


def read_manifest(directory: Path) -> dict[str, object] | None:
    """Check a finalized manifest. A legacy run with no manifest is left unchanged."""

    path = directory / "manifest.json"
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise CliError(f"run {directory.name} manifest is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise CliError(f"run {directory.name} manifest is not valid JSON")
    files = loaded.get("files")
    if not isinstance(files, dict):
        raise CliError(f"run {directory.name} manifest does not list its files")
    root = directory.resolve()
    for name, digest in files.items():
        if not isinstance(name, str) or not isinstance(digest, str) or "/" in name:
            raise CliError(f"run {directory.name} manifest has an invalid file entry")
        artifact = (directory / name).resolve()
        if root != artifact and root not in artifact.parents:
            raise CliError(f"run {directory.name} manifest escapes the run directory")
        if not artifact.is_file():
            raise CliError(f"run {directory.name} is missing {name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            raise CliError(f"run {directory.name} {name} does not match the manifest")
    return loaded


def latest_run(root: Path) -> Path | None:
    runs = root / ".insidia" / "runs"
    if not runs.is_dir():
        return None
    names = sorted(
        path.name for path in runs.iterdir() if path.is_dir() and not path.name.startswith(".")
    )
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


def _row(finding: Finding, run_id: str) -> str:
    engines = ", ".join(finding.engines) if finding.engines else finding.engine
    count = len(finding.engines) or 1
    engines = f"{engines} (reported by {count})"
    rerun = f"insidia rerun {run_id}"
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


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "unspecified":
        return "none"
    return "warning"


def _sarif_location(location: str) -> dict[str, object] | None:
    if not location:
        return None
    if "://" in location:
        return {"physicalLocation": {"artifactLocation": {"uri": location}}}
    path, separator, line = location.rpartition(":")
    if separator and line.isdigit() and path:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(line)},
            }
        }
    return {"physicalLocation": {"artifactLocation": {"uri": location}}}


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
        result: dict[str, object] = {
            "ruleId": finding.probe,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.engine}: {finding.attack} on {finding.target}"},
            "properties": {"engine": finding.engine, "severity": finding.severity},
        }
        location = _sarif_location(finding.location)
        if location is not None:
            result["locations"] = [location]
        results.append(result)
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
