"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from insidia import __version__, version_text
from insidia.errors import CliError
from insidia.findings import Finding, prepare_findings
from insidia.mask import SECRET_PATTERNS
from insidia.results import SCHEMA_VERSION, legacy_passed
from insidia.score import Score, coverage, score_frameworks, severity_rank

_CSS = """
:root {
  --crit: #8E1B3E;
  --high: #D43F3A;
  --med: #EE8A33;
  --low: #F2C230;
  --info: #3F8FD2;
  --pass: #2E8B57;
  --ink: #101028;
  --bg: #F6F6FB;
  --card: #fff;
  --line: #DADAE8;
  --muted: #5A5A80;
}
* { box-sizing: border-box; }
body {
  font: 16px/1.5 system-ui, sans-serif;
  margin: 0;
  color: var(--ink);
  background: var(--bg);
}
header {
  display: flex;
  gap: 1rem;
  align-items: center;
  padding: 1.2rem 2rem;
  color: #fff;
  background: #101028;
}
header svg { width: 48px; height: 48px; }
header h1 { margin: 0; font-size: 1.4rem; font-weight: 600; }
.brand { margin: 0; color: #B2B2D1; font-size: 0.85rem; }
nav {
  background: #fff;
  border-bottom: 1px solid var(--line);
  padding: 0.5rem 2rem;
  position: sticky;
  top: 0;
}
nav a {
  margin-right: 1.1rem;
  color: var(--ink);
  text-decoration: none;
  font-weight: 600;
}
main { padding: 1rem 2rem 3rem; max-width: 1100px; margin: auto; }
h2 {
  margin: 2rem 0 0.6rem;
  font-size: 1.15rem;
  border-bottom: 2px solid #101028;
  padding-bottom: 0.2rem;
}
.status {
  margin: 0 0 1rem;
  padding: 1rem 1.25rem;
  background: var(--card);
  border-left: 4px solid var(--high);
  border-radius: 8px;
}
.status.pass { border-left-color: var(--pass); }
.note, .muted { color: var(--muted); }
.tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.6rem; margin: 1rem 0; }
.tile { color: #fff; border-radius: 8px; padding: 0.7rem; text-align: center; }
.tile b { display: block; font-size: 2rem; line-height: 1.1; }
.tile span { font-size: 0.75rem; letter-spacing: 0.06em; }
.t-critical { background: var(--crit); }
.t-high { background: var(--high); }
.t-medium { background: var(--med); }
.t-low { background: var(--low); color: #222; }
.t-info { background: var(--info); }
table { border-collapse: collapse; width: 100%; background: var(--card); margin: 0.4rem 0; }
th, td {
  text-align: left;
  border-bottom: 1px solid var(--line);
  padding: 0.5rem 0.65rem;
  vertical-align: top;
}
th { color: var(--muted); font-weight: 600; }
code { font-family: ui-monospace, monospace; word-break: break-all; }
.sev, .res {
  display: inline-block;
  padding: 0.05rem 0.45rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 700;
}
.sev-critical, .bar-critical { background: var(--crit); color: #fff; }
.sev-high, .bar-high { background: var(--high); color: #fff; }
.sev-medium, .bar-medium { background: var(--med); color: #fff; }
.sev-low, .bar-low { background: var(--low); color: #222; }
.sev-info, .bar-info { background: var(--info); color: #fff; }
.res-fail { background: var(--high); color: #fff; }
.res-pass { background: var(--pass); color: #fff; }
.res-nt { background: #E4E4EE; color: #454573; }
details.finding {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 8px;
  margin: 0.6rem 0;
  overflow: hidden;
}
summary.bar {
  cursor: pointer;
  font-weight: 700;
  padding: 0.55rem 0.8rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  align-items: baseline;
}
.pid { font-family: ui-monospace, monospace; }
.right { margin-left: auto; font-size: 0.85rem; }
.body { padding: 0.2rem 1rem 1rem; }
pre {
  white-space: pre-wrap;
  word-break: break-word;
  background: #F1F1F7;
  padding: 0.6rem;
  border-radius: 6px;
}
footer {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  color: var(--muted);
}
@media (prefers-color-scheme: dark) {
  body { color: #F6F6FB; background: #101028; }
  nav, .status, table, details.finding { background: #181839; color: #F6F6FB; }
  nav a, h2 { color: #F6F6FB; }
  h2, header { border-color: #2E2E56; }
  .note, .muted, th, footer { color: #B2B2D1; }
  th, td, footer { border-bottom-color: #2E2E56; }
  pre { background: #101028; color: #F6F6FB; }
  .res-nt { background: #2E2E56; color: #F6F6FB; }
}
@media (max-width:700px) {
  header, nav, main { padding-left: 1rem; padding-right: 1rem; }
  .tiles { gap: 0.3rem; }
  .tile { padding: 0.35rem 0.15rem; }
  .tile b { font-size: 1.3rem; }
  .tile span { font-size: 0.6rem; letter-spacing: 0; }
  table thead { display: none; }
  table tr {
    display: block;
    border-bottom: 2px solid var(--line);
    padding: 0.3rem 0;
  }
  table td, table.scan th {
    display: flex;
    gap: 0.6rem;
    border: 0;
    padding: 0.2rem 0.4rem;
    max-width: 100%;
  }
  table td[data-l]::before {
    content: attr(data-l);
    flex: 0 0 6.2rem;
    font-weight: 600;
    color: var(--muted);
  }
  .right { margin-left: 0; width: 100%; }
  pre, code, td { overflow-wrap: anywhere; }
  body { overflow-x: hidden; }
}
@media (max-width:390px) {
  nav {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 1.1rem;
    max-width: 100%;
    overflow-x: auto;
  }
  nav a { margin-right: 0; white-space: nowrap; }
  table td[data-l], table.scan th, table.scan td {
    flex-direction: column;
    align-items: stretch;
    min-width: 0;
    max-width: 100%;
  }
  table td[data-l]::before { flex: none; }
}
@media print {
  nav { display: none; }
  details, details.finding { break-inside: avoid; }
  details > summary { list-style: none; }
  details > *:not(summary) { display: block !important; }
}
"""


_BEARER = re.compile(r"Bearer [A-Za-z0-9._\-]{8,}")


def config_snapshot(raw: bytes, secrets: tuple[str, ...] = ()) -> bytes:
    """Config text safe to store. Resolved secret values are never kept."""
    text = raw.decode("utf-8")
    cleaned = text
    for secret in secrets:
        if len(secret) >= 8 and secret in cleaned:
            cleaned = cleaned.replace(secret, "REDACTED")
    for _kind, pattern in SECRET_PATTERNS:
        cleaned = pattern.sub("REDACTED", cleaned)
    cleaned = _BEARER.sub("REDACTED", cleaned)
    for secret in secrets:
        if len(secret) >= 8 and secret in cleaned:
            raise CliError("refusing to store a configuration that still contains a secret")
    if cleaned == text:
        return raw
    return cleaned.encode("utf-8")


def new_run_id() -> str:
    # UTC, so that sorting the ids sorts the runs whatever the local zone.
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}-{secrets.token_hex(3)}"


def local_time(run_id: str) -> str:
    """When the run started, in this machine's time zone, or "" for an id without a stamp."""
    try:
        started = datetime.strptime(run_id[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return ""
    return started.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _format_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def write_run(
    root: Path,
    run_id: str,
    policy: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str]],
    skips: list[str],
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    config_digest: str = "",
    coverage: str = "standard",
    config_text: bytes | None = None,
    targets: tuple[tuple[str, str, str], ...] = (),
    started_epoch: float | None = None,
    scope_hosts: tuple[str, ...] = (),
) -> Path:
    runs = root / ".insidia" / "runs"
    staging = runs / f".{run_id}.partial"
    directory = runs / run_id
    if staging.exists():
        raise CliError(f"run {run_id} is already being written")
    staging.mkdir(parents=True)
    verdict = policy_verdict or ("pass" if passed else "fail")
    passed = legacy_passed(execution_status, verdict)
    findings = _stamp_targets(prepare_findings(findings), targets)
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
    headline = verdict_text(
        policy,
        passed,
        len(findings),
        execution_status=execution_status,
        policy_verdict=verdict,
        untested=not_tested(controls),
    )
    names = ["findings.json", "results.sarif", "benchmark.json", "report.html"]
    if config_text is not None:
        (staging / "insidia.yaml").write_bytes(config_text)
        names.append("insidia.yaml")
        config_digest = hashlib.sha256(config_text).hexdigest()
    finished_epoch = time.time()
    if started_epoch is None:
        duration_s = 0.0
    else:
        duration_s = round(max(0.0, finished_epoch - started_epoch), 3)
    finished_at = _format_epoch(finished_epoch)
    version = version_text()
    html = _render(
        run_id=run_id,
        policy=policy,
        headline=headline,
        passed=passed,
        findings=findings,
        controls=controls,
        skips=skips,
        scores=scores,
        targets=targets,
        started_at=local_time(run_id),
        finished_at=finished_at,
        duration_s=duration_s,
        version=version,
        execution_status=execution_status,
        verdict=verdict,
        coverage_name=coverage,
        scope_hosts=scope_hosts,
        config_digest=config_digest,
    )
    (staging / "report.html").write_text(html)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": local_time(run_id),
        "finished_at": finished_at,
        "duration_s": duration_s,
        "insidia_version": version,
        "policy": policy,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "config_digest": config_digest,
        "coverage": coverage,
        "files": {
            name: hashlib.sha256((staging / name).read_bytes()).hexdigest()
            for name in names
        },
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    staging.rename(directory)
    return directory


def not_tested(controls: list[dict[str, str]]) -> int:
    return sum(1 for control in controls if control.get("result") == "not tested")


def verdict_text(
    policy: str,
    passed: bool,
    findings: int,
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    untested: int = 0,
) -> str:
    verdict = policy_verdict or ("pass" if passed else "fail")
    label = "finding" if findings == 1 else "findings"
    if execution_status == "cancelled":
        return (
            f"Scan cancelled. Policy {policy} has no verdict. "
            f"{findings} {label} before it stopped."
        )
    if execution_status != "complete":
        if verdict == "fail":
            return (
                f"The scan did not finish. Policy {policy} did not pass. {findings} {label}."
            )
        return f"The scan did not finish. Policy {policy} is inconclusive."
    if verdict == "pass" and untested:
        checks = "check was" if untested == 1 else "checks were"
        return (
            f"The scan ran. Policy {policy} passed with no findings, "
            f"but {untested} {checks} not tested. See the report's coverage."
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

    if directory.is_symlink():
        raise CliError(f"run {directory.name} manifest escapes the run directory")
    path = directory / "manifest.json"
    if path.is_symlink():
        raise CliError(f"run {directory.name} manifest escapes the run directory")
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
        artifact_path = directory / name
        if artifact_path.is_symlink():
            raise CliError(f"run {directory.name} manifest escapes the run directory")
        artifact = artifact_path.resolve()
        if root != artifact and root not in artifact.parents:
            raise CliError(f"run {directory.name} manifest escapes the run directory")
        if not artifact.is_file():
            raise CliError(f"run {directory.name} is missing {name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            raise CliError(f"run {directory.name} {name} does not match the manifest")
    return loaded


def is_contained_run(root: Path, path: Path) -> bool:
    """True when path is a real directory inside root/.insidia/runs."""

    insidia = root / ".insidia"
    runs = insidia / "runs"
    if insidia.is_symlink() or runs.is_symlink() or path.is_symlink() or not path.is_dir():
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return runs.resolve() in resolved.parents


def latest_run(root: Path) -> Path | None:
    insidia = root / ".insidia"
    runs = insidia / "runs"
    if insidia.is_symlink() or runs.is_symlink() or not runs.is_dir():
        return None
    names = sorted(
        path.name
        for path in runs.iterdir()
        if not path.name.startswith(".") and is_contained_run(root, path)
    )
    if not names:
        return None
    return runs / names[-1]


def _score_rows(scores: tuple[Score, ...]) -> str:
    lines = []
    for score in scores:
        lines.append(
            "<tr>"
            f'<td data-l="Framework">{_escape(score.title)}</td>'
            f'<td data-l="Failed">{score.failed}</td>'
            f'<td data-l="Passed">{score.passed}</td>'
            f'<td data-l="Not tested">{score.not_tested}</td>'
            "</tr>"
        )
    return "\n".join(lines)


def _coverage_rows(controls: list[dict[str, str]]) -> str:
    lines = []
    labels = ("Control", "Title", "Result")
    for row in coverage(controls):
        pairs = zip(labels, row, strict=True)
        cells = "".join(
            f'<td data-l="{label}">{_escape(value)}</td>' for label, value in pairs
        )
        lines.append(f"<tr>{cells}</tr>")
    return "\n".join(lines)


_BUCKETS = ("critical", "high", "medium", "low", "informational")
_BUCKET_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}
_BUCKET_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def _bucket(severity: str) -> str:
    if severity in {"info", "informational", "unspecified"}:
        return "informational"
    if severity in _BUCKETS:
        return severity
    return "informational"


def _render(
    *,
    run_id: str,
    policy: str,
    headline: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str]],
    skips: list[str],
    scores: tuple[Score, ...],
    targets: tuple[tuple[str, str, str], ...],
    started_at: str,
    finished_at: str,
    duration_s: float,
    version: str,
    execution_status: str,
    verdict: str,
    coverage_name: str,
    scope_hosts: tuple[str, ...],
    config_digest: str,
) -> str:
    names = _target_names(findings, controls, targets)
    title = "Security scan report"
    if names:
        title = f"{title}: {', '.join(names)}"
    status = "pass" if passed else "fail"
    tiles = _tiles(findings)
    nav = (
        '<nav><a href="#summary">Summary</a><a href="#targets">Targets</a>'
        f'<a href="#findings">Findings ({len(findings)})</a>'
        '<a href="#remediation">Remediation</a><a href="#coverage">Coverage</a>'
        '<a href="#frameworks">Frameworks</a>'
        '<a href="#scaninfo">Scan info</a></nav>'
    )
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_escape(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<header>",
        _mark(),
        "<div>",
        '<p class="brand">Insidia Labs</p>',
        f"<h1>{_escape(title)}</h1>",
        (
            f'<p class="brand">Run {_escape(run_id)} · {_escape(started_at)}'
            f" · Policy {_escape(policy)} · {_escape(version)}</p>"
        ),
        "</div>",
        "</header>",
        nav,
        "<main>",
        '<h2 id="summary">Executive summary</h2>',
        f'<p class="status {status}">{_escape(headline)}</p>',
        tiles,
        (
            '<p class="note">This report is test evidence mapped to framework ids. '
            "It is not a certification. A pass means our probes did not trigger, "
            "not that the risk is absent. Checks that were not tested are not "
            "evidence that those risks are absent.</p>"
        ),
        '<h2 id="targets">Targets</h2>',
        _targets_table(findings, controls, targets),
        '<h2 id="findings">Findings by severity</h2>',
        _finding_cards(findings, run_id),
        '<h2 id="remediation">Remediation summary</h2>',
        _remediation_table(findings),
        '<h2 id="coverage">Coverage by target</h2>',
        _coverage_by_target(controls, skips),
        '<h2 id="frameworks">Framework mapping</h2>',
        "<table>",
        (
            "<thead><tr><th>Framework</th><th>Failed</th>"
            "<th>Passed</th><th>Not tested</th></tr></thead>"
        ),
        f"<tbody>\n{_score_rows(scores)}\n</tbody>",
        "</table>",
        "<details>",
        "<summary>OWASP item list</summary>",
        "<table>",
        "<thead><tr><th>Control</th><th>Title</th><th>Result</th></tr></thead>",
        f"<tbody>\n{_coverage_rows(controls)}\n</tbody>",
        "</table>",
        "</details>",
        '<h2 id="scaninfo">Scan information</h2>',
        _scan_table(
            run_id,
            started_at,
            finished_at,
            duration_s,
            version,
            policy,
            coverage_name,
            execution_status,
            verdict,
            scope_hosts,
            findings,
            skips,
            config_digest,
        ),
        "<footer>",
        (
            "<p>Artefacts: findings.json, results.sarif, benchmark.json, "
            "manifest.json, report.html</p>"
        ),
        f"<p><code>insidia rerun {_escape(run_id)}</code></p>",
        "</footer>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts) + "\n"


def _target_names(
    findings: list[Finding],
    controls: list[dict[str, str]],
    targets: tuple[tuple[str, str, str], ...],
) -> list[str]:
    names: list[str] = []
    for name, _kind, _endpoint in targets:
        if name and name not in names:
            names.append(name)
    for control in controls:
        name = str(control.get("target", ""))
        if name and name not in names:
            names.append(name)
    for finding in findings:
        if finding.target and finding.target not in names:
            names.append(finding.target)
    return names


def _tiles(findings: list[Finding]) -> str:
    counts = {bucket: 0 for bucket in _BUCKETS}
    for finding in findings:
        counts[_bucket(finding.severity)] += 1
    cells = []
    for bucket in _BUCKETS:
        css = _BUCKET_CLASS[bucket]
        label = _BUCKET_LABEL[bucket]
        cells.append(
            f'<div class="tile t-{css}"><b>{counts[bucket]}</b><span>{label}</span></div>'
        )
    return '<div class="tiles">' + "".join(cells) + "</div>"


def _targets_table(
    findings: list[Finding],
    controls: list[dict[str, str]],
    targets: tuple[tuple[str, str, str], ...],
) -> str:
    meta = {name: (kind, endpoint) for name, kind, endpoint in targets}
    names = _target_names(findings, controls, targets)
    if not names:
        return '<p class="note">No targets.</p>'
    rows = []
    for name in names:
        kind, endpoint = meta.get(name, ("", ""))
        if not kind:
            kind = next((item.target_kind for item in findings if item.target == name), "")
        if not endpoint:
            endpoint = next((item.endpoint for item in findings if item.target == name), "")
        counts = {bucket: 0 for bucket in _BUCKETS}
        for finding in findings:
            if finding.target == name:
                counts[_bucket(finding.severity)] += 1
        tallies = {"fail": 0, "pass": 0, "not tested": 0}
        for control in controls:
            if control.get("target") == name:
                result = control.get("result", "")
                if result in tallies:
                    tallies[result] += 1
        chips = "".join(
            f'<td data-l="{_BUCKET_LABEL[bucket]}">{counts[bucket]}</td>' for bucket in _BUCKETS
        )
        summary = (
            f'{tallies["fail"]} fail · {tallies["pass"]} pass · '
            f'0 weak · {tallies["not tested"]} not tested'
        )
        rows.append(
            "<tr>"
            f'<td data-l="Target">{_escape(name)}</td>'
            f'<td data-l="Kind">{_escape(kind)}</td>'
            f'<td data-l="Endpoint"><code>{_escape(endpoint)}</code></td>'
            f"{chips}"
            f'<td data-l="Checks">{_escape(summary)}</td>'
            "</tr>"
        )
    head = (
        "<tr><th>Target</th><th>Kind</th><th>Endpoint</th>"
        "<th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th>"
        "<th>Checks</th></tr>"
    )
    return f"<table class=\"targets\"><thead>{head}</thead><tbody>{''.join(rows)}</tbody></table>"


def _finding_cards(findings: list[Finding], run_id: str) -> str:
    if not findings:
        return '<p class="note">No findings.</p>'
    return "\n".join(
        _finding_card(finding, index, run_id) for index, finding in enumerate(findings)
    )


def _finding_card(finding: Finding, index: int, run_id: str) -> str:
    bucket = _bucket(finding.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    opened = " open" if index < 2 else ""
    title = finding.title or finding.attack
    check = finding.check_id or finding.probe
    factors = "; ".join(finding.risk_factors) or "base score"
    reported = len(finding.engines) or 1
    engine_word = "engine" if reported == 1 else "engines"
    corroborated = "cross-validated" if finding.cross_validated else "not cross-validated"
    risk_factor = (
        f'<span class="sev sev-{css}">{label}</span>'
        f" · confidence {_escape(finding.confidence)}"
        f" · reported by {reported} {engine_word} ({corroborated})"
    )
    fields = (
        ("Synopsis", _escape(finding.synopsis or finding.remediation)),
        ("Description", _escape(finding.description or finding.remediation)),
        ("Solution", _escape(finding.remediation)),
        ("Risk factor", risk_factor),
        (
            "Insidia Risk Score",
            _escape(f"{finding.risk_score:.1f}/10 ({factors})"),
        ),
        ("References", _escape(_reference_text(finding.taxonomy))),
        ("See Also", _see_also(finding.references)),
        ("Plugin output", _plugin_output(finding)),
        ("Re-run", f"<code>insidia rerun {_escape(run_id)}</code>"),
    )
    body = "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in fields)
    return (
        f'<details class="finding"{opened}>'
        f'<summary class="bar bar-{css}">'
        f'<span class="pid">{_escape(check)}</span> {_escape(title)}'
        f'<span class="right">{_escape(finding.target)} · {label} {finding.risk_score:.1f}</span>'
        f"</summary><dl>{body}</dl></details>"
    )


def _reference_text(taxonomy: tuple[str, ...]) -> str:
    labels: list[str] = []
    for tag in taxonomy:
        prefix, separator, item = tag.partition(":")
        if not separator:
            labels.append(tag)
            continue
        if prefix == "owasp-llm":
            labels.append(f"OWASP {item}")
        elif prefix == "owasp-web":
            labels.append(f"OWASP Web {item}")
        elif prefix == "owasp-api":
            labels.append(f"OWASP API {item}")
        elif prefix == "owasp-asi":
            labels.append(f"OWASP ASI {item}")
        elif prefix == "cwe":
            labels.append(item)
        else:
            labels.append(tag)
    return " · ".join(labels) or "None"


def _see_also(urls: tuple[str, ...]) -> str:
    links = []
    for url in urls:
        if url.startswith(("https://", "http://")):
            href = _escape(url).replace('"', "%22")
            links.append(f'<a href="{href}">{_escape(url)}</a>')
        elif url:
            links.append(_escape(url))
    return "<br>".join(links) or "None"


# One card shows this many characters of plugin output. A longer body keeps
# its start, and the card names this cap when that body was cut.
_PLUGIN_OUTPUT_CAP = 500


def _plugin_output(finding: Finding) -> str:
    """Masked evidence as text. Counts and the endpoint or file:line sit with it."""
    excerpt, truncated = _capped_plugin_excerpt(finding)
    if finding.location and "://" not in finding.location:
        affected = finding.location
    else:
        affected = finding.endpoint or finding.location or finding.target
    kind = f" · {finding.target_kind}" if finding.target_kind else ""
    cap = f" · truncated to {_PLUGIN_OUTPUT_CAP} characters" if truncated else ""
    lines = [
        f"<pre>{_escape(excerpt)}</pre>",
        (
            f"<p>{len(finding.observations)} observations"
            f" · probe <code>{_escape(finding.probe)}</code>"
            f" · engine {_escape(finding.engine)}{cap}</p>"
        ),
        f"<p>evidence_hash <code>{_escape(finding.evidence_hash)}</code></p>",
        f"<p>Affected {_escape(finding.target)}{kind} · <code>{_escape(affected)}</code></p>",
    ]
    return "".join(lines)


def _capped_plugin_excerpt(finding: Finding) -> tuple[str, bool]:
    """One excerpt. Observations that already hold the response are not copied again."""
    text = _plugin_source(finding)
    if len(text) <= _PLUGIN_OUTPUT_CAP:
        return text, False
    first, _, _rest = text.partition("\n")
    excerpt = first if first.strip() else text[:_PLUGIN_OUTPUT_CAP]
    if len(excerpt) > _PLUGIN_OUTPUT_CAP:
        excerpt = excerpt[:_PLUGIN_OUTPUT_CAP]
    return excerpt, True


def _plugin_source(finding: Finding) -> str:
    chunks: list[str] = []
    for item in finding.observations:
        if item.evidence and item.evidence not in chunks:
            chunks.append(item.evidence)
    response = finding.response
    if response and not any(response in chunk for chunk in chunks):
        chunks.append(response)
    return "\n".join(chunks)


def _remediation_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="note">Nothing to fix.</p>'
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.remediation, []).append(finding)
    ranked = sorted(
        grouped.items(),
        key=lambda item: (
            min(severity_rank(finding.severity) for finding in item[1]),
            -len(item[1]),
            item[0],
        ),
    )
    rows = []
    for text, items in ranked:
        worst = min(items, key=lambda finding: severity_rank(finding.severity))
        bucket = _bucket(worst.severity)
        names = ", ".join(sorted({finding.target for finding in items}))
        rows.append(
            "<tr>"
            f'<td data-l="Action">{_escape(text)}</td>'
            f'<td data-l="Fixes">{len(items)}</td>'
            f'<td data-l="Worst"><span class="sev sev-{_BUCKET_CLASS[bucket]}">'
            f"{_BUCKET_LABEL[bucket]}</span></td>"
            f'<td data-l="Targets">{_escape(names)}</td>'
            "</tr>"
        )
    return (
        '<table class="remediation"><thead><tr><th>Action</th><th>Fixes</th>'
        f"<th>Worst</th><th>Targets</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _coverage_by_target(controls: list[dict[str, str]], skips: list[str]) -> str:
    if not controls:
        return '<p class="note">No checks were recorded.</p>'
    by_target: dict[str, list[dict[str, str]]] = {}
    for control in controls:
        by_target.setdefault(str(control.get("target", "")), []).append(control)
    blocks = []
    for name, rows in by_target.items():
        body = []
        for control in rows:
            result = control.get("result", "")
            label, css = {
                "fail": ("FAIL", "fail"),
                "pass": ("PASS", "pass"),
                "not tested": ("NOT TESTED", "nt"),
            }.get(result, (result.upper() or "NOT TESTED", "nt"))
            why = _coverage_why(control, skips)
            body.append(
                "<tr>"
                f'<td data-l="Check"><code>{_escape(str(control.get("id", "")))}</code></td>'
                f'<td data-l="Result"><span class="res res-{css}">{label}</span></td>'
                f'<td data-l="Why">{_escape(why)}</td>'
                "</tr>"
            )
        blocks.append(
            f"<h3>{_escape(name)}</h3>"
            '<table class="coverage"><thead><tr>'
            "<th>Check</th><th>Result</th><th>Why</th></tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
        )
    return "\n".join(blocks)


# Same cause, so the same sentence. Different causes must not share this text.
_JUDGE_WHY = {
    "ai.harmful_content_policy": "needs a judge model: `models: {}`",
    "ai.bias": "needs a judge model: `models: {}`",
    "ai.citation_groundedness": "needs a judge model: `models: {}`",
}


def _coverage_why(control: dict[str, str], skips: list[str]) -> str:
    detail = control.get("detail", "").strip()
    if detail:
        return detail
    result = control.get("result", "")
    family = str(control.get("id", ""))
    target = str(control.get("target", ""))
    if result == "fail":
        return "A probe reported this check."
    if result == "pass":
        return "Probes ran and did not trigger."
    if result != "not tested":
        return result or "No result recorded."
    for skip in skips:
        if family and family in skip:
            return skip
    if family in _JUDGE_WHY:
        return _JUDGE_WHY[family]
    if family:
        return f"{family} was not run for {target or 'this target'}"
    return "No check id was recorded for this row."


def _scan_table(
    run_id: str,
    started_at: str,
    finished_at: str,
    duration_s: float,
    version: str,
    policy: str,
    coverage_name: str,
    execution_status: str,
    verdict: str,
    scope_hosts: tuple[str, ...],
    findings: list[Finding],
    skips: list[str],
    config_digest: str,
) -> str:
    engines: list[str] = []
    for finding in findings:
        names = finding.engines or (finding.engine,)
        for name in names:
            if name and name not in engines:
                engines.append(name)
    engines.sort()
    rows = (
        ("Run id", run_id),
        ("Started", started_at),
        ("Finished", finished_at),
        ("Duration", f"{duration_s:.3f}s"),
        ("Insidia version", version),
        ("Policy", policy),
        ("Coverage", coverage_name),
        ("Execution status", execution_status),
        ("Verdict", verdict),
        ("Scope hosts", ", ".join(scope_hosts)),
        ("Engines", ", ".join(engines)),
        ("Skips", str(len(skips))),
        ("Config digest", config_digest),
    )
    body = "".join(
        f"<tr><th>{_escape(label)}</th><td>{_escape(value)}</td></tr>" for label, value in rows
    )
    return f"<table class=\"scan\">{body}</table>"


def _sarif_level(severity: str) -> str:
    """GitHub code scanning: error, warning, and note. Info and low are notes."""
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    if severity in {"low", "informational", "info"}:
        return "note"
    return "none"


def _stamp_targets(
    findings: list[Finding], targets: tuple[tuple[str, str, str], ...]
) -> list[Finding]:
    known = {name: (kind, endpoint) for name, kind, endpoint in targets}
    stamped: list[Finding] = []
    for finding in findings:
        kind, endpoint = known.get(finding.target, ("", ""))
        stamped.append(
            replace(
                finding,
                target_kind=kind or finding.target_kind,
                endpoint=endpoint or finding.endpoint,
            )
        )
    return stamped


def _file_location(location: str) -> dict[str, object] | None:
    """A repository path stays file:line. A URL is not a file."""
    if not location or "://" in location:
        return None
    path, separator, line = location.rpartition(":")
    if separator and line.isdigit() and path:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(line)},
            }
        }
    return {"physicalLocation": {"artifactLocation": {"uri": location}}}


def _endpoint_location(target: str, endpoint: str) -> dict[str, object]:
    """Point GitHub code scanning at an endpoint that is not a file in the repo.

    Code scanning requires physicalLocation.artifactLocation.uri to be a relative
    path and drops results whose uri is an absolute URL. The method and URL are
    the logicalLocation. The physicalLocation is a relative fallback plus a snippet
    of that same endpoint, so the result still appears when the URL is not a file.
    """

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _relative_endpoint_uri(target, endpoint)},
            "region": {"startLine": 1, "snippet": {"text": endpoint}},
        },
        "logicalLocations": [
            {"kind": "endpoint", "name": target, "fullyQualifiedName": endpoint}
        ],
    }


def _relative_endpoint_uri(target: str, endpoint: str) -> str:
    text = endpoint.strip()
    _method, separator, rest = text.partition(" ")
    url = rest if separator and "://" in rest else text
    if "://" not in url:
        return f"insidia-endpoints/{_safe_part(target)}"
    parsed = urlparse(url)
    host = _safe_part(parsed.netloc or "unknown")
    parts = [
        _safe_part(part)
        for part in parsed.path.split("/")
        if part not in {"", ".", ".."}
    ]
    suffix = "/".join(parts) if parts else "root"
    return f"insidia-endpoints/{host}/{suffix}"


def _safe_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return cleaned or "target"


def _sarif_result_location(finding: Finding) -> dict[str, object]:
    filed = _file_location(finding.location)
    if filed is not None:
        return filed
    endpoint = finding.endpoint
    if not endpoint and finding.location and "://" in finding.location:
        endpoint = finding.location
    if not endpoint:
        endpoint = finding.target or "target"
    return _endpoint_location(finding.target or "target", endpoint)


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sarif(findings: list[Finding]) -> dict[str, object]:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in findings:
        if finding.probe not in seen:
            seen.add(finding.probe)
            rules.append(
                {
                    "id": finding.probe,
                    "name": finding.attack,
                    "properties": {"security-severity": f"{finding.risk_score:.1f}"},
                }
            )
        result: dict[str, object] = {
            "ruleId": finding.probe,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.engine}: {finding.attack} on {finding.target}"},
            "properties": {
                "engine": finding.engine,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "security-severity": f"{finding.risk_score:.1f}",
            },
        }
        result["locations"] = [_sarif_result_location(finding)]
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
