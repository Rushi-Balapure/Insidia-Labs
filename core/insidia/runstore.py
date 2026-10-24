"""Write one run directory under .insidia/runs."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import secrets
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import yaml  # type: ignore[import-untyped]

from insidia import __version__, version_text
from insidia.errors import CliError
from insidia.findings import Finding, prepare_findings
from insidia.mask import SECRET_PATTERNS, mask
from insidia.report_script import REPORT_SCRIPT
from insidia.report_styles import REPORT_CSS as _CSS
from insidia.report_ui import (
    CheckCounts,
    check_counts,
    coverage_filter,
    framework_chart,
    framework_groups,
    outcomes_chart,
    report_identity,
    severity_chart,
    status_badge,
    summary_metrics,
    tested_chart,
    untested_reason,
    verdict_strip,
)
from insidia.results import SCHEMA_VERSION, legacy_passed
from insidia.score import Score, score_frameworks, severity_rank

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
    return started.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def _format_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def write_run(
    root: Path,
    run_id: str,
    policy: str,
    passed: bool,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    skips: list[str],
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    config_digest: str = "",
    coverage: str = "standard",
    config_text: bytes | None = None,
    targets: tuple[tuple[str, str, str], ...] = (),
    started_epoch: float | None = None,
    scope_hosts: tuple[str, ...] = (),
    engines: tuple[str, ...] | None = None,
    judge: str = "none",
    rate_limits: tuple[tuple[str, float, int], ...] = (),
    rerun_of: str = "",
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
    if config_text is not None:
        config_digest = hashlib.sha256(config_text).hexdigest()
    baseline_id, baseline_dir = _select_baseline(
        runs,
        run_id,
        config_digest,
        frozenset(_target_names(findings, controls, targets)),
        rerun_of,
    )
    tracked, fixed = _compare_findings(run_id, findings, baseline_id, baseline_dir)
    payload = []
    for finding, item in zip(findings, tracked, strict=True):
        document = finding.as_json()
        document["state"] = item.state
        document["first_seen_run"] = item.first_seen_run
        payload.append(document)
    (staging / "findings.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    (staging / "findings.csv").write_text(
        _findings_csv(findings, run_id, targets),
        encoding="utf-8",
        newline="",
    )
    (staging / "results.sarif").write_text(
        json.dumps(_sarif(findings, controls, targets), indent=2) + "\n",
        encoding="utf-8",
    )
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
    (staging / "benchmark.json").write_text(
        json.dumps(benchmark, indent=2) + "\n",
        encoding="utf-8",
    )
    names = ["findings.json", "findings.csv", "results.sarif", "benchmark.json", "report.html"]
    if config_text is not None:
        (staging / "insidia.yaml").write_bytes(config_text)
        names.append("insidia.yaml")
        config_digest = hashlib.sha256(config_text).hexdigest()
    finished_epoch = time.time()
    if started_epoch is None:
        duration_s = 0.0
        started_at = local_time(run_id)
    else:
        duration_s = round(max(0.0, finished_epoch - started_epoch), 3)
        started_at = _format_epoch(started_epoch)
    finished_at = _format_epoch(finished_epoch)
    version = version_text()
    ran = _engine_names(findings, engines)
    limits = _limit_rows(rate_limits)
    # report.html is hashed after it is written, because the page lists these digests.
    artefacts = {
        name: hashlib.sha256((staging / name).read_bytes()).hexdigest()
        for name in names
        if name != "report.html"
    }
    html = _render(
        _ReportData(
            run_id=run_id,
            policy=policy,
            passed=passed,
            findings=findings,
            controls=controls,
            skips=skips,
            scores=scores,
            targets=targets,
            started_at=started_at,
            finished_at=finished_at,
            duration_s=duration_s,
            version=version,
            execution_status=execution_status,
            verdict=verdict,
            coverage_name=coverage,
            scope_hosts=scope_hosts,
            config_digest=config_digest,
            judge=judge,
            rate_limits=limits,
            engines=tuple(ran),
            artefacts=tuple(artefacts.items()),
            baseline_id=baseline_id,
            fixed=fixed,
            new_count=sum(1 for item in tracked if item.state == "new"),
            still_open_count=sum(1 for item in tracked if item.state == "still_open"),
            fixed_count=len(fixed),
        )
    )
    (staging / "report.html").write_text(html, encoding="utf-8")
    artefacts["report.html"] = hashlib.sha256((staging / "report.html").read_bytes()).hexdigest()
    artefacts = {name: artefacts[name] for name in names}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": duration_s,
        "insidia_version": version,
        "policy": policy,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "config_digest": config_digest,
        "coverage": coverage,
        "models": {"judge": judge},
        "rate_limits": limits,
        "engines": ran,
        "skips": skips,
        "files": artefacts,
    }
    if rerun_of:
        manifest["rerun_of"] = rerun_of
    (staging / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    staging.rename(directory)
    return directory


@dataclass(frozen=True)
class _Tracked:
    state: str
    first_seen_run: str


@dataclass(frozen=True)
class _FixedFinding:
    title: str
    target: str
    evidence_hash: str


def _select_baseline(
    runs: Path,
    run_id: str,
    config_digest: str,
    target_names: frozenset[str],
    rerun_of: str,
) -> tuple[str, Path | None]:
    """The run this one is compared with, and its directory when that directory is readable."""
    if rerun_of:
        return rerun_of, _contained_child(runs, rerun_of)
    earlier = _earlier_run_dirs(runs, run_id)
    for path in earlier:
        manifest = _loose_object(path / "manifest.json")
        digest = manifest.get("config_digest") if manifest is not None else None
        if isinstance(digest, str) and digest == config_digest:
            return path.name, path
    for path in earlier:
        if _stored_target_names(path) == target_names:
            return path.name, path
    return "", None


def _compare_findings(
    run_id: str,
    findings: list[Finding],
    baseline_id: str,
    baseline_dir: Path | None,
) -> tuple[tuple[_Tracked, ...], tuple[_FixedFinding, ...]]:
    """Mark each current finding new or still open, and list baseline hashes that are gone."""
    if not baseline_id:
        return tuple(_Tracked("new", run_id) for _finding in findings), ()
    previous = _object_list(baseline_dir / "findings.json") if baseline_dir is not None else []
    origin: dict[str, str] = {}
    for item in previous:
        digest = item.get("evidence_hash")
        if not isinstance(digest, str) or digest in origin:
            continue
        first = item.get("first_seen_run")
        origin[digest] = first if isinstance(first, str) and first else baseline_id
    current = {finding.evidence_hash for finding in findings}
    fixed: list[_FixedFinding] = []
    for item in previous:
        digest = item.get("evidence_hash")
        if not isinstance(digest, str) or digest in current:
            continue
        title = item.get("title")
        target = item.get("target")
        fixed.append(
            _FixedFinding(
                title if isinstance(title, str) else "",
                target if isinstance(target, str) else "",
                digest,
            )
        )
    tracked = tuple(
        _Tracked("still_open", origin[finding.evidence_hash])
        if finding.evidence_hash in origin
        else _Tracked("new", run_id)
        for finding in findings
    )
    return tracked, tuple(fixed)


def _earlier_run_dirs(runs: Path, run_id: str) -> list[Path]:
    """Finalized runs whose ids sort before this one. Names starting with '.' are skipped."""
    if runs.is_symlink() or not runs.is_dir():
        return []
    found: list[Path] = []
    try:
        children = list(runs.iterdir())
    except OSError:
        return []
    for path in children:
        name = path.name
        if name.startswith(".") or name >= run_id:
            continue
        if path.is_symlink() or not path.is_dir() or not _stays_inside(runs, path):
            continue
        found.append(path)
    found.sort(key=lambda item: item.name, reverse=True)
    return found


def _contained_child(runs: Path, name: str) -> Path | None:
    if not name or name.startswith(".") or "/" in name or "\\" in name:
        return None
    if runs.is_symlink() or not runs.is_dir():
        return None
    path = runs / name
    if path.is_symlink() or not path.is_dir() or not _stays_inside(runs, path):
        return None
    return path


def _stays_inside(root: Path, path: Path) -> bool:
    try:
        resolved = path.resolve()
        parent = root.resolve()
    except OSError:
        return False
    return parent == resolved or parent in resolved.parents


def _stored_target_names(directory: Path) -> frozenset[str]:
    names: list[str] = []
    snapshot = _yaml_target_names(directory)
    if snapshot is not None:
        names.extend(snapshot)
    benchmark = _loose_object(directory / "benchmark.json")
    controls = benchmark.get("controls") if benchmark is not None else None
    if isinstance(controls, list):
        for item in controls:
            if not isinstance(item, dict):
                continue
            target = item.get("target")
            if isinstance(target, str) and target and target not in names:
                names.append(target)
    for item in _object_list(directory / "findings.json"):
        target = item.get("target")
        if isinstance(target, str) and target and target not in names:
            names.append(target)
    return frozenset(names)


def _yaml_target_names(directory: Path) -> tuple[str, ...] | None:
    path = directory / "insidia.yaml"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    if not isinstance(loaded, dict):
        return None
    targets = loaded.get("targets")
    if not isinstance(targets, dict):
        return ()
    return tuple(key for key in targets if isinstance(key, str) and key)


def _loose_object(path: Path) -> dict[str, object] | None:
    loaded = _loose_json(path)
    if not isinstance(loaded, dict):
        return None
    return cast(dict[str, object], loaded)


def _object_list(path: Path) -> list[dict[str, object]]:
    loaded = _loose_json(path)
    if not isinstance(loaded, list):
        return []
    return [cast(dict[str, object], item) for item in loaded if isinstance(item, dict)]


def _loose_json(path: Path) -> object | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


_CSV_COLUMNS = (
    "check_id",
    "title",
    "severity",
    "risk_score",
    "target",
    "target_kind",
    "endpoint",
    "cve",
    "taxonomy",
    "synopsis",
    "solution",
    "evidence",
    "evidence_hash",
    "engines",
    "run_id",
)
_CSV_EVIDENCE_CAP = 500
_CSV_TRIM_NOTE = " truncated to 500 characters"
_CSV_FORMULA = ("=", "+", "-", "@")


def _findings_csv(
    findings: list[Finding],
    run_id: str,
    targets: tuple[tuple[str, str, str], ...],
) -> str:
    """One header, then one row per finding. Cells are masked and formula-safe."""
    kinds = {name: kind for name, kind, _endpoint in targets}
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for finding in findings:
        writer.writerow(
            [
                _csv_cell(finding.check_id),
                _csv_cell(finding.title),
                _csv_cell(finding.severity),
                _csv_cell(json.dumps(finding.risk_score)),
                _csv_cell(finding.target),
                _csv_cell(kinds.get(finding.target, "")),
                _csv_cell(finding.endpoint or finding.location),
                _csv_cell("; ".join(finding.cve)),
                _csv_cell("; ".join(finding.taxonomy)),
                _csv_cell(finding.synopsis),
                _csv_cell(finding.remediation),
                _csv_evidence(finding),
                _csv_cell(finding.evidence_hash),
                _csv_cell("; ".join(finding.engines)),
                _csv_cell(run_id),
            ]
        )
    return buffer.getvalue()


def _finding_evidence(finding: Finding) -> str:
    """Observation evidence, or the response when no observation stored any."""
    parts = [item.evidence for item in finding.observations if item.evidence]
    if parts:
        return "\n".join(parts)
    return finding.response


def _csv_evidence(finding: Finding) -> str:
    """Mask evidence, then keep at most 500 characters."""
    text = mask(_finding_evidence(finding))
    if len(text) > _CSV_EVIDENCE_CAP:
        text = text[:_CSV_EVIDENCE_CAP] + _CSV_TRIM_NOTE
    return _formula_safe(text)


def _csv_cell(value: str) -> str:
    return _formula_safe(mask(value))


def _formula_safe(value: str) -> str:
    """A leading spreadsheet formula is text. Applied after masking and trimming."""
    if value.startswith(_CSV_FORMULA):
        return f"'{value}"
    return value


def not_tested(controls: list[dict[str, str | int]]) -> int:
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
            f"Scan cancelled. Policy {policy} has no verdict. {findings} {label} before it stopped."
        )
    if execution_status != "complete":
        if verdict == "fail":
            return f"The scan did not finish. Policy {policy} did not pass. {findings} {label}."
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


def _brand_lockup(variant: str) -> str:
    """Embed the approved outlined logo, with document-unique SVG identifiers."""
    svg = (Path(__file__).resolve().parent / "brand" / f"lockup-{variant}.svg").read_text()
    for identifier in re.findall(r'\bid="([^"]+)"', svg):
        qualified = f"report-logo-{variant}-{identifier}"
        svg = svg.replace(f'id="{identifier}"', f'id="{qualified}"')
        svg = svg.replace(f"url(#{identifier})", f"url(#{qualified})")
        svg = svg.replace(f'href="#{identifier}"', f'href="#{qualified}"')
    svg = svg.replace("<svg ", '<svg aria-hidden="true" focusable="false" ', 1)
    return (
        f'<span class="report-logo report-logo-{variant}" role="img" '
        f'aria-label="Insidia Labs">{svg.strip()}</span>'
    )


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
        loaded = json.loads(path.read_text(encoding="utf-8"))
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


def _passed_text(passed: int, low: int) -> str:
    """How many passes, and how many of those have assurance low."""
    return f"{passed} passed ({low} low assurance)"


def _score_rows(scores: tuple[Score, ...]) -> str:
    lines = []
    for score in scores:
        lines.append(
            "<tr>"
            f'<td data-l="Framework">{_escape(score.title)}</td>'
            f'<td class="number count-fail" data-l="Failed">{score.failed}</td>'
            f'<td class="number count-pass" data-l="Passed">'
            f"{_escape(_passed_text(score.passed, score.low_assurance))}</td>"
            f'<td class="number count-nt" data-l="Not tested">{score.not_tested}</td>'
            "</tr>"
        )
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


@dataclass(frozen=True)
class _ReportData:
    run_id: str
    policy: str
    passed: bool
    findings: list[Finding]
    controls: list[dict[str, str | int]]
    skips: list[str]
    scores: tuple[Score, ...]
    targets: tuple[tuple[str, str, str], ...]
    started_at: str
    finished_at: str
    duration_s: float
    version: str
    execution_status: str
    verdict: str
    coverage_name: str
    scope_hosts: tuple[str, ...]
    config_digest: str
    judge: str
    rate_limits: list[dict[str, object]]
    engines: tuple[str, ...]
    artefacts: tuple[tuple[str, str], ...]
    baseline_id: str = ""
    fixed: tuple[_FixedFinding, ...] = ()
    new_count: int = 0
    still_open_count: int = 0
    fixed_count: int = 0


def _render(report: _ReportData) -> str:
    names = _target_names(report.findings, report.controls, report.targets)
    title = "Security scan report" + (f": {', '.join(names)}" if names else "")
    parts = (
        _report_head(report, title),
        _report_navigation(len(report.findings)),
        '<main id="main" tabindex="-1">',
        _report_pages(report, names),
        "</main>",
        _report_footer(report.run_id),
        f"<script data-report-ui>{REPORT_SCRIPT}</script>",
        "</body></html>",
    )
    return "\n".join(part for part in parts if part) + "\n"


def _report_pages(report: _ReportData, names: list[str]) -> str:
    pages = (
        ("summary", _report_overview(report)),
        ("findings", _report_findings(report, names)),
        (
            "remediation",
            '<h2 id="remediation">Remediation summary</h2>' + _remediation_table(report.findings),
        ),
        (
            "targets",
            '<h2 id="targets">Targets</h2>'
            + _targets_table(report.findings, report.controls, report.targets),
        ),
        (
            "coverage",
            '<h2 id="coverage">Coverage by target</h2>'
            + _coverage_by_target(report.controls, report.skips),
        ),
        ("frameworks", _report_frameworks(report.controls, report.scores)),
        ("scaninfo", _report_scan_information(report)),
    )
    sections = []
    for page, content in pages:
        hidden = "" if page == "summary" else " hidden"
        sections.append(
            f'<section class="report-page" data-page="{page}" '
            f'aria-labelledby="{page}"{hidden}>{content}</section>'
        )
    fallback = (
        "<noscript><style>.report-page[hidden] { display: block; }</style>"
        '<p class="note">JavaScript is disabled. '
        'All report sections are shown below.</p></noscript>'
    )
    return fallback + "\n".join(sections)


def _report_head(report: _ReportData, title: str) -> str:
    return "\n".join(
        (
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_escape(title)}</title><style>{_CSS}</style></head><body>",
            '<a class="skip-link" href="#main">Skip to report</a>',
            "<header>",
            _brand_lockup("dark"),
            _brand_lockup("light"),
            '<div class="report-heading">',
            f"<h1>{_escape(title)}</h1>",
            report_identity(
                report.run_id, report.started_at, report.policy, report.version, report.engines
            ),
            "</div></header>",
        )
    )


def _report_navigation(findings: int) -> str:
    pages = (
        ("summary", "Overview"),
        ("findings", f"Findings ({findings})"),
        ("remediation", "Remediation"),
        ("targets", "Targets"),
        ("coverage", "Coverage"),
        ("frameworks", "Frameworks"),
        ("scaninfo", "Scan info"),
    )
    links = []
    for page, label in pages:
        current = ' aria-current="page"' if page == "summary" else ""
        links.append(f'<a href="?page={page}" data-page-link="{page}"{current}>{label}</a>')
    return '<nav aria-label="Report sections">' + "".join(links) + "</nav>"


def _report_overview(report: _ReportData) -> str:
    counts = check_counts(report.controls)
    status = "pass" if report.passed else "fail"
    summary = _executive_summary(
        run_id=report.run_id,
        policy=report.policy,
        findings=report.findings,
        controls=report.controls,
        targets=report.targets,
        execution_status=report.execution_status,
        verdict=report.verdict,
        baseline_id=report.baseline_id,
        new_count=report.new_count,
        still_open_count=report.still_open_count,
        fixed_count=report.fixed_count,
    )
    return "\n".join(
        (
            '<h2 id="summary">Executive summary</h2>',
            verdict_strip(report.execution_status, report.policy, report.verdict, counts),
            summary_metrics(counts, len(report.findings)),
            '<div class="charts-grid">',
            tested_chart(counts),
            outcomes_chart(counts),
            "</div>",
            '<details class="summary-detail"><summary>Scan summary and limitations</summary>',
            f'<p class="status {status}">{_escape(summary)}</p></details>',
        )
    )


def _report_findings(report: _ReportData, names: list[str]) -> str:
    return "\n".join(
        (
            '<h2 id="findings">Findings by severity</h2>',
            severity_chart([finding.severity for finding in report.findings]),
            _finding_cards(report.findings, report.run_id, names),
            _fixed_section(report.baseline_id, report.fixed),
        )
    )


def _report_frameworks(controls: list[dict[str, str | int]], scores: tuple[Score, ...]) -> str:
    counts = CheckCounts(
        sum(s.passed for s in scores),
        sum(s.failed for s in scores),
        0,
        sum(s.not_tested for s in scores),
    )
    return "\n".join(
        (
            '<h2 id="frameworks">Framework coverage</h2>',
            '<p class="note">Counts below are mapped framework items, not individual checks. '
            "An item can contain multiple checks. This is coverage, not a security rating.</p>",
            framework_chart(scores),
            '<table class="framework-scores">',
            "<thead><tr><th>Framework</th><th>Failed</th>"
            "<th>Passed</th><th>Not tested</th></tr></thead>",
            f"<tbody>\n{_score_rows(scores)}\n</tbody></table>",
            "<details><summary>OWASP item list</summary>",
            '<p class="note">Not tested means no passing or failing check mapped to this item. '
            "See Coverage by target for recorded check limitations.</p>",
            coverage_filter(
                framework_groups(controls, scores),
                counts,
                prefix="framework-filter",
                unit="framework items",
            ),
            "</details>",
        )
    )


def _report_scan_information(report: _ReportData) -> str:
    return '<h2 id="scaninfo">Scan information</h2>\n' + _scan_table(
        report.run_id,
        report.started_at,
        report.finished_at,
        report.duration_s,
        report.version,
        report.policy,
        report.coverage_name,
        report.execution_status,
        report.verdict,
        report.scope_hosts,
        report.skips,
        report.config_digest,
        report.judge,
        report.rate_limits,
        report.engines,
        report.artefacts,
    )


def _report_footer(run_id: str) -> str:
    return (
        '<footer><p>Artefacts: findings.json, <a href="findings.csv">findings.csv</a>, '
        "results.sarif, benchmark.json, manifest.json, report.html</p>"
        f"<p><code>insidia rerun {_escape(run_id)}</code></p></footer>"
    )


def _target_names(
    findings: list[Finding],
    controls: list[dict[str, str | int]],
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


def _executive_summary(
    *,
    run_id: str,
    policy: str,
    findings: list[Finding],
    controls: list[dict[str, str | int]],
    targets: tuple[tuple[str, str, str], ...],
    execution_status: str,
    verdict: str,
    baseline_id: str = "",
    new_count: int = 0,
    still_open_count: int = 0,
    fixed_count: int = 0,
) -> str:
    """Fail, pass, and incomplete summaries share one shape and one ending."""

    names = _target_names(findings, controls, targets)
    counts = check_counts(controls)
    noun = "target" if len(names) == 1 else "targets"
    target_clause = f"{len(names)} {noun}" + (f" ({', '.join(names)})" if names else "")
    sentences = [
        f"Insidia ran {counts.tested} of {counts.total} checks against {target_clause}.",
        _summary_outcome(policy, verdict, execution_status, findings),
        _summary_serious_finding(findings),
        _summary_assurance(counts),
    ]
    if execution_status != "complete":
        sentences.extend(
            (
                f"Results below cover {counts.tested} checks only.",
                f"Re-run with `insidia rerun {run_id}`.",
            )
        )
    if baseline_id:
        sentences.append(
            f"{new_count} new, {still_open_count} still open, and {fixed_count} fixed "
            f"since {mask(baseline_id)}."
        )
    sentences.append("This report is test evidence, not a certification.")
    return " ".join(sentences)


def _summary_outcome(policy: str, verdict: str, execution: str, findings: list[Finding]) -> str:
    counts = {bucket: 0 for bucket in _BUCKETS}
    for finding in findings:
        counts[_bucket(finding.severity)] += 1
    severity_counts = ", ".join(
        f"{counts[bucket]} {_BUCKET_LABEL[bucket].lower()}" for bucket in _BUCKETS
    )
    outcome = {"pass": "passed", "fail": "did not pass"}.get(verdict, "is inconclusive")
    noun = "finding" if len(findings) == 1 else "findings"
    sentence = f"Policy {policy} {outcome}: {len(findings)} {noun} ({severity_counts})."
    return (
        sentence if execution == "complete" else f"The scan did not finish: {execution}. {sentence}"
    )


def _summary_serious_finding(findings: list[Finding]) -> str:
    if not findings:
        return "The most serious finding is none."
    top = findings[0]
    return (
        f"The most serious finding is {top.title or top.attack}, severity {top.severity}, "
        f"score {top.risk_score:.1f}, target {top.target}."
    )


def _summary_assurance(counts: CheckCounts) -> str:
    weak = (
        "1 passed check has low assurance"
        if counts.low_assurance == 1
        else f"{counts.low_assurance} passed checks have low assurance"
    )
    untested = (
        "1 check was not tested"
        if counts.untested == 1
        else f"{counts.untested} checks were not tested"
    )
    return (
        f"{weak} and {untested}. "
        "Checks that were not tested are not evidence that those risks are absent."
    )


def _fixed_section(baseline_id: str, fixed: tuple[_FixedFinding, ...]) -> str:
    """Baseline findings whose evidence hash is absent. Evidence text is not printed."""
    if not baseline_id:
        return ""
    rows = []
    for item in fixed:
        title = _escape(mask(item.title))
        target = _escape(mask(item.target))
        fingerprint = _escape(mask(item.evidence_hash))
        rows.append(f"<li>{title} · {target} · <code>{fingerprint}</code></li>")
    body = "<ul>" + "".join(rows) + "</ul>"
    heading = _escape(mask(baseline_id))
    return f'<h2 id="fixed">Fixed since {heading}</h2>\n{body}'


def _targets_table(
    findings: list[Finding],
    controls: list[dict[str, str | int]],
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
        low = 0
        for control in controls:
            if control.get("target") != name:
                continue
            result = control.get("result", "")
            if result in tallies:
                tallies[result] += 1
            if result == "pass" and control.get("assurance") == "low":
                low += 1
        chips = "".join(
            f'<td data-l="{_BUCKET_LABEL[bucket]}">{counts[bucket]}</td>' for bucket in _BUCKETS
        )
        summary = (
            f"{tallies['fail']} fail · {_passed_text(tallies['pass'], low)} · "
            f"{tallies['not tested']} not tested"
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
    return f'<table class="targets"><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table>'


# A check with three or fewer hits stays a flat card. More than three share one header.
_GROUP_AFTER = 3
_PACKAGE_PIN = re.compile(
    r"(?<![A-Za-z0-9_])(@?[A-Za-z0-9_][\w.-]{0,60}==[A-Za-z0-9][\w.+-]{0,40})"
)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


def _finding_cards(findings: list[Finding], run_id: str, target_names: list[str]) -> str:
    """Cards for each hit. A busy check collapses, and two targets can be filtered."""
    if not findings:
        return (
            '<div class="empty-findings"><strong>No findings detected '
            "in the checks performed.</strong>"
            "<p>Review untested checks and coverage limitations "
            "before interpreting this result.</p>"
            '<a href="?page=coverage">Review check coverage →</a></div>'
        )
    names = list(target_names)
    for finding in findings:
        if finding.target and finding.target not in names:
            names.append(finding.target)
    tokens = {name: f"t{index}" for index, name in enumerate(names)} if len(names) >= 2 else {}
    cards = _render_finding_cards(findings, run_id, tokens)
    if not tokens:
        return "\n".join(cards)
    return _by_target_filter(cards, names)


def _render_finding_cards(
    findings: list[Finding], run_id: str, tokens: dict[str, str]
) -> list[str]:
    buckets: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        key = _check_key(finding)
        if key not in buckets:
            order.append(key)
            buckets[key] = []
        buckets[key].append(finding)
    cards: list[str] = []
    index = 0
    for key in order:
        items = buckets[key]
        if len(items) > _GROUP_AFTER:
            cards.append(_grouped_finding_card(items, index, run_id, tokens))
            index += 1
            continue
        for finding in items:
            cards.append(_finding_card(finding, index, run_id, tokens.get(finding.target, "")))
            index += 1
    return cards


def _check_key(finding: Finding) -> str:
    return finding.check_id or finding.probe or finding.attack


def _finding_card(finding: Finding, index: int, run_id: str, token: str = "") -> str:
    bucket = _bucket(finding.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    opened = " open" if index < 2 else ""
    title = finding.title or finding.attack
    check = _check_key(finding)
    target_attr = f' data-target="{token}"' if token else ""
    right = f"{finding.target} · {label} {finding.risk_score:.1f}"
    return (
        f'<details class="finding"{target_attr}{opened}>'
        f"{_finding_summary(css, check, title, right, finding.engine)}"
        f"<dl>{_finding_body(finding, run_id)}</dl></details>"
    )


def _grouped_finding_card(
    items: list[Finding], index: int, run_id: str, tokens: dict[str, str]
) -> str:
    """One header for a check, then every hit's file, package, and CVE."""
    worst = items[0]
    bucket = _bucket(worst.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
    opened = " open" if index < 2 else ""
    title = worst.title or worst.attack
    check = _check_key(worst)
    targets = list(dict.fromkeys(item.target for item in items if item.target))
    if len(targets) == 1:
        where = targets[0]
        token = tokens.get(where, "")
        target_attr = f' data-target="{token}"' if token else ""
    else:
        where = f"{len(targets)} targets" if targets else (worst.target or "unspecified")
        target_attr = ""
    noun = "location" if len(items) == 1 else "locations"
    right = f"{where} · {len(items)} {noun} · {label} {worst.risk_score:.1f}"
    show_target = bool(tokens)
    rows = "".join(
        _location_row(item, tokens.get(item.target, ""), show_target=show_target) for item in items
    )
    return (
        f'<details class="finding"{target_attr}{opened}>'
        f"{_finding_summary(css, check, title, right, worst.engine)}"
        f'<ul class="locations">{rows}</ul>'
        f"<dl>{_finding_body(worst, run_id)}</dl></details>"
    )


def _finding_summary(css: str, check: str, title: str, right: str, engine: str) -> str:
    return (
        f'<summary class="bar bar-{css}">'
        f'<span class="sev sev-{css}">{css.upper()}</span>'
        f'<span class="pid">{_escape(check)}</span> {_escape(title)}'
        f'<span class="finding-engine">Engine: {_escape(engine)}</span>'
        f'<span class="right">{_escape(right)}</span>'
        f"</summary>"
    )


def _finding_body(finding: Finding, run_id: str) -> str:
    bucket = _bucket(finding.severity)
    css = _BUCKET_CLASS[bucket]
    label = _BUCKET_LABEL[bucket].upper()
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
    return "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in fields)


def _location_row(finding: Finding, token: str, *, show_target: bool) -> str:
    attr = f' data-target="{token}"' if token else ""
    return f'<li class="loc"{attr}>{_location_html(finding, show_target=show_target)}</li>'


def _location_html(finding: Finding, *, show_target: bool) -> str:
    file_line = _file_line_text(finding.location)
    pins = _package_pins(finding)
    cves = _cve_ids(finding)
    chunks: list[str] = []
    if show_target and finding.target:
        chunks.append(_escape(finding.target))
    if file_line:
        chunks.append(f"<code>{_escape(file_line)}</code>")
    chunks.extend(f"<code>{_escape(pin)}</code>" for pin in pins)
    chunks.extend(_escape(cve) for cve in cves)
    if not file_line and not pins and not cves:
        fallback = finding.endpoint or finding.location
        if fallback:
            chunks.append(f"<code>{_escape(fallback)}</code>")
        elif not chunks:
            chunks.append(_escape(finding.target or "unspecified"))
    return " · ".join(chunks)


def _file_line_text(location: str) -> str:
    if not location or "://" in location or "==" in location:
        return ""
    path, separator, line = location.rpartition(":")
    if separator and line.isdigit() and path:
        return f"{path}:{line}"
    return ""


def _package_pins(finding: Finding) -> list[str]:
    found: list[str] = []
    for pin in _PACKAGE_PIN.findall(_location_source(finding)):
        if pin not in found:
            found.append(pin)
    return found


def _cve_ids(finding: Finding) -> list[str]:
    if finding.cve:
        return list(dict.fromkeys(finding.cve))
    found: list[str] = []
    for cve in _CVE_ID.findall(_location_source(finding)):
        if cve not in found:
            found.append(cve)
    return found


def _location_source(finding: Finding) -> str:
    parts = [finding.location, finding.response]
    parts.extend(item.evidence for item in finding.observations)
    return "\n".join(parts)


def _by_target_filter(cards: list[str], names: list[str]) -> str:
    """All targets stays selected. Choosing a target hides the other findings."""
    controls = [
        '<input type="radio" name="by-target" id="flt-all" checked>',
        '<label for="flt-all">All targets</label>',
    ]
    rules: list[str] = []
    for index, name in enumerate(names):
        token = f"t{index}"
        controls.append(f'<input type="radio" name="by-target" id="flt-{index}">')
        controls.append(f'<label for="flt-{index}">{_escape(name)}</label>')
        rules.append(
            f"#flt-{index}:checked ~ .finding"
            f':not([data-target="{token}"]):not(:has([data-target="{token}"]))'
            "{display:none}"
        )
        rules.append(
            f'#flt-{index}:checked ~ .finding .loc:not([data-target="{token}"]){{display:none}}'
        )
    style = "<style>" + " ".join(rules) + "</style>"
    return '<div class="by-target">' + "".join(controls) + style + "\n".join(cards) + "</div>"


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
        return '<p class="note">No remediation actions were recorded for this run.</p>'
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


def _coverage_by_target(controls: list[dict[str, str | int]], skips: list[str]) -> str:
    if not controls:
        return '<p class="note">No checks were recorded.</p>'
    by_target: dict[str, list[dict[str, str | int]]] = {}
    for control in controls:
        by_target.setdefault(str(control.get("target", "")), []).append(control)
    content = "\n".join(_coverage_target(name, rows, skips) for name, rows in by_target.items())
    return coverage_filter(content, check_counts(controls), prefix="check-filter", unit="checks")


def _coverage_target(name: str, controls: list[dict[str, str | int]], skips: list[str]) -> str:
    counts = check_counts(controls)
    body = "".join(_coverage_check_row(control, skips) for control in controls)
    return (
        f"<h3>{_escape(name or 'Unspecified target')}</h3>"
        f'<p class="note">{_passed_text(counts.passed, counts.low_assurance)}</p>'
        '<table class="coverage"><thead><tr><th>Check</th><th>Result</th><th>Why</th>'
        f"</tr></thead><tbody>{body}</tbody></table>"
    )


def _coverage_check_row(control: dict[str, str | int], skips: list[str]) -> str:
    result = _control_text(control, "result")
    if result == "pass" and _control_text(control, "assurance") == "low":
        result = "pass (low assurance)"
    badge = status_badge(result, uppercase=True)
    why = _coverage_why(control, skips)
    outcome = _control_outcome(control)
    explanation = untested_reason(why) if outcome == "not tested" else _escape(why)
    return (
        f'<tr class="coverage-row" data-result="{outcome}">'
        f'<td data-l="Check"><code>{_escape(str(control.get("id", "")))}</code></td>'
        f'<td data-l="Result">{badge}</td><td data-l="Why">{explanation}</td></tr>'
    )


def _control_outcome(control: dict[str, str | int]) -> str:
    result = _control_text(control, "result")
    return result if result in {"pass", "fail", "info"} else "not tested"


# Same cause, so the same sentence. Different causes must not share this text.
_JUDGE_WHY = {
    "ai.harmful_content_policy": "needs a judge model: `models: {}`",
    "ai.bias": "needs a judge model: `models: {}`",
    "ai.citation_groundedness": "needs a judge model: `models: {}`",
}


def _control_text(control: dict[str, str | int], key: str) -> str:
    value = control.get(key, "")
    return value if isinstance(value, str) else ""


def _sent_clause(control: dict[str, str | int]) -> str:
    value = control.get("probes", 0)
    count = value if isinstance(value, int) else 0
    if count <= 0:
        return ""
    noun = "prompt" if _control_text(control, "id").startswith("ai.") else "payload"
    if count != 1:
        noun += "s"
    return f"{count} {noun} sent"


def _coverage_why(control: dict[str, str | int], skips: list[str]) -> str:
    reason = ""
    if _control_text(control, "assurance") == "low":
        reason = _control_text(control, "assurance_reason").strip()
    detail = _control_text(control, "detail").strip()
    result = _control_text(control, "result")
    # Low assurance stays a pass. A non-pass keeps the reason and gains no sent clause.
    if reason and result != "pass":
        return reason
    if result in {"pass", "fail"} and "probes" in control:
        sent = _sent_clause(control)
        if result == "pass" and reason:
            if sent:
                return f"{sent}, none triggered. {reason}"
            return reason
        if sent and detail:
            return f"{sent}. {detail}"
        if detail:
            return detail
        if result == "pass":
            if sent:
                return f"{sent}, none triggered."
            return "none triggered."
        if sent:
            return f"{sent}. A probe reported this check."
        return "A probe reported this check."
    if reason:
        return reason
    if detail:
        return detail
    family = _control_text(control, "id")
    target = _control_text(control, "target")
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


def _engine_names(findings: list[Finding], engines: tuple[str, ...] | None) -> list[str]:
    """Engines the scan recorded. Without that list, use engines that produced findings."""
    if engines is None:
        names: list[str] = []
        for finding in findings:
            for name in finding.engines or (finding.engine,):
                if name and name not in names:
                    names.append(name)
        names.sort()
        return names
    return sorted({name for name in engines if name})


def _limit_rows(rate_limits: tuple[tuple[str, float, int], ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for name, rps, concurrency in rate_limits:
        shown: int | float = int(rps) if float(rps).is_integer() else rps
        rows.append({"target": name, "rps": shown, "concurrency": concurrency})
    return rows


def _rate_limits_text(rate_limits: list[dict[str, object]]) -> str:
    if not rate_limits:
        return "none"
    parts: list[str] = []
    for row in rate_limits:
        parts.append(f"{row['target']}: {row['rps']} rps, concurrency {row['concurrency']}")
    return "; ".join(parts)


def _skips_text(skips: list[str]) -> str:
    count = len(skips)
    if count == 0:
        return "0"
    return f"{count}: {'; '.join(skips)}"


def _artefacts_text(artefacts: tuple[tuple[str, str], ...]) -> str:
    return ", ".join(f"{name} {digest}" for name, digest in artefacts)


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
    skips: list[str],
    config_digest: str,
    judge: str,
    rate_limits: list[dict[str, object]],
    engines: tuple[str, ...],
    artefacts: tuple[tuple[str, str], ...],
) -> str:
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
        ("models/judge", judge),
        ("Rate limits", _rate_limits_text(rate_limits)),
        ("Engines", ", ".join(engines)),
        ("Skips", _skips_text(skips)),
        ("Config digest", config_digest),
        ("Artefacts", _artefacts_text(artefacts)),
    )
    body = "".join(
        f"<tr><th>{_escape(label)}</th><td>{_escape(value)}</td></tr>" for label, value in rows
    )
    return f'<table class="scan">{body}</table>'


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
        "logicalLocations": [{"kind": "endpoint", "name": target, "fullyQualifiedName": endpoint}],
    }


def _relative_endpoint_uri(target: str, endpoint: str) -> str:
    text = endpoint.strip()
    _method, separator, rest = text.partition(" ")
    url = rest if separator and "://" in rest else text
    if "://" not in url:
        return f"insidia-endpoints/{_safe_part(target)}"
    parsed = urlparse(url)
    host = _safe_part(parsed.netloc or "unknown")
    parts = [_safe_part(part) for part in parsed.path.split("/") if part not in {"", ".", ".."}]
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


def _sarif_tags(taxonomy: tuple[str, ...]) -> list[str]:
    """security, then each taxonomy id. cwe:CWE-200 is emitted as CWE-200."""
    tags = ["security"]
    for item in taxonomy:
        prefix, separator, rest = item.partition(":")
        tag = rest if separator and prefix == "cwe" and rest else item
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _sarif_help(finding: Finding) -> str:
    """Remediation, then each reference on its own line."""
    refs = [item for item in finding.references if item]
    if not finding.remediation:
        return "\n".join(refs)
    if not refs:
        return finding.remediation
    return f"{finding.remediation}\n\n" + "\n".join(refs)


def _sarif_rule(finding: Finding) -> dict[str, object]:
    help_text = _sarif_help(finding)
    rule: dict[str, object] = {
        "id": finding.probe,
        "name": finding.attack,
        "shortDescription": {"text": finding.title or finding.attack},
        "fullDescription": {"text": finding.synopsis or finding.description or finding.remediation},
        "help": {"text": help_text, "markdown": help_text},
        "properties": {
            "security-severity": f"{finding.risk_score:.1f}",
            "tags": _sarif_tags(finding.taxonomy),
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _banner_warning(control: dict[str, str | int]) -> str:
    """The low-confidence banner note, when this control is that case."""
    result = _control_text(control, "result")
    if result == "info":
        text = _control_text(control, "detail").strip()
    elif result == "pass" and control.get("assurance") == "low":
        text = _control_text(control, "assurance_reason").strip()
        if not text:
            text = _control_text(control, "detail").strip()
    else:
        return ""
    if "not a vulnerability assessment" not in text or "low confidence" not in text:
        return ""
    return text


def _sarif_message(finding: Finding) -> str:
    """Name the finding and show masked evidence. A raw secret never reaches SARIF."""
    title = finding.title or finding.attack
    evidence = mask(finding.response).strip()
    if evidence:
        return f"{title} ({finding.target}): {evidence}"
    return f"{title} ({finding.target})"


_BANNER_RULE_ID = "insidia.infra.cve.banner"


def _sarif_banner_note(
    control: dict[str, str | int], endpoints: dict[str, str]
) -> dict[str, object] | None:
    warning = _banner_warning(control)
    if not warning:
        return None
    target_name = _control_text(control, "target") or "target"
    endpoint = endpoints.get(target_name, "") or target_name
    return {
        "ruleId": _BANNER_RULE_ID,
        "level": "note",
        "message": {"text": mask(warning)},
        "properties": {
            "engine": "insidia",
            "severity": "info",
            "confidence": "low",
            "security-severity": "0.0",
        },
        "locations": [_endpoint_location(target_name, endpoint)],
    }


def _banner_rule(warning: str) -> dict[str, object]:
    return {
        "id": _BANNER_RULE_ID,
        "name": "infra.cve",
        "shortDescription": {"text": "Banner version is not a vulnerability assessment"},
        "fullDescription": {"text": warning},
        "help": {"text": warning, "markdown": warning},
        "properties": {"security-severity": "0.0", "tags": ["security"]},
    }


def _sarif(
    findings: list[Finding],
    controls: list[dict[str, str | int]] | None = None,
    targets: tuple[tuple[str, str, str], ...] = (),
) -> dict[str, object]:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in findings:
        if finding.probe not in seen:
            seen.add(finding.probe)
            rules.append(_sarif_rule(finding))
        result: dict[str, object] = {
            "ruleId": finding.probe,
            "level": _sarif_level(finding.severity),
            "message": {"text": _sarif_message(finding)},
            "properties": {
                "engine": finding.engine,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "security-severity": f"{finding.risk_score:.1f}",
            },
        }
        result["locations"] = [_sarif_result_location(finding)]
        results.append(result)
    endpoints = {name: endpoint for name, _kind, endpoint in targets}
    for control in controls or []:
        warning = _banner_warning(control)
        note = _sarif_banner_note(control, endpoints)
        if not warning or note is None:
            continue
        rule_id = _BANNER_RULE_ID
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append(_banner_rule(mask(warning)))
        results.append(note)
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
