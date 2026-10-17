"""Helpers for the N2 and N4 regression cases.

Configs are the QA yaml files with the loopback port rewritten to the ephemeral
port the fixture bound. Each target's rate limit is raised to 200 requests per
second at concurrency 1 so the suite stays fast and probe order stays serial.
That does not change what a check sends. The manual wrapper (strace, audit
hook) is intentionally not reproduced: the fixture records request lines.
"""

from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml
from insidia.cli import main
from insidia.score import coverage
from insidia.ui import Event, ScanView
from tests.fixtures.regression_v6.server import RecordingServer

_CONFIGS = Path(__file__).resolve().parent / "fixtures" / "regression_v6" / "configs"
_ROW = re.compile(
    r"^\s+\S+\s+([A-Za-z0-9_.]+)\s+(pass|FAIL|not tested|incomplete|skipped)\s*(.*)$"
)
_TIME = re.compile(r"\s+\d+(?:\.\d+)?s$")
_TARGET = re.compile(r"^[A-Za-z0-9_-]+$")
_HTML_COVERAGE = re.compile(r"<tr><td>(owasp-[^<]+)</td><td>[^<]*</td><td>([^<]+)</td></tr>")

N2_FAMILIES = ("web.ssti", "web.cmdi", "web.path_lfi", "api.bola_idor")
N2_OWASP = ("owasp-api:API1", "owasp-web:A01", "owasp-web:A03")


@dataclass
class _Span:
    target: str
    family: str
    start: float
    end: float | None = None


@dataclass
class ScanRun:
    code: int
    stdout: str
    stderr: str
    run_dir: Path
    benchmark: dict[str, object]
    findings: list[dict[str, object]]
    report: str
    probes: dict[tuple[str, str], list[str]]
    rows: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)

    def control(self, target: str, family: str) -> dict[str, object]:
        controls = self.benchmark["controls"]
        if not isinstance(controls, list):
            raise AssertionError("benchmark controls is not a list")
        matches = [
            row
            for row in controls
            if isinstance(row, dict) and row.get("target") == target and row.get("id") == family
        ]
        if len(matches) != 1:
            raise AssertionError(f"expected one {target} {family} control, found {len(matches)}")
        return matches[0]

    def detail(self, target: str, family: str) -> str:
        label, text = self.rows.get((target, family), ("", ""))
        del label
        return text

    def framework(self) -> dict[str, str]:
        controls = self.benchmark["controls"]
        if not isinstance(controls, list):
            raise AssertionError("benchmark controls is not a list")
        return {item_id: result for item_id, _title, result in coverage(controls)}

    def html_framework(self) -> dict[str, str]:
        return {item_id: result for item_id, result in _HTML_COVERAGE.findall(self.report)}


def write_config(
    directory: Path,
    name: str,
    ports: dict[int, int],
    only: tuple[str, ...] | None = None,
) -> Path:
    """Copy a vendored config, point its URLs at ``ports``, and keep ``only`` targets."""
    loaded = yaml.safe_load((_CONFIGS / name).read_text())
    if not isinstance(loaded, dict):
        raise AssertionError(f"{name} is not a mapping")
    targets = loaded.get("targets")
    if not isinstance(targets, dict):
        raise AssertionError(f"{name} has no targets")
    if only is not None:
        targets = {key: targets[key] for key in only}
        loaded["targets"] = targets
    for spec in targets.values():
        if not isinstance(spec, dict) or not isinstance(spec.get("url"), str):
            raise AssertionError(f"{name} has a target without a url")
        url = spec["url"]
        for old, new in ports.items():
            url = url.replace(f"127.0.0.1:{old}", f"127.0.0.1:{new}")
        if any(f"127.0.0.1:{old}" in url for old in ports):
            raise AssertionError(f"port rewrite missed {url}")
        spec["url"] = url
        spec["rate_limit"] = {"rps": 200, "concurrency": 1}
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "insidia.yaml"
    path.write_text(yaml.safe_dump(loaded, sort_keys=False))
    return path


def run_scan(
    directory: Path,
    config: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    servers: list[RecordingServer],
) -> ScanRun:
    """Run ``insidia scan`` and collect the run dir, printed rows, and probe lines."""
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(directory / "toolchain"))
    spans: list[_Span] = []
    original = ScanView.__call__

    def wrapped(self: ScanView, event: Event) -> None:
        now = time.monotonic()
        if event.kind == "begin":
            spans.append(_Span(event.target, event.family, now))
        elif event.kind == "end":
            for span in reversed(spans):
                same = span.target == event.target and span.family == event.family
                if span.end is None and same:
                    span.end = now
                    break
        original(self, event)

    monkeypatch.setattr(ScanView, "__call__", wrapped)
    state = random.getstate()
    random.seed(64)
    try:
        code = main(
            ["scan", "--config", str(config), "--policy", "L1", "--yes", "--no-color"]
        )
    finally:
        random.setstate(state)
    captured = capsys.readouterr()
    run_dir = _latest(directory)
    benchmark = json.loads((run_dir / "benchmark.json").read_text())
    findings = json.loads((run_dir / "findings.json").read_text())
    if not isinstance(benchmark, dict) or not isinstance(findings, list):
        raise AssertionError("scan did not write benchmark.json and findings.json")
    return ScanRun(
        code,
        captured.out,
        captured.err,
        run_dir,
        benchmark,
        findings,
        (run_dir / "report.html").read_text(),
        _probes(spans, servers),
        _rows(captured.err),
    )


def reason_text(control: dict[str, object], detail: str, skips: object, family: str) -> str:
    parts = [str(control.get("reason", "")), str(control.get("detail", "")), detail]
    if isinstance(skips, list):
        parts.extend(str(skip) for skip in skips if family in str(skip))
    return " ".join(part for part in parts if part and part != "None").strip()


def assurance_of(control: dict[str, object], detail: str) -> str:
    raw = str(control.get("assurance", "")).strip().lower()
    if raw and raw != "none":
        return raw
    lowered = detail.lower()
    if "low assurance" in lowered or "assurance: low" in lowered or "assurance low" in lowered:
        return "low"
    return ""


def names_placeholder(text: str) -> bool:
    lowered = text.lower()
    return (
        "placeholder" in lowered
        or "{{payload}}" in text
        or "no payload" in lowered
        or "missing payload" in lowered
    )


def names_blind_spot(text: str) -> bool:
    lowered = text.lower()
    return any(
        phrase in lowered
        for phrase in ("you are", "phrasing", "persona", "system prompt", "article", "blind")
    )


def vacuous_problem(
    control: dict[str, object],
    detail: str,
    skips: object,
    family: str,
    *,
    allow_low_assurance: bool,
) -> str | None:
    """Error text when a no-payload check is a plain pass, or None when it is acceptable."""
    result = str(control.get("result", ""))
    reason = reason_text(control, detail, skips, family)
    assurance = assurance_of(control, detail)
    low = result == "pass" and assurance == "low" and bool(reason) and names_placeholder(reason)
    if result == "not tested" and names_placeholder(reason):
        return None
    if allow_low_assurance and low:
        return None
    if result == "pass":
        return f"{family}: expected 'not tested', got 'pass'"
    if result == "not tested":
        return (
            f"{family}: expected 'not tested' with a reason naming the missing placeholder, "
            f"got {reason!r}"
        )
    return f"{family}: expected 'not tested', got {result!r}"


def hidden_context_problem(
    control: dict[str, object], detail: str, skips: object, *, allow_low_assurance: bool
) -> str | None:
    result = str(control.get("result", ""))
    reason = reason_text(control, detail, skips, "ai.hidden_context_extraction")
    assurance = assurance_of(control, detail)
    if result == "fail":
        return None
    if allow_low_assurance and result == "pass" and assurance == "low" and names_blind_spot(reason):
        return None
    if result == "pass":
        return "ai.hidden_context_extraction: expected 'fail', got 'pass'"
    return f"ai.hidden_context_extraction: expected 'fail', got {result!r}"


def owasp_problem(rows: dict[str, str], item_id: str) -> str | None:
    result = rows.get(item_id)
    if result is None:
        return f"{item_id}: missing from framework coverage"
    if result == "pass":
        return f"{item_id}: expected not a plain pass, got 'pass'"
    return None


def finding_text(findings: list[dict[str, object]], attack: str) -> str:
    chunks: list[str] = []
    for item in findings:
        if item.get("attack") != attack:
            continue
        chunks.append(str(item.get("response", "")))
        observations = item.get("observations", [])
        if isinstance(observations, list):
            for observation in observations:
                if isinstance(observation, dict):
                    chunks.append(str(observation.get("evidence", "")))
    return "\n".join(chunks)


def _latest(directory: Path) -> Path:
    runs = directory / ".insidia" / "runs"
    names = sorted(
        path.name for path in runs.iterdir() if path.is_dir() and not path.name.startswith(".")
    )
    if not names:
        raise AssertionError("scan wrote no run directory")
    return runs / names[-1]


def _probes(
    spans: list[_Span], servers: list[RecordingServer]
) -> dict[tuple[str, str], list[str]]:
    requests = [item for server in servers for item in server.requests]
    grouped: dict[tuple[str, str], list[str]] = {}
    for span in spans:
        if span.end is None:
            continue
        grouped[(span.target, span.family)] = [
            line for stamp, line in requests if span.start <= stamp <= span.end
        ]
    return grouped


def _rows(stderr: str) -> dict[tuple[str, str], tuple[str, str]]:
    current = ""
    found: dict[tuple[str, str], tuple[str, str]] = {}
    for raw in stderr.splitlines():
        line = raw.rstrip()
        match = _ROW.match(line)
        if match and current:
            label = match.group(2).lower() if match.group(2) != "FAIL" else "fail"
            detail = _TIME.sub("", match.group(3)).strip()
            found[(current, match.group(1))] = (label, detail)
            continue
        stripped = line.strip()
        if _TARGET.fullmatch(stripped):
            current = stripped
    return found
