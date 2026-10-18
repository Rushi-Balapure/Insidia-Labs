"""A recognised banner with no built-in CVE match is info, not a pass."""

import json
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
from insidia.adapters import find
from insidia.cli import main
from insidia.config import load_project
from insidia.findings import Finding
from insidia.policy import get_policy
from insidia.probes import run
from insidia.runstore import write_run
from insidia.score import coverage

_TOKEN = "ghp_" + "A" * 36
_SAFE = re.compile(r"\bsafe\b", re.IGNORECASE)
_EXPLOIT = ("../", "%2e", "cgi-bin", "etc/passwd", "{{", "union", "pickle", "<!DOCTYPE")


def _warns(text: str) -> None:
    assert "nginx/1.25.3" in text
    assert "no match in the built-in list" in text
    assert "banner-based" in text
    assert "low confidence" in text
    assert "not a vulnerability assessment" in text
    assert _SAFE.search(text) is None
    assert _TOKEN not in text


@contextmanager
def _serve(server: str, powered_by: str = "") -> Iterator[tuple[int, list[str]]]:
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(self.path)
            raw = b"ok"
            self.send_response(200)
            self.send_header("Server", server)
            if powered_by:
                self.send_header("X-Powered-By", powered_by)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1]), seen
    finally:
        httpd.shutdown()
        httpd.server_close()


def _config(tmp_path: Path, port: int, *, placeholder: bool = False) -> Path:
    query = '    query:\n      q: "{{payload}}"\n' if placeholder else ""
    path = tmp_path / "insidia.yaml"
    path.write_text(
        f"""\
version: 1
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: web
    url: http://127.0.0.1:{port}/
    method: GET
{query}    rate_limit:
      rps: 100
      concurrency: 1
""",
        encoding="utf-8",
    )
    return path


def _scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    port: int,
    *flags: str,
    placeholder: bool = False,
    quiet: bool = True,
) -> tuple[int, Path]:
    monkeypatch.setenv("INSIDIA_TOOLCHAIN", str(tmp_path / "toolchain"))
    config = _config(tmp_path, port, placeholder=placeholder)
    command = ["scan", "--config", str(config)]
    if quiet:
        command.append("--quiet")
    command.extend(flags)
    code = main(command)
    runs = tmp_path / ".insidia" / "runs"
    latest = max(path for path in runs.iterdir() if path.is_dir() and not path.name.startswith("."))
    return code, latest


def _control(latest: Path) -> dict[str, object]:
    benchmark = json.loads((latest / "benchmark.json").read_text(encoding="utf-8"))
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    rows = [row for row in controls if isinstance(row, dict) and row.get("id") == "infra.cve"]
    assert len(rows) == 1
    return rows[0]


def test_a_banner_with_no_cve_match_is_info(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with _serve("nginx/1.25.3", _TOKEN) as (port, _seen):
        code, latest = _scan(tmp_path, monkeypatch, port, quiet=False)
    err = capsys.readouterr().err
    finished = [
        line
        for line in err.splitlines()
        if "infra.cve" in line and not line.strip().startswith(("…", "..."))
    ]
    assert len(finished) == 1
    cli = finished[0]
    assert "info" in cli
    assert "pass" not in cli
    # No other check can finish, so the info result leaves the scan inconclusive.
    assert code == 2
    benchmark = json.loads((latest / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "inconclusive"
    row = _control(latest)
    assert row["result"] == "info"
    assert row["confidence"] == "low"
    detail = str(row["detail"])
    _warns(detail)
    findings = json.loads((latest / "findings.json").read_text(encoding="utf-8"))
    assert [item for item in findings if item["attack"] == "infra.cve"] == []
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    scored = {item_id: result for item_id, _title, result in coverage(controls)}
    assert scored["owasp-web:A06"] == "not tested"
    html = (latest / "report.html").read_text(encoding="utf-8")
    cell = html.split("infra.cve", 1)[1].split("</tr>", 1)[0]
    assert "INFO" in cell
    assert "not a vulnerability assessment" in cell
    assert ">PASS<" not in cell
    sarif = json.loads((latest / "results.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert results
    assert all(item["level"] == "note" for item in results)
    message = results[0]["message"]["text"]
    _warns(message)
    assert _TOKEN not in (latest / "results.sarif").read_text(encoding="utf-8")
    assert _TOKEN not in html


def test_info_does_not_sink_a_scan_that_passed_another_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _serve("nginx/1.25.3") as (port, _seen):
        code, latest = _scan(tmp_path, monkeypatch, port, placeholder=True)
    assert code == 0
    benchmark = json.loads((latest / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "pass"
    row = _control(latest)
    assert row["result"] == "info"
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    assert any(item.get("result") == "pass" for item in controls if isinstance(item, dict))
    scored = {item_id: result for item_id, _title, result in coverage(controls)}
    assert scored["owasp-web:A06"] != "pass"


def test_accept_banner_only_records_low_assurance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with _serve("nginx/1.25.3") as (port, _seen):
        code, latest = _scan(
            tmp_path, monkeypatch, port, "--accept-banner-only", quiet=False
        )
    err = capsys.readouterr().err
    cli = next(line for line in err.splitlines() if "infra.cve" in line and "pass" in line)
    assert "pass (low assurance)" in cli
    assert cli.split()[0] not in {"✔", "+"}
    assert "insidia" in cli
    assert "not a vulnerability assessment" in cli
    assert "low confidence" in cli
    assert "1 passed (1 low assurance)" in err
    assert code == 0
    benchmark = json.loads((latest / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "pass"
    row = _control(latest)
    assert row["result"] == "pass"
    assert row["assurance"] == "low"
    _warns(str(row["assurance_reason"]))
    _warns(str(row["detail"]))
    findings = json.loads((latest / "findings.json").read_text(encoding="utf-8"))
    assert [item for item in findings if item["attack"] == "infra.cve"] == []
    controls = benchmark["controls"]
    assert isinstance(controls, list)
    scored = {item_id: result for item_id, _title, result in coverage(controls)}
    assert scored["owasp-web:A06"] == "pass (low assurance)"
    html = (latest / "report.html").read_text(encoding="utf-8")
    assert "pass (low assurance)" in html
    cell = html.split("infra.cve", 1)[1].split("</tr>", 1)[0]
    badge = cell.split('data-l="Result">', 1)[1].split("</td>", 1)[0]
    assert "PASS (low assurance)" in badge
    assert "res-low" in badge
    assert "res-pass" not in badge
    assert "not a vulnerability assessment" in cell
    sarif = json.loads((latest / "results.sarif").read_text(encoding="utf-8"))
    notes = [item for item in sarif["runs"][0]["results"] if item["level"] == "note"]
    assert notes
    assert all(item["level"] == "note" for item in notes)
    assert "low confidence" in notes[0]["message"]["text"]
    noisy = [
        item
        for item in sarif["runs"][0]["results"]
        if item["level"] in {"error", "warning"}
        and "vulnerability assessment" in item["message"]["text"]
    ]
    assert noisy == []


def test_a_matched_cve_still_fails_when_banner_only_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _serve("Apache/2.4.49 (Unix)") as (port, _seen):
        code, latest = _scan(tmp_path, monkeypatch, port, "--accept-banner-only")
    assert code == 1
    benchmark = json.loads((latest / "benchmark.json").read_text(encoding="utf-8"))
    assert benchmark["policy_verdict"] == "fail"
    row = _control(latest)
    assert row["result"] == "fail"
    assert row.get("assurance") != "low"
    findings = json.loads((latest / "findings.json").read_text(encoding="utf-8"))
    matched = [item for item in findings if item["attack"] == "infra.cve"]
    assert matched
    assert "CVE-2021-41773" in json.dumps(matched)


def test_the_banner_url_is_not_fetched_as_an_exploit(
    tmp_path: Path,
) -> None:
    with _serve("nginx/1.25.3") as (port, seen):
        config = _config(tmp_path, port)
        project = load_project(config)
        adapter, spec = find("insidia.infra.cve")
        attempt = run(
            adapter,
            spec,
            project.targets[0],
            project,
            tmp_path,
            get_policy("L1").control("infra.cve"),
        )
    assert attempt.hits == ()
    assert attempt.untested == ""
    _warns(attempt.info)
    assert len(seen) == 2
    assert {urlparse(path).path for path in seen} == {"/"}
    for path in seen:
        folded = path.lower()
        assert not any(mark.lower() in folded for mark in _EXPLOIT)


def test_a_cve_finding_and_a_banner_note_are_separate_sarif_rules(tmp_path: Path) -> None:
    finding = Finding(
        track="classic",
        engine="insidia",
        probe="insidia.infra.cve",
        severity="high",
        confidence="high",
        attack="infra.cve",
        response="Apache/2.4.49: CVE-2021-41773",
        trace_ref="old",
        taxonomy=("owasp-web:A06",),
        remediation="Remove the vulnerable server banner.",
        evidence_hash="cve",
        cross_validated=False,
        target="old",
    )
    detail = (
        "nginx/1.25.3 identified; no match in the built-in list (8 entries); "
        "banner-based, low confidence; not a vulnerability assessment"
    )
    controls = [
        {
            "id": "infra.cve",
            "target": "current",
            "result": "info",
            "detail": detail,
        }
    ]
    directory = write_run(tmp_path, "run-mixed-cve", "L1", False, [finding], controls, [])
    sarif = json.loads((directory / "results.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"insidia.infra.cve", "insidia.infra.cve.banner"}
    assert rules["insidia.infra.cve"]["shortDescription"]["text"] == "Cve"
    assert rules["insidia.infra.cve"]["properties"]["security-severity"] == "7.5"
    assert rules["insidia.infra.cve.banner"]["properties"]["security-severity"] == "0.0"
    results = {item["ruleId"]: item for item in run["results"]}
    assert set(results) == {"insidia.infra.cve", "insidia.infra.cve.banner"}
    note = results["insidia.infra.cve.banner"]
    cve = results["insidia.infra.cve"]
    assert note["level"] == "note"
    assert note["properties"]["security-severity"] == "0.0"
    assert rules[note["ruleId"]]["properties"]["security-severity"] == "0.0"
    assert "not a vulnerability assessment" in note["message"]["text"]
    assert cve["properties"]["security-severity"] == "7.5"
    assert "CVE-2021-41773" in cve["message"]["text"]
    assert "Cve" in cve["message"]["text"]
