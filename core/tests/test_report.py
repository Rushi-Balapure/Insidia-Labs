import json
from datetime import datetime
from pathlib import Path

import pytest
from insidia.findings import Finding, Observation
from insidia.mask import mask
from insidia.policy import MARKDOWN_BEACON, get_policy
from insidia.runstore import (
    _PLUGIN_OUTPUT_CAP,
    _format_epoch,
    local_time,
    read_manifest,
    write_run,
)
from insidia.score import coverage, score_frameworks

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_report_scores_frameworks_and_names_the_engine(tmp_path: Path) -> None:
    finding = Finding(
        track="ai",
        engine="insidia",
        probe="insidia.ai.data_leakage",
        severity="high",
        confidence="high",
        attack="ai.data_leakage",
        response=mask(f"token {_SECRET} end"),
        trace_ref="chat",
        taxonomy=("owasp-llm:LLM02",),
        remediation="Stop returning secrets.",
        evidence_hash="abc",
        cross_validated=False,
        target="chat",
    )
    controls = [
        {
            "id": "ai.data_leakage",
            "target": "chat",
            "result": "fail",
            "taxonomy": "owasp-llm:LLM02",
        },
        {
            "id": "web.ssti",
            "target": "web",
            "result": "pass",
            "taxonomy": "owasp-web:A03,cwe:CWE-1336",
        },
    ]
    directory = write_run(tmp_path, "run-1", "L1", False, [finding], controls, [])
    html = (directory / "report.html").read_text()
    assert "OWASP LLM" in html
    assert "OWASP Web" in html
    assert _score_line(html, "OWASP LLM Top 10") == ("1", "0 passed (0 low assurance)", "9")
    assert _score_line(html, "OWASP Web Top 10") == ("0", "1 passed (0 low assurance)", "9")
    assert "<script" not in html
    assert "prefers-color-scheme: dark" in html
    assert "#101028" in html
    assert html.split('<p class="status', 1)[1].split("</p>", 1)[0].endswith(
        "This report is test evidence, not a certification."
    )
    assert "<svg" in html
    assert "owasp-llm:LLM01" in html
    assert "not tested" in html
    assert "owasp-llm:LLM06" in html
    assert "Stop returning secrets." in html
    assert "insidia rerun run-1" in html
    assert _SECRET not in html
    assert "AKIA" not in html
    benchmark = json.loads((directory / "benchmark.json").read_text())
    assert benchmark["scores"] == [
        {
            "framework": "owasp-llm",
            "title": "OWASP LLM Top 10",
            "failed": 1,
            "passed": 0,
            "not_tested": 9,
            "low_assurance": 0,
        },
        {
            "framework": "owasp-asi",
            "title": "OWASP Agentic Top 10",
            "failed": 0,
            "passed": 0,
            "not_tested": 10,
            "low_assurance": 0,
        },
        {
            "framework": "owasp-web",
            "title": "OWASP Web Top 10",
            "failed": 0,
            "passed": 1,
            "not_tested": 9,
            "low_assurance": 0,
        },
        {
            "framework": "owasp-api",
            "title": "OWASP API Top 10",
            "failed": 0,
            "passed": 0,
            "not_tested": 10,
            "low_assurance": 0,
        },
    ]
    sarif = json.loads((directory / "results.sarif").read_text())
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Insidia"
    assert run["results"][0]["properties"]["engine"] == "insidia"


def test_report_sections_follow_the_nessus_order(tmp_path: Path) -> None:
    import re

    chat = _bare(
        track="ai",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        response=mask(f"token {_SECRET}"),
        taxonomy=("owasp-llm:LLM02",),
        remediation="Stop returning secrets.",
        target="nova",
    )
    web = _bare(target="shop", attack="web.cmdi", probe="insidia.web.cmdi", response="uid=0")
    controls = [
        {
            "id": "ai.data_leakage",
            "target": "nova",
            "result": "fail",
            "taxonomy": "owasp-llm:LLM02",
        },
        {"id": "web.cmdi", "target": "shop", "result": "fail", "taxonomy": "owasp-web:A03"},
        {
            "id": "ai.bias",
            "target": "nova",
            "result": "not tested",
            "taxonomy": "owasp-llm:LLM01",
        },
    ]
    directory = write_run(
        tmp_path,
        "20261016T012713Z-a321e5",
        "L1",
        False,
        [chat, web],
        controls,
        ["nova: ai.bias needs a judge"],
        targets=(
            ("nova", "chat", "POST http://127.0.0.1:8100/api/v1/assistant"),
            ("shop", "web", "GET http://127.0.0.1:8090/ping"),
        ),
        started_epoch=1_700_000_000.0,
        scope_hosts=("127.0.0.1",),
    )
    html = (directory / "report.html").read_text()
    headings = re.findall(r"<h2[^>]*>([^<]+)</h2>", html)
    assert headings == [
        "Executive summary",
        "Targets",
        "Findings by severity",
        "Remediation summary",
        "Coverage by target",
        "Framework mapping",
        "Scan information",
    ]
    assert html.index("Executive summary") < html.index("Findings by severity")
    assert html.index("Findings by severity") < html.index("Coverage by target")
    assert "OWASP item list" in html
    assert html.index("Framework mapping") < html.index("OWASP item list")
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert label in html
    payload = json.loads((directory / "findings.json").read_text())
    sarif = json.loads((directory / "results.sarif").read_text())["runs"][0]["results"]
    shown = [int(item) for item in re.findall(r'class="tile t-[a-z]+"><b>(\d+)</b>', html)]
    assert sum(shown) == len(payload) == len(sarif) == 2
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["finished_at"]
    assert manifest["duration_s"] >= 0
    assert manifest["insidia_version"].startswith("insidia ")
    assert "Security scan report: nova, shop" in html
    assert "127.0.0.1" in html
    footer = html.split("<footer>", 1)[1]
    assert footer.count("insidia rerun 20261016T012713Z-a321e5") == 1


def test_manifest_started_at_is_the_scan_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started_epoch = 1_700_000_000.0
    finished_epoch = started_epoch + 5.25
    run_id = "20261016T120000Z-abc123"
    monkeypatch.setattr("insidia.runstore.time.time", lambda: finished_epoch)
    directory = write_run(
        tmp_path,
        run_id,
        "L1",
        True,
        [],
        [],
        [],
        started_epoch=started_epoch,
    )
    manifest = json.loads((directory / "manifest.json").read_text())
    html = (directory / "report.html").read_text()
    assert manifest["started_at"] == _format_epoch(started_epoch)
    assert manifest["finished_at"] == _format_epoch(finished_epoch)
    assert manifest["finished_at"] > manifest["started_at"]
    assert manifest["duration_s"] == 5.25
    assert manifest["started_at"] != local_time(run_id)
    assert manifest["started_at"] in html
    started = _wall_clock(str(manifest["started_at"]))
    finished = _wall_clock(str(manifest["finished_at"]))
    assert finished > started
    elapsed = (finished - started).total_seconds()
    assert abs(elapsed - float(manifest["duration_s"])) <= 2


def _wall_clock(stamp: str) -> datetime:
    wall, _zone = stamp.rsplit(" ", 1)
    return datetime.strptime(wall, "%Y-%m-%d %H:%M:%S")


def test_clean_run_lists_engines_and_artefact_hashes(tmp_path: Path) -> None:
    import hashlib
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from insidia.cli import main

    class _Ok(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        (tmp_path / "insidia.yaml").write_text(
            f"""\
version: 1
policy: L1
coverage: standard
scope:
  - host: 127.0.0.1
targets:
  app:
    kind: web
    url: http://127.0.0.1:{port}/
    method: GET
    query:
      q: "{{{{payload}}}}"
    rate_limit:
      rps: 100
      concurrency: 1
"""
        )
        assert main(["scan", "--config", str(tmp_path / "insidia.yaml"), "--quiet"]) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    directory = next((tmp_path / ".insidia" / "runs").iterdir())
    manifest = json.loads((directory / "manifest.json").read_text())
    benchmark = json.loads((directory / "benchmark.json").read_text())
    findings = json.loads((directory / "findings.json").read_text())
    html = (directory / "report.html").read_text()
    assert findings == []
    engines = _scan_cell(html, "Engines")
    assert engines.strip()
    assert "insidia" in engines.split(", ")
    assert engines.split(", ") == manifest["engines"]
    assert _scan_cell(html, "models/judge") == "none"
    assert manifest["models"] == {"judge": "none"}
    assert manifest["rate_limits"] == [{"target": "app", "rps": 100, "concurrency": 1}]
    assert _scan_cell(html, "Rate limits") == "app: 100 rps, concurrency 1"
    skips = manifest["skips"]
    assert skips == benchmark["skips"]
    assert isinstance(skips, list)
    skips_cell = _scan_cell(html, "Skips")
    if skips:
        assert skips_cell.startswith(f"{len(skips)}:")
        for skip in skips:
            assert skip in skips_cell
    else:
        assert skips_cell == "0"
    files = manifest["files"]
    assert isinstance(files, dict)
    shown = _artefact_cells(html)
    for name, digest in files.items():
        assert isinstance(name, str)
        assert isinstance(digest, str)
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        assert digest == actual
        if name == "report.html":
            continue
        assert shown[name] == digest
    assert set(shown) == set(files) - {"report.html"}


def test_findings_csv_masks_formula_cells_and_is_hashed(tmp_path: Path) -> None:
    import csv
    import hashlib
    import io

    token = "ghp_" + ("b" * 36)
    planted = _bare(
        check_id="INS-AI-001",
        title="Secret returned in chatbot reply",
        severity="high",
        risk_score=9.1,
        risk_factors=("reported",),
        target="nova",
        taxonomy=("owasp-llm:LLM02", "cwe:CWE-200"),
        cve=("CVE-2024-0001", "CVE-2024-0002"),
        synopsis="The reply contained a credential.",
        remediation="Stop returning secrets.",
        evidence_hash="planted-hash",
        engines=("insidia", "garak"),
        location="reply:1",
        observations=(
            Observation(
                "insidia",
                "insidia.ai.data_leakage",
                "high",
                "reply:1",
                f"={token}",
            ),
        ),
        response="ordinary reply",
    )
    ordinary_evidence = "template returned 49 " + ("x" * 500)
    ordinary = _bare(
        check_id="INS-WEB-001",
        title="Template injection",
        severity="medium",
        risk_score=5.0,
        risk_factors=("reported",),
        target="shop",
        taxonomy=("owasp-web:A03",),
        synopsis="User input was evaluated.",
        remediation="Do not evaluate user input as a template.",
        evidence_hash="ordinary-hash",
        engines=("insidia",),
        location="GET http://127.0.0.1:8090/ping",
        observations=(
            Observation(
                "insidia",
                "insidia.web.ssti",
                "medium",
                "/ping",
                ordinary_evidence,
            ),
        ),
    )
    endpoint = "POST http://127.0.0.1:8100/api/v1/assistant"
    directory = write_run(
        tmp_path,
        "run-csv",
        "L1",
        False,
        [planted, ordinary],
        [],
        [],
        targets=(("nova", "chat", endpoint),),
    )
    raw = (directory / "findings.csv").read_bytes()
    text = raw.decode()
    assert token not in text
    assert "ghp_" not in text
    rows = list(csv.reader(io.StringIO(text)))
    header = [
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
    ]
    assert rows[0] == header
    payload = json.loads((directory / "findings.json").read_text())
    assert len(rows) - 1 == len(payload) == 2
    by_id = {row[0]: row for row in rows[1:]}
    formula = by_id["INS-AI-001"]
    evidence = formula[header.index("evidence")]
    assert evidence.startswith("'=")
    assert mask(token) in evidence
    assert formula[header.index("target_kind")] == "chat"
    assert formula[header.index("endpoint")] == endpoint
    assert formula[header.index("cve")] == "CVE-2024-0001; CVE-2024-0002"
    assert formula[header.index("taxonomy")] == "owasp-llm:LLM02; cwe:CWE-200"
    assert formula[header.index("solution")] == "Stop returning secrets."
    assert formula[header.index("engines")] == "insidia; garak"
    assert formula[header.index("run_id")] == "run-csv"
    plain = by_id["INS-WEB-001"]
    plain_evidence = plain[header.index("evidence")]
    masked_ordinary = mask(ordinary_evidence)
    assert plain_evidence == masked_ordinary[:500] + " truncated to 500 characters"
    assert plain[header.index("target_kind")] == ""
    assert plain[header.index("endpoint")] == "GET http://127.0.0.1:8090/ping"
    manifest = json.loads((directory / "manifest.json").read_text())
    files = manifest["files"]
    assert isinstance(files, dict)
    assert files["findings.csv"] == hashlib.sha256(raw).hexdigest()
    report_bytes = (directory / "report.html").read_bytes()
    assert files["report.html"] == hashlib.sha256(report_bytes).hexdigest()
    footer = report_bytes.decode().split("<footer>", 1)[1]
    assert 'href="findings.csv"' in footer

    empty = write_run(tmp_path, "run-empty", "L1", True, [], [], [])
    empty_raw = (empty / "findings.csv").read_bytes()
    empty_rows = list(csv.reader(io.StringIO(empty_raw.decode())))
    assert empty_rows == [header]
    empty_files = json.loads((empty / "manifest.json").read_text())["files"]
    assert empty_files["findings.csv"] == hashlib.sha256(empty_raw).hexdigest()


def _scan_cell(html: str, label: str) -> str:
    table = html.split('<table class="scan">', 1)[1].split("</table>", 1)[0]
    needle = f"<th>{label}</th><td>"
    assert needle in table
    return table.split(needle, 1)[1].split("</td>", 1)[0]


def _artefact_cells(html: str) -> dict[str, str]:
    shown: dict[str, str] = {}
    for part in _scan_cell(html, "Artefacts").split(", "):
        name, digest = part.split(" ", 1)
        shown[name] = digest
    return shown


def test_finding_cards_list_fields_in_order_and_escape_evidence(tmp_path: Path) -> None:
    import re

    leaked = "ghp_" + ("b" * 36)
    stripe = "sk_live_" + ("c" * 20)
    response = f"see <img src=\"https://evil.example/a.png\"> {leaked} {stripe} {_SECRET}"
    finding = _bare(
        track="ai",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        response=mask(response),
        taxonomy=("owasp-llm:LLM02", "cwe:CWE-200"),
        remediation="Stop returning secrets.",
        target="nova",
        evidence_hash="abc123",
    )
    directory = write_run(tmp_path, "run-card", "L1", False, [finding], [], [])
    html = (directory / "report.html").read_text()
    card = html.split('<details class="finding"', 1)[1].split("</details>", 1)[0]
    labels = re.findall(r"<dt>([^<]+)</dt>", card)
    assert labels == [
        "Synopsis",
        "Description",
        "Solution",
        "Risk factor",
        "Insidia Risk Score",
        "References",
        "See Also",
        "Plugin output",
        "Re-run",
    ]
    assert "Insidia Risk Score" in card
    assert "CVSS" not in card.split("Insidia Risk Score", 1)[0]
    assert "<img" not in html
    assert "https://evil.example/a.png" in html
    assert leaked not in html
    assert stripe not in html
    assert _SECRET not in html
    assert "[GITHUB_TOKEN " in html
    assert "[AWS_ACCESS_KEY " in html
    assert "OWASP LLM02" in card
    assert "CWE-200" in card
    assert "genai.owasp.org" in card
    assert "insidia rerun run-card" in card


def test_finding_card_shows_confidence_for_one_and_two_engines(tmp_path: Path) -> None:
    leaked = "ghp_" + ("b" * 36)
    shared = _bare(
        track="ai",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        severity="critical",
        confidence="medium",
        response=mask(leaked),
        taxonomy=("owasp-llm:LLM02",),
        remediation="Stop returning secrets.",
        target="nova",
        engines=("insidia", "garak"),
        cross_validated=True,
        check_id="INS-AI-002",
        title="Sensitive data leaked",
        risk_score=9.1,
        risk_factors=("base 9.1",),
    )
    alone = _bare(
        probe="insidia.web.cmdi",
        attack="web.cmdi",
        severity="critical",
        confidence="high",
        response="uid=0",
        remediation="Do not pass user input to a shell.",
        target="shop",
        engines=("insidia",),
        cross_validated=False,
        check_id="INS-WEB-005",
        title="Command injection",
        risk_score=9.8,
        risk_factors=("base 9.8",),
    )
    directory = write_run(tmp_path, "run-ux6", "L1", False, [shared, alone], [], [])
    html = (directory / "report.html").read_text()
    cards = {
        card.split('class="pid">', 1)[1].split("<", 1)[0]: card.split("</details>", 1)[0]
        for card in html.split('<details class="finding"')[1:]
    }
    assert _risk_factor_text(cards["INS-AI-002"]) == (
        "CRITICAL · confidence medium · reported by 2 engines (cross-validated)"
    )
    assert _risk_factor_text(cards["INS-WEB-005"]) == (
        "CRITICAL · confidence high · reported by 1 engine (not cross-validated)"
    )
    assert leaked not in html
    assert "[GITHUB_TOKEN " in cards["INS-AI-002"]


def test_four_hits_of_one_check_group_and_two_targets_filter(tmp_path: Path) -> None:
    import re

    leaked = mask(_SECRET)
    pins = (
        (
            "shop",
            "requirements.txt:1",
            f"{leaked} Django==3.2.0 is below 4.2.11 (CVE-2024-27351)",
            ("CVE-2024-27351",),
            "medium",
        ),
        (
            "shop",
            "requirements.txt:2",
            "urllib3==2.0.0 is below 2.0.7 (CVE-2023-45803)",
            ("CVE-2023-45803",),
            "high",
        ),
        ("tree", "pkg/a.py:3", "pin", (), "high"),
        (
            "tree",
            "pkg/b.py:9",
            "lodash==4.17.4 is below 4.17.21 (CVE-2021-23337)",
            ("CVE-2021-23337",),
            "high",
        ),
    )
    grouped = [
        _bare(
            probe="insidia.deps.sca",
            attack="deps.sca",
            check_id="INS-DEP-001",
            title="Pinned dependency has a known CVE",
            target=target,
            location=location,
            response=response,
            evidence_hash=f"dep-{index}",
            cve=cves,
            confidence=confidence,
            severity="high",
            risk_score=7.2,
            risk_factors=("CVE score 7.2",),
            remediation="Upgrade the pinned dependency that has a known CVE.",
        )
        for index, (target, location, response, cves, confidence) in enumerate(pins)
    ]
    other = _bare(
        probe="insidia.web.cmdi",
        attack="web.cmdi",
        check_id="INS-WEB-005",
        title="Command injection",
        target="shop",
        severity="critical",
        confidence="high",
        response="uid=0",
        evidence_hash="cmdi",
        risk_score=9.8,
        risk_factors=("base 9.8",),
        remediation="Do not pass user input to a shell.",
    )
    directory = write_run(
        tmp_path,
        "run-r6",
        "L1",
        False,
        [*grouped, other],
        [],
        [],
        targets=(
            ("tree", "repo", "repo"),
            ("shop", "web", "GET http://127.0.0.1:8090/ping"),
        ),
    )
    html = (directory / "report.html").read_text()
    assert html.count('<details class="finding"') == 2
    assert html.count('<span class="pid">INS-DEP-001</span>') == 1
    assert 'href="#findings">Findings (5)</a>' in html
    payload = json.loads((directory / "findings.json").read_text())
    sarif = json.loads((directory / "results.sarif").read_text())["runs"][0]["results"]
    assert len(payload) == len(sarif) == 5
    group = html.split('<span class="pid">INS-DEP-001</span>', 1)[1].split("</details>", 1)[0]
    locations = group.split('<ul class="locations">', 1)[1].split("</ul>", 1)[0]
    listed = re.sub(r"<[^>]+>", "", locations)
    assert listed == (
        "shop · requirements.txt:1 · Django==3.2.0 · CVE-2024-27351"
        "shop · requirements.txt:2 · urllib3==2.0.0 · CVE-2023-45803"
        "tree · pkg/a.py:3"
        "tree · pkg/b.py:9 · lodash==4.17.4 · CVE-2021-23337"
    )
    assert "2 targets · 4 locations · HIGH 7.2" in group
    assert _risk_factor_text(group) == (
        "HIGH · confidence medium · reported by 1 engine (not cross-validated)"
    )
    assert _SECRET not in html
    assert "[AWS_ACCESS_KEY " in group
    assert 'name="by-target"' in html
    assert html.count('name="by-target"') == 3
    assert '<label for="flt-all">All targets</label>' in html
    assert '<label for="flt-0">tree</label>' in html
    assert '<label for="flt-1">shop</label>' in html
    assert '#flt-0:checked ~ .finding:not([data-target="t0"])' in html
    assert '#flt-1:checked ~ .finding .loc:not([data-target="t1"])' in html
    cards = {
        card.split('class="pid">', 1)[1].split("<", 1)[0]: card
        for card in html.split('<details class="finding"')[1:]
    }
    assert _risk_factor_text(cards["INS-WEB-005"]) == (
        "CRITICAL · confidence high · reported by 1 engine (not cross-validated)"
    )


def test_three_hits_of_one_check_stay_separate_cards(tmp_path: Path) -> None:
    findings = [
        _bare(
            probe="insidia.code.secrets",
            attack="code.secrets",
            check_id="INS-CODE-001",
            title="Live-format secret in the repository",
            target="tree",
            location=f"pkg/a.py:{line}",
            evidence_hash=f"sec-{line}",
            risk_score=9.1,
            risk_factors=("live-format credential floor 9.1",),
        )
        for line in (1, 2, 3)
    ]
    directory = write_run(tmp_path, "run-r6-flat", "L1", False, findings, [], [])
    html = (directory / "report.html").read_text()
    assert html.count('<details class="finding"') == 3
    assert html.count('<span class="pid">INS-CODE-001</span>') == 3
    assert '<ul class="locations">' not in html
    assert 'name="by-target"' not in html


def test_sarif_result_properties_include_confidence(tmp_path: Path) -> None:
    high = _bare(confidence="high", probe="insidia.web.cmdi", attack="web.cmdi")
    medium = _bare(
        confidence="medium",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        target="nova",
        track="ai",
    )
    directory = write_run(tmp_path, "run-conf", "L1", False, [high, medium], [], [])
    results = json.loads((directory / "results.sarif").read_text())["runs"][0]["results"]
    by_rule = {item["ruleId"]: item["properties"] for item in results}
    assert by_rule["insidia.web.cmdi"]["confidence"] == "high"
    assert by_rule["insidia.ai.data_leakage"]["confidence"] == "medium"
    assert "shortDescription" not in by_rule["insidia.web.cmdi"]


def test_sarif_rules_describe_the_finding_and_mask_the_message(tmp_path: Path) -> None:
    token = "ghp_" + ("b" * 36)
    reference = "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"
    finding = _bare(
        track="ai",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        confidence="high",
        response=token,
        taxonomy=("owasp-llm:LLM02", "cwe:CWE-200"),
        remediation="Stop returning secrets.",
        target="nova",
    )
    directory = write_run(tmp_path, "run-sarif", "L1", False, [finding], [], [])
    sarif_text = (directory / "results.sarif").read_text()
    sarif = json.loads(sarif_text)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "Secret returned in chatbot reply"
    assert rule["fullDescription"]["text"] == (
        "The chatbot returned a credential-shaped secret in its reply."
    )
    assert rule["help"]["text"] == rule["help"]["markdown"]
    assert rule["help"]["text"] == f"Stop returning secrets.\n\n{reference}"
    assert rule["helpUri"] == reference
    assert rule["properties"]["tags"] == ["security", "owasp-llm:LLM02", "CWE-200"]
    assert "security-severity" in rule["properties"]
    result = run["results"][0]
    masked = mask(token)
    assert result["message"]["text"] == f"Secret returned in chatbot reply (nova): {masked}"
    assert result["properties"]["confidence"] == "high"
    assert token not in sarif_text
    assert "ghp_" not in sarif_text


def test_plugin_output_caps_a_long_passwd_body(tmp_path: Path) -> None:
    lines = [
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "root:x:0:0:root:/root:/bin/bash",
        *[f"user{i}:x:{i}:{i}::/home/user{i}:/bin/sh" for i in range(1, 40)],
    ]
    body = "\n".join(lines)
    assert len(body) > _PLUGIN_OUTPUT_CAP
    assert len(lines[0]) <= _PLUGIN_OUTPUT_CAP
    finding = _bare(
        probe="insidia.web.path_lfi",
        attack="web.path_lfi",
        response=body,
        target="files",
        observations=(
            Observation("insidia", "insidia.web.path_lfi", "high", "/file", body),
            Observation("insidia", "insidia.web.path_lfi", "high", "/file", body),
        ),
    )
    directory = write_run(tmp_path, "run-lfi", "L1", False, [finding], [], [])
    html = (directory / "report.html").read_text()
    card = html.split('<details class="finding"', 1)[1].split("</details>", 1)[0]
    plugin = card.split("Plugin output", 1)[1].split("<dt>", 1)[0]
    assert plugin.count("<pre>") == 1
    pre = plugin.split("<pre>", 1)[1].split("</pre>", 1)[0]
    assert pre == lines[0]
    assert len(pre) <= _PLUGIN_OUTPUT_CAP
    assert f"{len(finding.observations)} observations" in plugin
    assert f"truncated to {_PLUGIN_OUTPUT_CAP} characters" in plugin
    for line in lines[1:]:
        assert line not in html


def test_not_tested_rows_say_why_and_passes_are_counted_honestly(tmp_path: Path) -> None:
    import re

    controls = [
        {
            "id": "ai.bias",
            "target": "nova",
            "result": "not tested",
            "taxonomy": "owasp-llm:LLM01",
            "detail": "needs a judge model: `models: {}`",
        },
        {
            "id": "infra.tls",
            "target": "shop",
            "result": "not tested",
            "taxonomy": "owasp-web:A02",
            "detail": "http:// target has no TLS to test",
        },
        {
            "id": "logic.race",
            "target": "shop",
            "result": "not tested",
            "taxonomy": "owasp-web:A04",
        },
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A03,cwe:CWE-1336",
        },
    ]
    directory = write_run(tmp_path, "run-cov", "L1", True, [], controls, [])
    html = (directory / "report.html").read_text()
    assert "not evidence that those risks are absent" in html
    reasons = []
    for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
        if "NOT TESTED" not in row:
            continue
        why = re.search(r'data-l="Why">(.*?)</td>', row)
        assert why is not None
        text = why.group(1).strip()
        assert text
        reasons.append(text)
    assert len(reasons) == 3
    assert len(set(reasons)) == 3
    assert any("judge model" in reason for reason in reasons)
    assert any("no TLS" in reason for reason in reasons)
    assert any("logic.race" in reason for reason in reasons)
    assert _score_line(html, "OWASP LLM Top 10") == ("0", "0 passed (0 low assurance)", "10")
    assert _score_line(html, "OWASP Web Top 10") == ("0", "1 passed (0 low assurance)", "9")
    assert "@media (max-width:700px)" in html
    assert "@media print" in html
    assert "nav { display: none; }" in html
    assert "prefers-color-scheme: dark" in html


def test_report_css_fits_a_390px_screen(tmp_path: Path) -> None:
    directory = write_run(tmp_path, "run-narrow", "L1", True, [], [], [])
    html = (directory / "report.html").read_text()
    assert "@media (max-width:390px)" in html
    assert "@media print" in html
    assert "nav { display: none; }" in html


def _risk_factor_text(card: str) -> str:
    import re

    chunk = card.split("<dt>Risk factor</dt><dd>", 1)[1].split("</dd>", 1)[0]
    return re.sub(r"<[^>]+>", "", chunk)


_NOT_A_CERTIFICATION = "This report is test evidence, not a certification."


def _summary_paragraph(html: str) -> str:
    block = html.split('<h2 id="summary">Executive summary</h2>', 1)[1]
    paragraph = block.split("<p", 1)[1]
    return paragraph.split(">", 1)[1].split("</p>", 1)[0]


def _leak() -> Finding:
    return _bare(
        track="ai",
        attack="ai.data_leakage",
        probe="insidia.ai.data_leakage",
        severity="critical",
        title="Secret returned in chatbot reply",
        risk_score=9.1,
        risk_factors=("live-format credential floor 9.1",),
        target="nova",
        taxonomy=("owasp-llm:LLM02",),
    )


def _nova_controls() -> list[dict[str, str]]:
    return [
        {
            "id": "ai.data_leakage",
            "target": "nova",
            "result": "fail",
            "taxonomy": "owasp-llm:LLM02",
        },
        {
            "id": "web.ssti",
            "target": "nova",
            "result": "pass",
            "taxonomy": "owasp-web:A03",
        },
        {
            "id": "ai.bias",
            "target": "nova",
            "result": "not tested",
            "taxonomy": "owasp-llm:LLM01",
        },
    ]


def test_fail_summary_names_the_run_and_is_not_a_certification(tmp_path: Path) -> None:
    directory = write_run(tmp_path, "run-fail", "L1", False, [_leak()], _nova_controls(), [])
    text = _summary_paragraph((directory / "report.html").read_text())
    assert text == (
        "Insidia ran 2 of 3 checks against 1 target (nova). "
        "Policy L1 did not pass: 1 finding (1 critical, 0 high, 0 medium, 0 low, 0 info). "
        "The most serious finding is Secret returned in chatbot reply, severity critical, "
        "score 9.1, target nova. "
        "0 passed checks have low assurance and 1 check was not tested. "
        "Checks that were not tested are not evidence that those risks are absent. "
        "This report is test evidence, not a certification."
    )
    assert text.endswith(_NOT_A_CERTIFICATION)


def test_pass_summary_follows_the_same_shape(tmp_path: Path) -> None:
    controls = [
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A03",
        },
        {
            "id": "ai.bias",
            "target": "shop",
            "result": "not tested",
            "taxonomy": "owasp-llm:LLM01",
        },
    ]
    directory = write_run(tmp_path, "run-pass", "L1", True, [], controls, [])
    text = _summary_paragraph((directory / "report.html").read_text())
    assert text == (
        "Insidia ran 1 of 2 checks against 1 target (shop). "
        "Policy L1 passed: 0 findings (0 critical, 0 high, 0 medium, 0 low, 0 info). "
        "The most serious finding is none. "
        "0 passed checks have low assurance and 1 check was not tested. "
        "Checks that were not tested are not evidence that those risks are absent. "
        "This report is test evidence, not a certification."
    )
    assert text.endswith(_NOT_A_CERTIFICATION)
    assert "did not pass" not in text
    assert "The scan did not finish" not in text


def test_incomplete_summary_follows_the_same_shape(tmp_path: Path) -> None:
    directory = write_run(
        tmp_path,
        "run-gap",
        "L1",
        False,
        [_leak()],
        _nova_controls(),
        [],
        execution_status="incomplete",
    )
    text = _summary_paragraph((directory / "report.html").read_text())
    assert text == (
        "Insidia ran 2 of 3 checks against 1 target (nova). "
        "The scan did not finish: incomplete. "
        "Policy L1 did not pass: 1 finding (1 critical, 0 high, 0 medium, 0 low, 0 info). "
        "The most serious finding is Secret returned in chatbot reply, severity critical, "
        "score 9.1, target nova. "
        "0 passed checks have low assurance and 1 check was not tested. "
        "Checks that were not tested are not evidence that those risks are absent. "
        "Results below cover 2 checks only. "
        "Re-run with `insidia rerun run-gap`. "
        "This report is test evidence, not a certification."
    )
    assert text.endswith(_NOT_A_CERTIFICATION)


def test_low_assurance_passes_are_counted_from_the_field(tmp_path: Path) -> None:
    note = "garak sent only 1 prompt(s)"
    controls = [
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A03",
            "assurance": "low",
            "assurance_reason": note,
        },
        {
            "id": "web.headers",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A05",
        },
    ]
    directory = write_run(tmp_path, "run-weak", "L1", True, [], controls, [])
    html = (directory / "report.html").read_text()
    text = _summary_paragraph(html)
    assert "1 passed check has low assurance and 0 checks were not tested." in text
    assert "0 passed checks have low assurance" not in text
    assert "2 passed (1 low assurance)" in html
    assert _score_line(html, "OWASP Web Top 10") == ("0", "2 passed (1 low assurance)", "8")
    assert _owasp_result(html, "owasp-web:A03") == "pass (low assurance)"
    assert _owasp_result(html, "owasp-web:A05") == "pass"
    weak_badge = _coverage_badge(html, "web.ssti")
    assert "PASS (low assurance)" in weak_badge
    assert "res-low" in weak_badge
    assert "res-pass" not in weak_badge
    full_badge = _coverage_badge(html, "web.headers")
    assert "res-pass" in full_badge
    assert ">PASS<" in full_badge
    assert "low assurance" not in full_badge
    assert note in html
    benchmark = json.loads((directory / "benchmark.json").read_text())
    weak = next(row for row in benchmark["controls"] if row["id"] == "web.ssti")
    assert weak["assurance"] == "low"
    assert weak["assurance_reason"] == note
    web = next(item for item in benchmark["scores"] if item["framework"] == "owasp-web")
    assert web["passed"] == 2
    assert web["low_assurance"] == 1


def test_an_owasp_row_with_a_strong_pass_stays_plain() -> None:
    controls = [
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A03",
            "assurance": "low",
            "assurance_reason": "garak sent only 1 prompt(s)",
        },
        {
            "id": "web.cmdi",
            "target": "shop",
            "result": "pass",
            "taxonomy": "owasp-web:A03",
        },
    ]
    web = next(score for score in score_frameworks(controls) if score.framework == "owasp-web")
    assert web.passed == 1
    assert web.low_assurance == 0
    rows = {item_id: result for item_id, _title, result in coverage(controls)}
    assert rows["owasp-web:A03"] == "pass"
    failed = [
        {
            "id": "web.ssti",
            "target": "shop",
            "result": "fail",
            "taxonomy": "owasp-web:A03",
        },
        controls[0],
    ]
    failed_rows = {item_id: result for item_id, _title, result in coverage(failed)}
    assert failed_rows["owasp-web:A03"] == "fail"


def _coverage_badge(html: str, check_id: str) -> str:
    row = html.split(f"<code>{check_id}</code>", 1)[1].split("</tr>", 1)[0]
    return row.split('data-l="Result">', 1)[1].split("</td>", 1)[0]


def _owasp_result(html: str, control_id: str) -> str:
    row = next(line for line in html.splitlines() if f">{control_id}<" in line)
    cells = row.split("<td")
    return cells[-1].split(">", 1)[1].split("<", 1)[0]


def _score_line(html: str, title: str) -> tuple[str, str, str]:
    row = next(line for line in html.splitlines() if title in line)
    cells = row.split("<td")
    values = [cell.split(">", 1)[1].split("<", 1)[0] for cell in cells[1:]]
    assert values[0] == title
    return values[1], values[2], values[3]


def test_unknown_taxonomy_id_is_rejected() -> None:
    controls = [{"id": "x", "target": "chat", "result": "fail", "taxonomy": "owasp-llm:LLM99"}]
    with pytest.raises(ValueError, match="unknown taxonomy id owasp-llm:LLM99"):
        score_frameworks(controls)


def _bare(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "track": "classic",
        "engine": "insidia",
        "probe": "insidia.web.ssti",
        "severity": "high",
        "confidence": "high",
        "attack": "web.ssti",
        "response": "49",
        "trace_ref": "shop",
        "taxonomy": ("owasp-web:A03",),
        "remediation": "Do not evaluate user input as a template.",
        "evidence_hash": "abc",
        "cross_validated": False,
        "target": "shop",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def test_every_sarif_result_locates_the_endpoint_or_the_file(tmp_path: Path) -> None:
    chat = _bare(
        track="ai",
        probe="insidia.ai.data_leakage",
        attack="ai.data_leakage",
        response=mask(f"token {_SECRET}"),
        taxonomy=("owasp-llm:LLM02",),
        remediation="Stop returning secrets.",
        target="nova",
        location="",
    )
    repo = _bare(
        probe="insidia.code.secrets",
        attack="code.secrets",
        response=mask(_SECRET),
        taxonomy=("owasp-web:A05",),
        remediation="Remove the key.",
        target="tree",
        location="pkg/secrets.py:12",
    )
    blank = _bare(target="orphan", location="")
    endpoint = "POST http://127.0.0.1:8100/api/v1/assistant"
    directory = write_run(
        tmp_path,
        "run-loc",
        "L1",
        False,
        [chat, repo, blank],
        [],
        [],
        targets=(
            ("nova", "chat", endpoint),
            ("tree", "repo", "benchmark/targets/insidia/repo"),
        ),
    )
    payload = json.loads((directory / "findings.json").read_text())
    by_target = {item["target"]: item for item in payload}
    assert by_target["nova"]["endpoint"] == endpoint
    assert by_target["nova"]["target_kind"] == "chat"
    assert by_target["tree"]["target_kind"] == "repo"
    assert by_target["tree"]["endpoint"] == "benchmark/targets/insidia/repo"
    assert by_target["orphan"]["endpoint"] == ""
    assert by_target["orphan"]["target_kind"] == ""
    results = json.loads((directory / "results.sarif").read_text())["runs"][0]["results"]
    assert len(results) == len(payload)
    for result in results:
        assert result["locations"]
        physical = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "://" not in physical
        assert not physical.startswith("/")
    nova = next(item for item in results if "data_leakage" in item["ruleId"])
    logical = nova["locations"][0]["logicalLocations"][0]
    assert logical["kind"] == "endpoint"
    assert logical["fullyQualifiedName"] == endpoint
    assert nova["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == endpoint
    assert nova["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "insidia-endpoints/"
    )
    secret = next(item for item in results if item["ruleId"] == "insidia.code.secrets")
    region = secret["locations"][0]["physicalLocation"]
    assert region["artifactLocation"]["uri"] == "pkg/secrets.py"
    assert region["region"]["startLine"] == 12
    assert "logicalLocations" not in secret["locations"][0]


def test_l1_tags_prompt_injection_and_template_injection() -> None:
    policy = get_policy("L1")
    assert "owasp-llm:LLM01" in policy.control("ai.prompt_injection_direct").taxonomy
    assert "owasp-web:A03" in policy.control("web.ssti").taxonomy
    assert "owasp-llm:LLM06" in policy.control("ai.unbounded_consumption").taxonomy


_LLM_INDEX = "https://genai.owasp.org/llm-top-10/"
_LIVE_LLM = {
    "01": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "02": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    "03": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    "04": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
    "05": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    "06": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    "07": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
    "08": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
    "09": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
    "10": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
}


_CSV_HEADER = [
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
]


def test_rerun_records_provenance_and_finding_state(tmp_path: Path) -> None:
    import csv
    import io

    token = "ghp_" + ("c" * 36)
    masked = mask(f"saw {token} in the reply")
    kept = _bare(title="Kept finding", evidence_hash="hash-kept", response="kept reply")
    dropped = _bare(
        title="Dropped finding",
        evidence_hash="hash-dropped",
        response=masked,
        observations=(
            Observation("insidia", "insidia.web.ssti", "high", "/ping", masked),
        ),
    )
    fresh = _bare(title="New finding", evidence_hash="hash-new", response="new reply")
    run_a = "20261018T000000Z-aaaaaa"
    run_b = "20261018T000001Z-bbbbbb"
    directory_a = write_run(tmp_path, run_a, "L1", False, [kept, dropped], [], [])
    manifest_a = read_manifest(directory_a)
    assert manifest_a is not None
    assert "rerun_of" not in manifest_a
    stored = json.loads((directory_a / "findings.json").read_text())
    dropped_stored = next(item for item in stored if item["evidence_hash"] == "hash-dropped")
    assert token not in json.dumps(dropped_stored)
    assert all(item["state"] == "new" and item["first_seen_run"] == run_a for item in stored)
    assert "Fixed since" not in (directory_a / "report.html").read_text()

    directory_b = write_run(
        tmp_path,
        run_b,
        "L1",
        False,
        [kept, fresh],
        [],
        [],
        rerun_of=run_a,
    )
    manifest_b = read_manifest(directory_b)
    assert manifest_b is not None
    assert manifest_b["rerun_of"] == run_a
    payload = json.loads((directory_b / "findings.json").read_text())
    by_hash = {item["evidence_hash"]: item for item in payload}
    assert by_hash["hash-kept"]["state"] == "still_open"
    assert by_hash["hash-kept"]["first_seen_run"] == run_a
    assert by_hash["hash-new"]["state"] == "new"
    assert by_hash["hash-new"]["first_seen_run"] == run_b
    html = (directory_b / "report.html").read_text()
    assert f"Fixed since {run_a}" in html
    assert "Dropped finding" in html
    assert "hash-dropped" in html
    assert token not in html
    assert "ghp_" not in html
    summary = _summary_paragraph(html)
    assert f"1 new, 1 still open, and 1 fixed since {run_a}." in summary
    assert summary.endswith("This report is test evidence, not a certification.")
    header = next(csv.reader(io.StringIO((directory_b / "findings.csv").read_text())))
    assert header == _CSV_HEADER
    assert "state" not in header
    sarif = json.loads((directory_b / "results.sarif").read_text())
    result = sarif["runs"][0]["results"][0]
    assert "state" not in result
    assert "state" not in result["properties"]

    run_c = "20261018T000002Z-cccccc"
    directory_c = write_run(
        tmp_path, run_c, "L1", False, [kept], [], [], rerun_of=run_b
    )
    later = json.loads((directory_c / "findings.json").read_text())
    assert later[0]["evidence_hash"] == "hash-kept"
    assert later[0]["state"] == "still_open"
    assert later[0]["first_seen_run"] == run_a


def test_baseline_uses_digest_then_target_names_and_skips_dot_dirs(tmp_path: Path) -> None:
    root = tmp_path / "digest"
    kept = _bare(title="Kept finding", evidence_hash="hash-kept")
    other = _bare(title="Other finding", evidence_hash="hash-other", target="shop")
    digest = "ab" * 32
    other_digest = "cd" * 32
    older = "20261018T000000Z-older1"
    middle = "20261018T000001Z-middle"
    current = "20261018T000002Z-curr01"
    write_run(
        root,
        older,
        "L1",
        False,
        [kept, other],
        [],
        [],
        config_digest=digest,
        targets=(("shop", "web", "http://127.0.0.1/"),),
    )
    write_run(
        root,
        middle,
        "L1",
        False,
        [other],
        [],
        [],
        config_digest=other_digest,
        targets=(("shop", "web", "http://127.0.0.1/"),),
    )
    hidden = root / ".insidia" / "runs" / ".hidden"
    hidden.mkdir()
    (hidden / "manifest.json").write_text(json.dumps({"config_digest": digest}))
    (hidden / "findings.json").write_text(
        json.dumps([{"title": "Hidden finding", "target": "shop", "evidence_hash": "hash-hidden"}])
    )
    directory = write_run(
        root,
        current,
        "L1",
        False,
        [kept],
        [],
        [],
        config_digest=digest,
        targets=(("shop", "web", "http://127.0.0.1/"),),
    )
    payload = json.loads((directory / "findings.json").read_text())
    assert payload[0]["state"] == "still_open"
    assert payload[0]["first_seen_run"] == older
    html = (directory / "report.html").read_text()
    assert f"Fixed since {older}" in html
    assert "Other finding" in html
    assert "Hidden finding" not in html
    assert "rerun_of" not in json.loads((directory / "manifest.json").read_text())

    names = tmp_path / "names"
    write_run(names, ".hidden", "L1", False, [kept], [], [], config_digest=digest)
    named = write_run(
        names,
        "20261018T000003Z-named1",
        "L1",
        False,
        [other],
        [],
        [],
        config_digest="ef" * 32,
        targets=(("shop", "web", "http://127.0.0.1/"),),
    )
    followed = write_run(
        names,
        "20261018T000004Z-named2",
        "L1",
        False,
        [other],
        [],
        [],
        config_digest="12" * 32,
        targets=(("shop", "web", "http://127.0.0.1/"),),
    )
    followed_payload = json.loads((followed / "findings.json").read_text())
    assert followed_payload[0]["state"] == "still_open"
    assert followed_payload[0]["first_seen_run"] == named.name
    assert "Fixed since .hidden" not in (followed / "report.html").read_text()
    lone = write_run(tmp_path / "lone", "run-b", "L1", False, [kept], [], [])
    assert "Fixed since" not in (lone / "report.html").read_text()
    # A dot-named run is not a baseline for a later run that shares its digest.
    dots = tmp_path / "dots"
    write_run(dots, ".hidden", "L1", False, [kept], [], [], config_digest=digest)
    dotted = write_run(
        dots,
        "run-c",
        "L1",
        False,
        [kept],
        [],
        [],
        config_digest=digest,
    )
    dotted_payload = json.loads((dotted / "findings.json").read_text())
    assert dotted_payload[0]["state"] == "new"
    assert dotted_payload[0]["first_seen_run"] == "run-c"
    assert "Fixed since" not in (dotted / "report.html").read_text()


def test_still_open_without_first_seen_uses_the_baseline_run(tmp_path: Path) -> None:
    token = "ghp_" + ("d" * 36)
    legacy = tmp_path / ".insidia" / "runs" / "legacy-run"
    legacy.mkdir(parents=True)
    (legacy / "findings.json").write_text(
        json.dumps(
            [
                {"title": "Old finding", "target": "shop", "evidence_hash": "hash-kept"},
                {
                    "title": f"Gone {token}",
                    "target": "shop",
                    "evidence_hash": "hash-dropped",
                    "evidence": f"raw evidence {token}",
                },
            ]
        )
        + "\n"
    )
    directory = write_run(
        tmp_path,
        "run-b",
        "L1",
        False,
        [_bare(title="Old finding", evidence_hash="hash-kept")],
        [],
        [],
        rerun_of="legacy-run",
    )
    payload = json.loads((directory / "findings.json").read_text())
    assert payload[0]["state"] == "still_open"
    assert payload[0]["first_seen_run"] == "legacy-run"
    html = (directory / "report.html").read_text()
    assert "Fixed since legacy-run" in html
    assert token not in html
    assert "raw evidence" not in html
    assert mask(f"Gone {token}") in html


def test_owasp_llm_references_use_a_live_page_or_the_index() -> None:
    controls = (*get_policy("L1").controls, MARKDOWN_BEACON)
    checked = 0
    for control in controls:
        numbers = [
            item.removeprefix("owasp-llm:LLM")
            for item in control.taxonomy
            if item.startswith("owasp-llm:LLM")
        ]
        for url in control.references:
            if not numbers:
                continue
            checked += 1
            assert "2026" not in url
            for number in numbers:
                if number == "08":
                    assert "llm07" not in url
                if number == "10":
                    assert "llm05" not in url
                assert url == _LLM_INDEX or url == _LIVE_LLM[number]
    assert checked
