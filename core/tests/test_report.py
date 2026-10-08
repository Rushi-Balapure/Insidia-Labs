import json
from pathlib import Path

from insidia.findings import Finding
from insidia.mask import mask
from insidia.runstore import write_run

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
    assert "<tr><td>OWASP LLM Top 10</td><td>1</td><td>0</td><td>9</td></tr>" in html
    assert "<tr><td>OWASP Web Top 10</td><td>0</td><td>1</td><td>9</td></tr>" in html
    assert "<script" not in html
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
        },
        {
            "framework": "owasp-asi",
            "title": "OWASP Agentic Top 10",
            "failed": 0,
            "passed": 0,
            "not_tested": 10,
        },
        {
            "framework": "owasp-web",
            "title": "OWASP Web Top 10",
            "failed": 0,
            "passed": 1,
            "not_tested": 9,
        },
        {
            "framework": "owasp-api",
            "title": "OWASP API Top 10",
            "failed": 0,
            "passed": 0,
            "not_tested": 10,
        },
    ]
    sarif = json.loads((directory / "results.sarif").read_text())
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Insidia"
    assert run["results"][0]["properties"]["engine"] == "insidia"
