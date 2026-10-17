import json
from pathlib import Path

import pytest
from insidia.findings import Finding
from insidia.mask import mask
from insidia.policy import get_policy
from insidia.runstore import write_run
from insidia.score import score_frameworks

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
    assert "prefers-color-scheme: dark" in html
    assert "#101028" in html
    assert "The scan ran. Policy L1 did not pass. 1 finding." in html
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
