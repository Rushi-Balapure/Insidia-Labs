import json
from pathlib import Path

import pytest
from insidia.findings import Finding, Observation
from insidia.mask import mask
from insidia.policy import MARKDOWN_BEACON, get_policy
from insidia.runstore import _PLUGIN_OUTPUT_CAP, write_run
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
    assert _score_line(html, "OWASP LLM Top 10") == ("1", "0", "9")
    assert _score_line(html, "OWASP Web Top 10") == ("0", "1", "9")
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
    rules = json.loads((directory / "results.sarif").read_text())["runs"][0]["tool"]["driver"][
        "rules"
    ]
    assert all("help" not in rule and "helpUri" not in rule for rule in rules)


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
    assert _score_line(html, "OWASP LLM Top 10") == ("0", "0", "10")
    assert _score_line(html, "OWASP Web Top 10") == ("0", "1", "9")
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
