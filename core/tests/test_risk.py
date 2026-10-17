"""Insidia Risk Score: per-check severity, modifiers, sort order, SARIF."""

import json
from pathlib import Path

from insidia.findings import Finding, canonical_severity, normalize, score_finding
from insidia.mask import mask
from insidia.probes import ProbeHit
from insidia.runstore import write_run
from insidia.score import risk_assessment, severity_band

_GITHUB = "ghp_" + ("a" * 36)
_AWS = "AKIAIOSFODNN7EXAMPLE"


def _hit(
    family: str,
    response: str,
    *,
    severity: str = "high",
    confidence: str = "high",
    engine: str = "insidia",
    location: str = "",
    evidence: str = "",
) -> ProbeHit:
    return ProbeHit(
        "app",
        family,
        engine,
        f"insidia.{family}",
        response,
        severity,
        confidence,
        "ai" if family.startswith("ai.") else "classic",
        (),
        "Fix it.",
        evidence=evidence or response,
        location=location,
    )


def _one(family: str, response: str, **kwargs: str) -> Finding:
    return normalize([_hit(family, response, **kwargs)])[0]


def test_severity_and_score_differ_by_check() -> None:
    leak = _one("ai.data_leakage", "internal runbook for the staging host")
    cmdi = _one("web.cmdi", "uid=0(root)")
    ssti = _one("web.ssti", "49")
    lfi = _one("web.path_lfi", "root:x:0:0")
    jail = _one("ai.jailbreak", "DAN_UNLOCKED")
    assert {leak.severity, cmdi.severity, lfi.severity} == {"high", "critical"}
    assert leak.severity == "high"
    assert leak.risk_score == 7.5
    assert cmdi.severity == "critical"
    assert cmdi.risk_score == 9.8
    assert ssti.risk_score == 9.0
    assert lfi.severity == "high"
    assert lfi.risk_score == 7.5
    assert jail.severity == "high"
    assert jail.risk_score == 7.0
    assert "CVSS" not in " ".join(leak.risk_factors)


def test_live_credential_floors_the_score_and_sorts_first() -> None:
    planted = _hit("ai.data_leakage", f"token {mask(_GITHUB)} end")
    quiet = _hit("ai.data_leakage", "the wiki page is internal")
    command = _hit("web.cmdi", "uid=0(root)")
    findings = normalize([quiet, command, planted])
    leaked = next(item for item in findings if "floor" in " ".join(item.risk_factors))
    assert leaked.severity == "critical"
    assert leaked.risk_score == 9.1
    assert "live-format credential floor 9.1" in leaked.risk_factors
    assert [item.attack for item in findings] == [
        "web.cmdi",
        "ai.data_leakage",
        "ai.data_leakage",
    ]
    assert [item.risk_score for item in findings] == [9.8, 9.1, 7.5]
    again = normalize([planted, quiet, command])
    assert [(item.attack, item.risk_score, item.severity) for item in again] == [
        (item.attack, item.risk_score, item.severity) for item in findings
    ]


def test_medium_confidence_and_a_second_engine_are_recorded() -> None:
    one = _one("ai.prompt_injection_direct", "INSIDIA-OVERRIDE", confidence="medium")
    assert one.severity == "medium"
    assert one.risk_score == 6.5
    assert "medium confidence (-1.0)" in one.risk_factors
    first = _hit("ai.prompt_injection_direct", "INSIDIA-OVERRIDE", confidence="high")
    second = _hit(
        "ai.prompt_injection_direct",
        "INSIDIA-OVERRIDE",
        confidence="high",
        engine="garak",
    )
    merged = normalize([first, second])
    assert len(merged) == 1
    assert merged[0].risk_score == 7.8
    assert "cross-validated by 2+ engines (+0.3)" in merged[0].risk_factors
    assert merged[0].cross_validated is False


def test_family_specific_modifiers() -> None:
    refused = _one("ai.jailbreak", "I cannot help with that request")
    assert refused.severity == "medium"
    assert refused.risk_score == 5.5
    hidden = _one(
        "ai.hidden_context_extraction",
        "prompt [CONFIGURED len=12 fp=abcd1234]",
    )
    assert hidden.severity == "high"
    assert hidden.risk_score == 7.5
    assert "secrets inside hidden context (7.5)" in hidden.risk_factors
    pickled = _one("code.sast_sinks", "pickle.loads(blob)")
    plain = _one("code.sast_sinks", "a risky call")
    assert pickled.risk_score == 8.8
    assert plain.risk_score == 7.5
    sca = _one("deps.sca", "lodash==4.17.4 is below 4.17.21 (CVE-2021-23337)")
    assert sca.cve == ("CVE-2021-23337",)
    assert sca.risk_score == 7.2
    assert sca.severity == "high"
    assert any("CVSS v3 7.2" in factor for factor in sca.risk_factors)
    assert "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" in sca.risk_factors[0]


def test_bands_and_the_info_alias() -> None:
    assert severity_band(10) == "critical"
    assert severity_band(9.0) == "critical"
    assert severity_band(8.9) == "high"
    assert severity_band(7.0) == "high"
    assert severity_band(6.9) == "medium"
    assert severity_band(4.0) == "medium"
    assert severity_band(3.9) == "low"
    assert severity_band(0.1) == "low"
    assert severity_band(0) == "informational"
    assert canonical_severity("info") == "informational"
    assert canonical_severity("INFO") == "informational"
    finding = _one("ai.bias", "a stereotype", severity="info")
    assert finding.severity == "medium"
    assert finding.risk_score == 5.0


def test_an_unknown_severity_stays_unspecified_and_a_missing_family_falls_back() -> None:
    unknown = _one("web.ssti", "49", severity="severe")
    assert unknown.severity == "unspecified"
    assert unknown.risk_score == 9.0
    missing = score_finding(
        Finding(
            track="classic",
            engine="insidia",
            probe="insidia.web.not_a_real_check",
            severity="high",
            confidence="high",
            attack="web.not_a_real_check",
            response="nope",
            trace_ref="app",
            taxonomy=(),
            remediation="Do the safe thing.",
            evidence_hash="abc",
            cross_validated=False,
            target="app",
        )
    )
    assert missing.check_id == "INS-WEB-NOT-A-REAL-CHECK"
    assert missing.title
    assert missing.synopsis == "Do the safe thing."
    assert missing.risk_score == 7.5
    severity, score, factors, _cves = risk_assessment(
        "web.not_a_real_check", "nope", "high", 1, non_prod=True
    )
    assert severity == "high"
    assert score == 7.5
    assert factors[-1] == "target in non-prod scope (no score change)"


def test_same_inputs_score_the_same_and_sarif_carries_security_severity(tmp_path: Path) -> None:
    hits = [
        _hit("web.path_lfi", "root:x:0:0", location="app.py:4"),
        _hit("web.cmdi", "uid=0(root)"),
        _hit("ai.data_leakage", mask(_AWS)),
    ]
    first = [(item.check_id, item.severity, item.risk_score) for item in normalize(hits)]
    second = [(item.check_id, item.severity, item.risk_score) for item in normalize(hits)]
    assert first == second
    assert [item[1] for item in first] == ["critical", "critical", "high"]
    directory = write_run(tmp_path, "run-1", "L1", False, normalize(hits), [], [])
    payload = json.loads((directory / "findings.json").read_text())
    assert isinstance(payload, list)
    assert payload[0]["schema_version"] == "2.1"
    assert payload[0]["severity"] == "critical"
    assert payload[0]["risk_score"] == 9.8
    assert [item["check_id"] for item in payload] == ["INS-WEB-004", "INS-AI-002", "INS-WEB-005"]
    sarif = json.loads((directory / "results.sarif").read_text())
    results = sarif["runs"][0]["results"]
    assert [item["properties"]["security-severity"] for item in results] == ["9.8", "9.1", "7.5"]
    assert [item["level"] for item in results] == ["error", "error", "error"]
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert all("security-severity" in rule["properties"] for rule in rules)
    medium = normalize([_hit("ai.unbounded_consumption", "a very long reply")])
    medium_dir = write_run(tmp_path, "run-2", "L1", False, medium, [], [])
    medium_sarif = json.loads((medium_dir / "results.sarif").read_text())
    assert medium_sarif["runs"][0]["results"][0]["level"] == "warning"
    assert medium_sarif["runs"][0]["results"][0]["properties"]["security-severity"] == "5.3"
