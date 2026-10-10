from insidia.findings import normalize
from insidia.probes import ProbeHit
from insidia.registry import Capability, select


def test_standard_keeps_the_highest_priority_probe() -> None:
    entries = (
        Capability("ai.data_leakage", "insidia", "insidia.ai.data_leakage", 100, False, True),
        Capability("ai.data_leakage", "other", "other.leak", 10, False, True),
        Capability("ai.data_leakage", "offline", "offline.leak", 200, True, True),
    )
    standard = select("ai.data_leakage", "standard", model_available=False, entries=entries)
    thorough = select("ai.data_leakage", "thorough", model_available=True, entries=entries)
    assert [item.engine for item in standard] == ["insidia"]
    assert [item.engine for item in thorough] == ["offline", "insidia", "other"]


def test_a_match_after_the_first_500_characters_is_kept() -> None:
    evidence = "insidia-plant-canary-7f3a"
    hit = ProbeHit(
        "app",
        "ai.data_leakage",
        "insidia",
        "insidia.ai.data_leakage",
        ("x" * 600) + evidence,
        "high",
        "medium",
        "ai",
        ("owasp-llm:LLM02",),
        "Stop returning secrets.",
        evidence=evidence,
    )
    findings = normalize([hit])
    assert evidence in findings[0].response


def test_two_engines_mark_a_finding_cross_validated() -> None:
    hit = ProbeHit(
        "app",
        "ai.data_leakage",
        "insidia",
        "insidia.ai.data_leakage",
        "insidia-plant-canary-7f3a",
        "high",
        "medium",
        "ai",
        ("owasp-llm:LLM02",),
        "Stop returning secrets.",
    )
    other = ProbeHit(
        "app",
        "ai.data_leakage",
        "garak",
        "garak.leak",
        "insidia-plant-canary-7f3a",
        "high",
        "medium",
        "ai",
        ("owasp-llm:LLM02",),
        "Stop returning secrets.",
    )
    findings = normalize([hit, other])
    assert len(findings) == 1
    assert findings[0].cross_validated is False
    assert findings[0].engine == "insidia"
    assert findings[0].engines == ("insidia", "garak")
    assert findings[0].as_json()["reported_by"] == 2
    assert [item.engine for item in findings[0].observations] == ["insidia", "garak"]


def test_the_same_rule_at_two_locations_is_two_findings() -> None:
    def hit(location: str) -> ProbeHit:
        return ProbeHit(
            "repo",
            "code.secrets",
            "gitleaks",
            "gitleaks.secrets",
            "AKIAIOSFODNN7EXAMPLE",
            "high",
            "high",
            "classic",
            ("owasp-web:A05",),
            "Remove the key.",
            location=location,
        )

    findings = normalize([hit("a.py:3"), hit("b.py:9")])
    assert [item.location for item in findings] == ["a.py:3", "b.py:9"]


def test_an_unknown_severity_is_explicit() -> None:
    hit = ProbeHit(
        "app",
        "web.ssti",
        "insidia",
        "insidia.web.ssti",
        "49",
        "severe",
        "high",
        "classic",
        ("owasp-web:A03",),
        "Do not evaluate user input as a template.",
    )
    assert normalize([hit])[0].severity == "unspecified"
