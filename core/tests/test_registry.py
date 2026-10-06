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
    assert findings[0].cross_validated
    assert findings[0].engine == "insidia"
    assert findings[0].engines == ("insidia", "garak")
    assert findings[0].as_json()["engines"] == ["insidia", "garak"]
