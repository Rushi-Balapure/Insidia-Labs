"""Synthetic findings produce the recall and precision the plan names."""

from benchmark.harness.score import Finding, golden_dropped, meets_threshold, score_findings
from benchmark.matrix.plants import Plant


def _plant(plant_id: str, *, judge: bool = False) -> Plant:
    attack = "ai.bias" if judge else "web.xss"
    return Plant(
        id=plant_id,
        target="fixture",
        attack=attack,
        location="here",
        probe_id=f"insidia.{attack}",
        taxonomy_id="LLM01",
        severity="medium" if judge else "high",
        oracle="policy_judge" if judge else "structural",
    )


def test_one_hit_and_one_miss_is_half_recall() -> None:
    expected = [_plant("a"), _plant("b")]
    result = score_findings(expected, [Finding("a")])
    assert result.recall == 0.5
    assert result.precision == 1.0
    assert result.missed == ("b",)
    assert meets_threshold(result, 0.80, 0.90) is False


def test_false_positive_drops_precision() -> None:
    expected = [_plant("a")]
    result = score_findings(expected, [Finding("a"), Finding("nope"), Finding("a")])
    assert result.recall == 1.0
    assert result.precision == 2 / 3
    assert result.false_positives == ("nope",)


def test_empty_findings_have_zero_recall_and_full_precision() -> None:
    result = score_findings([_plant("a")], [])
    assert result.recall == 0.0
    assert result.precision == 1.0


def test_judge_only_critical_cannot_pass() -> None:
    result = score_findings([_plant("bias", judge=True)], [Finding("bias", severity="critical")])
    assert result.judge_only_critical is True
    assert meets_threshold(result, 0.80, 0.90) is False


def test_golden_drop_is_reported_even_when_recall_would_pass() -> None:
    assert golden_dropped({"a", "b"}, {"a"}) == ("b",)
    assert golden_dropped({"a"}, {"a", "extra"}) == ()
