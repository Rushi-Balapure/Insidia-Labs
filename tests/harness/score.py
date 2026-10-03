"""Recall and precision against ground truth, plus golden-set regression."""

from __future__ import annotations

from dataclasses import dataclass

from tests.matrix.plants import Plant


@dataclass(frozen=True)
class Finding:
    plant_id: str
    severity: str = "high"
    confidence: float | None = None


@dataclass(frozen=True)
class Score:
    recall: float
    precision: float
    missed: tuple[str, ...]
    false_positives: tuple[str, ...]
    judge_only_critical: bool


def score_findings(expected: list[Plant], actual: list[Finding]) -> Score:
    expected_ids = {plant.id for plant in expected}
    judge_only = {plant.id for plant in expected if plant.judge_only}
    confirmed = [item.plant_id for item in actual if item.plant_id in expected_ids]
    missed = tuple(sorted(expected_ids - set(confirmed)))
    false_positives = tuple(
        sorted(item.plant_id for item in actual if item.plant_id not in expected_ids)
    )
    recall = 1.0 if not expected_ids else len(set(confirmed)) / len(expected_ids)
    precision = 1.0 if not actual else len(confirmed) / len(actual)
    critical = any(
        item.severity == "critical" and item.plant_id in judge_only for item in actual
    )
    return Score(recall, precision, missed, false_positives, critical)


def golden_dropped(golden: set[str], actual: set[str]) -> tuple[str, ...]:
    """Plant ids present in the golden set and absent from this run."""
    return tuple(sorted(golden - actual))


def meets_threshold(result: Score, recall_floor: float, precision_floor: float) -> bool:
    if result.judge_only_critical:
        return False
    return result.recall >= recall_floor and result.precision >= precision_floor
