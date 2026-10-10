"""The result contract: execution and policy are separate."""

from insidia.results import (
    CANCELLED,
    COMPLETE,
    ERROR,
    NOT_APPLICABLE,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)


def test_a_finished_scan_with_no_findings_passes() -> None:
    status, verdict = aggregate([CheckRecord("app", "web.ssti", "insidia", COMPLETE)])
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert legacy_passed(status, verdict) is True


def test_a_finished_scan_with_a_finding_fails() -> None:
    status, verdict = aggregate(
        [CheckRecord("app", "web.ssti", "insidia", COMPLETE, finding_count=1)]
    )
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "fail", 1)
    assert legacy_passed(status, verdict) is False


def test_a_failed_engine_beside_a_clean_one_is_incomplete() -> None:
    records = [
        CheckRecord("app", "ai.data_leakage", "insidia", COMPLETE),
        CheckRecord("app", "ai.data_leakage", "garak", ERROR, "report missing"),
    ]
    status, verdict = aggregate(records)
    assert status == "incomplete"
    assert verdict == "inconclusive"
    assert exit_for(status, verdict) == 2
    assert legacy_passed(status, verdict) is False


def test_findings_survive_a_failed_engine() -> None:
    records = [
        CheckRecord("app", "ai.data_leakage", "insidia", COMPLETE, finding_count=1),
        CheckRecord("app", "ai.data_leakage", "garak", ERROR, "report missing"),
    ]
    status, verdict = aggregate(records)
    assert status == "incomplete"
    assert verdict == "fail"
    assert exit_for(status, verdict) == 2


def test_no_applicable_check_is_inconclusive() -> None:
    status, verdict = aggregate([CheckRecord("app", "chat", "", NOT_APPLICABLE, "no controls")])
    assert (status, verdict, exit_for(status, verdict)) == ("incomplete", "inconclusive", 2)


def test_cancellation_exits_130() -> None:
    status, verdict = aggregate([CheckRecord("app", "web.ssti", "insidia", CANCELLED)])
    assert exit_for(status, verdict) == 130
