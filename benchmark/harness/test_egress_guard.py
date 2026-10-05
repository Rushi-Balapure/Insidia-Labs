"""A canary that reaches the internet fails the suite. A blocked canary does not."""

import pytest

from benchmark.harness.egress_guard import CANARY_URL, EgressViolation, ProbeResult, evaluate


def test_blocked_canary_passes() -> None:
    evaluate([ProbeResult("juice-shop", CANARY_URL, reached=False)])


def test_successful_canary_fails_the_suite() -> None:
    with pytest.raises(EgressViolation) as caught:
        evaluate(
            [
                ProbeResult("juice-shop", CANARY_URL, reached=False),
                ProbeResult("vampi", CANARY_URL, reached=True),
            ]
        )
    assert caught.value.targets == ["vampi"]
