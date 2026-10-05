"""Fail the suite if a sandbox target reached the public internet."""

from __future__ import annotations

from dataclasses import dataclass

CANARY_URL = "http://example.com/"


class EgressViolation(Exception):
    def __init__(self, targets: list[str]) -> None:
        self.targets = targets
        joined = ", ".join(targets)
        super().__init__(f"sandbox target reached {CANARY_URL}: {joined}")


@dataclass(frozen=True)
class ProbeResult:
    target: str
    destination: str
    reached: bool


def evaluate(results: list[ProbeResult]) -> None:
    leaked = [item.target for item in results if item.reached]
    if leaked:
        raise EgressViolation(leaked)
