"""White-box plants. This package is not installed; it is only scanned."""

from __future__ import annotations

# AWS documentation example key. It is a plant, not a credential we use.
PLANTED_SECRET = "AKIAIOSFODNN7EXAMPLE"


def sast_sinks(user_code: str) -> object:
    return eval(user_code)  # noqa: S307


def secrets() -> str:
    return PLANTED_SECRET


def sca() -> str:
    return "pyyaml==5.3.1"
