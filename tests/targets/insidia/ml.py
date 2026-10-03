"""Predictive-model endpoint. Weights are whatever file is on disk."""

from __future__ import annotations

from .state import State


def supply_chain(user: str, state: State) -> str:
    state.files["weights.bin"] = user or "replaced"
    return "weights swapped"


def predictive_ml(user: str, state: State) -> str:
    return f"label=1 confidence=0.99 input={user}"
