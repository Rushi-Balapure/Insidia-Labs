"""Phase exit gate: a phase is done only when the cells it owns are green."""

from __future__ import annotations

from benchmark.matrix.registry import Cell


def still_red(phase: str, cells: tuple[Cell, ...], outcomes: dict[str, str]) -> tuple[str, ...]:
    """Return owned cell ids whose pytest outcome is still xfailed or missing.

    `outcomes` maps cell id to `passed`, `xfailed`, or `failed`.
    """
    blocked: list[str] = []
    for cell in cells:
        if not cell.valid or cell.phase != phase:
            continue
        outcome = outcomes.get(cell.cell_id)
        if outcome != "passed":
            blocked.append(cell.cell_id)
    return tuple(blocked)
