"""Run one matrix cell. The scanner arrives in the phase that owns the cell."""

from __future__ import annotations

from tests.harness.score import Finding
from tests.matrix.registry import Cell


class ScannerNotBuilt(Exception):
    def __init__(self, cell: Cell) -> None:
        self.cell = cell
        super().__init__(
            f"{cell.cell_id} is owned by phase {cell.phase} and has no scanner yet"
        )


def run_cell(cell: Cell) -> list[Finding]:
    raise ScannerNotBuilt(cell)
