"""Each valid cell meets ground truth once the scanner can prove it. The rest stay xfail."""

from __future__ import annotations

import pytest

from benchmark.harness.run_cell import run_cell, scanner_ready
from benchmark.harness.score import golden_dropped, meets_threshold, score_findings
from benchmark.matrix.plants import plant_for
from benchmark.matrix.registry import Cell, valid_cells


def _parameters() -> list[object]:
    parameters: list[object] = []
    for cell in valid_cells():
        marks = [getattr(pytest.mark, name) for name in cell.marker_names()]
        if not scanner_ready(cell):
            marks.append(
                pytest.mark.xfail(
                    strict=True,
                    reason=f"phase {cell.phase} scanner is not built",
                )
            )
        parameters.append(pytest.param(cell, id=cell.cell_id, marks=marks))
    return parameters


@pytest.mark.parametrize("cell", _parameters())
def test_cell_meets_ground_truth(cell: Cell) -> None:
    actual = run_cell(cell)
    expected = [plant_for(cell.target, cell.attack)]
    result = score_findings(expected, actual)
    assert meets_threshold(result, cell.recall_floor, cell.precision_floor)
    found = {item.plant_id for item in actual}
    assert golden_dropped(set(cell.plant_ids), found) == ()
