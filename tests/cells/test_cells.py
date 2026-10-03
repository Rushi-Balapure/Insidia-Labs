"""Each valid cell fails until the phase that owns it ships a scanner."""

from __future__ import annotations

import pytest

from tests.harness.run_cell import run_cell
from tests.harness.score import golden_dropped, meets_threshold, score_findings
from tests.matrix.plants import plant_for
from tests.matrix.registry import Cell, valid_cells


def _parameters() -> list[object]:
    parameters: list[object] = []
    for cell in valid_cells():
        marks = [getattr(pytest.mark, name) for name in cell.marker_names()]
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
