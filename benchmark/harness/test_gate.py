"""A phase cannot exit while a cell it owns is still xfail."""

from benchmark.harness.gate import still_red
from benchmark.matrix.registry import valid_cells


def test_xfailed_owned_cell_blocks_the_phase() -> None:
    cells = valid_cells()
    sample = next(cell for cell in cells if cell.phase == "1B")
    outcomes = {cell.cell_id: "passed" for cell in cells if cell.phase == "1B"}
    outcomes[sample.cell_id] = "xfailed"
    blocked = still_red("1B", cells, outcomes)
    assert blocked == (sample.cell_id,)


def test_other_phases_do_not_block() -> None:
    cells = valid_cells()
    outcomes = {cell.cell_id: "xfailed" for cell in cells}
    assert still_red("1B", cells, {cell.cell_id: "passed" for cell in cells}) == ()
    # 1D formats results. It does not own scanner cells.
    assert still_red("1D", cells, outcomes) == ()
