"""The registry covers the full cross-product and matches the files on disk."""

from __future__ import annotations

import importlib
from pathlib import Path

from benchmark.matrix.cells import main
from benchmark.matrix.ownership import OWNING_PHASES
from benchmark.matrix.plants import covered_connectors, plant_for
from benchmark.matrix.registry import build_cells, cell_dict, valid_cells
from benchmark.matrix.snapshots import ground_truth_path, load_cells, registry_is_current
from benchmark.matrix.validity import (
    ATTACKS,
    BOXES,
    CONNECTORS,
    CONNS,
    is_valid,
)

REPO = Path(__file__).resolve().parents[2]


def test_dimensions_match_the_plan() -> None:
    assert len(CONNECTORS) == 17
    assert len(ATTACKS) == 44
    assert len(BOXES) == 3
    assert len(CONNS) == 4
    assert covered_connectors() == CONNECTORS


def test_valid_plus_na_is_the_cross_product() -> None:
    cells = build_cells()
    assert len(cells) == 17 * 3 * 44 * 4
    valid = [cell for cell in cells if cell.valid]
    na = [cell for cell in cells if not cell.valid]
    assert len(valid) + len(na) == len(cells)
    assert len({cell.cell_id for cell in cells}) == len(cells)
    assert len(valid) == 1235
    assert len(na) == 7741


def test_flags_match_is_valid_and_na_reasons_are_set() -> None:
    for cell in build_cells():
        ok, reason = is_valid(cell.connector, cell.box, cell.attack, cell.conn)
        assert cell.valid is ok
        assert cell.reason == reason
        if cell.valid:
            assert cell.reason == "valid"
            assert cell.phase in OWNING_PHASES
        else:
            assert cell.reason != "valid"
            assert cell.phase == ""


def test_every_valid_cell_has_one_plant_and_one_owner() -> None:
    phases: dict[str, int] = {}
    for cell in valid_cells():
        assert len(cell.plant_ids) == 1
        plant = plant_for(cell.target, cell.attack)
        assert cell.plant_ids == (plant.id,)
        assert cell.recall_floor == 1.0
        assert cell.precision_floor == 0.9
        phases[cell.phase] = phases.get(cell.phase, 0) + 1
    assert sum(phases.values()) == 1235
    assert set(phases) <= set(OWNING_PHASES)
    assert "1D" not in phases


def test_web_connector_has_96_cells() -> None:
    web = [
        cell
        for cell in valid_cells()
        if cell.connector == "web"
    ]
    assert len(web) == 96


def test_documented_na_reasons() -> None:
    assert is_valid("web", "black", "web.xss", "relay") == (
        False,
        "relay cannot reach web",
    )
    assert is_valid("web", "white", "code.secrets", "tunnel") == (
        False,
        "code.secrets does not apply to web",
    )


def test_committed_registry_matches_the_function() -> None:
    assert registry_is_current()
    assert main(["--check"]) == 0
    assert load_cells() == [cell_dict(cell) for cell in build_cells()]


def test_insidia_plant_functions_exist() -> None:
    seen: set[str] = set()
    for cell in valid_cells():
        plant = plant_for(cell.target, cell.attack)
        if plant.location in seen or ".py:" not in plant.location:
            seen.add(plant.location)
            continue
        seen.add(plant.location)
        relative, function = plant.location.split(":")
        module_name = relative.removesuffix(".py").replace("/", ".")
        module = importlib.import_module(module_name)
        assert hasattr(module, function), plant.location
        path = REPO / relative
        assert path.is_file()
        assert ground_truth_path(cell.target).is_file()
