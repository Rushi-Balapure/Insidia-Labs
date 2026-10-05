"""Write and reload the generated registry files."""

from __future__ import annotations

from pathlib import Path

import yaml

from benchmark.matrix.plants import Plant, plants_by_target
from benchmark.matrix.registry import Cell, build_cells, cell_dict, valid_cells

ROOT = Path(__file__).resolve().parents[2]
CELLS_PATH = Path(__file__).with_name("cells.yaml")
OWNERSHIP_PATH = Path(__file__).with_name("ownership.yaml")
GOLDEN_PATH = ROOT / "benchmark" / "golden" / "expected.yaml"
TARGETS = ROOT / "benchmark" / "targets"


def dump_registry(cells: tuple[Cell, ...] | None = None) -> None:
    source = build_cells() if cells is None else cells
    CELLS_PATH.write_text(
        yaml.safe_dump(
            [cell_dict(cell) for cell in source],
            sort_keys=False,
        )
    )
    owned = valid_cells(source)
    counts: dict[str, int] = {}
    assignments = []
    golden: dict[str, list[str]] = {}
    for cell in owned:
        counts[cell.phase] = counts.get(cell.phase, 0) + 1
        assignments.append({"id": cell.cell_id, "phase": cell.phase})
        golden[cell.cell_id] = list(cell.plant_ids)
    OWNERSHIP_PATH.write_text(
        yaml.safe_dump(
            {"counts": counts, "assignments": assignments},
            sort_keys=False,
        )
    )
    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(yaml.safe_dump(golden, sort_keys=True))
    pairs = {(cell.connector, cell.attack) for cell in owned}
    for target, plants in plants_by_target(pairs).items():
        path = ground_truth_path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump([_plant_dict(plant) for plant in plants], sort_keys=False))


def ground_truth_path(target: str) -> Path:
    if target.startswith("insidia-"):
        name = target.removeprefix("insidia-")
        return TARGETS / "insidia" / "ground_truth" / f"{name}.yaml"
    return TARGETS / target / "ground_truth.yaml"


def registry_is_current(cells: tuple[Cell, ...] | None = None) -> bool:
    source = build_cells() if cells is None else cells
    if not CELLS_PATH.is_file() or load_cells() != [cell_dict(cell) for cell in source]:
        return False
    if not OWNERSHIP_PATH.is_file() or not GOLDEN_PATH.is_file():
        return False
    owned = valid_cells(source)
    ownership = yaml.safe_load(OWNERSHIP_PATH.read_text())
    golden = yaml.safe_load(GOLDEN_PATH.read_text())
    assignments = [{"id": cell.cell_id, "phase": cell.phase} for cell in owned]
    if ownership.get("assignments") != assignments:
        return False
    if golden != {cell.cell_id: list(cell.plant_ids) for cell in owned}:
        return False
    pairs = {(cell.connector, cell.attack) for cell in owned}
    for target, plants in plants_by_target(pairs).items():
        path = ground_truth_path(target)
        if not path.is_file():
            return False
        if yaml.safe_load(path.read_text()) != [_plant_dict(plant) for plant in plants]:
            return False
    return True


def load_cells() -> list[dict[str, object]]:
    loaded = yaml.safe_load(CELLS_PATH.read_text())
    if not isinstance(loaded, list):
        raise TypeError("cells.yaml is not a list")
    return loaded


def _plant_dict(plant: Plant) -> dict[str, object]:
    return {
        "id": plant.id,
        "attack": plant.attack,
        "location": plant.location,
        "probe_id": plant.probe_id,
        "taxonomy_id": plant.taxonomy_id,
        "severity": plant.severity,
        "oracle": plant.oracle,
    }


