"""Build the cell registry from the validity function and the plant catalog."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from benchmark.matrix.ownership import owning_phase
from benchmark.matrix.plants import assign_target, plant_for
from benchmark.matrix.validity import (
    DEFAULT_PRECISION,
    FOCUSED_RECALL,
    is_valid,
    iter_combinations,
)


@dataclass(frozen=True)
class Cell:
    connector: str
    box: str
    attack: str
    conn: str
    valid: bool
    reason: str
    phase: str
    target: str
    plant_ids: tuple[str, ...]
    recall_floor: float
    precision_floor: float

    @property
    def cell_id(self) -> str:
        return f"{self.connector}|{self.box}|{self.attack}|{self.conn}"

    def marker_names(self) -> tuple[str, ...]:
        box = {"black": "blackbox", "gray": "graybox", "white": "whitebox"}[self.box]
        attack = self.attack.split(".", 1)[1]
        return (
            f"connector_{self.connector}",
            box,
            attack,
            self.conn,
        )


def build_cells() -> tuple[Cell, ...]:
    cells: list[Cell] = []
    for connector, box, attack, conn in iter_combinations():
        valid, reason = is_valid(connector, box, attack, conn)
        if not valid:
            cells.append(
                Cell(
                    connector, box, attack, conn, False, reason, "", "", (), 0.0, 0.0
                )
            )
            continue
        target = assign_target(connector, attack)
        plant = plant_for(target, attack)
        plant_ids = (plant.id,)
        recall = FOCUSED_RECALL if len(plant_ids) == 1 else 0.80
        cells.append(
            Cell(
                connector,
                box,
                attack,
                conn,
                True,
                reason,
                owning_phase(connector, box, attack),
                target,
                plant_ids,
                recall,
                DEFAULT_PRECISION,
            )
        )
    return tuple(cells)


def valid_cells(cells: tuple[Cell, ...] | None = None) -> tuple[Cell, ...]:
    source = build_cells() if cells is None else cells
    return tuple(cell for cell in source if cell.valid)


def cell_dict(cell: Cell) -> dict[str, object]:
    payload = asdict(cell)
    payload["plant_ids"] = list(cell.plant_ids)
    payload["id"] = cell.cell_id
    return payload
