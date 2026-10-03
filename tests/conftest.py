"""Register matrix markers so a phase can select its slice."""

from __future__ import annotations

from tests.matrix.registry import valid_cells


def pytest_configure(config: object) -> None:
    names: set[str] = set()
    for cell in valid_cells():
        names.update(cell.marker_names())
    add = config.addinivalue_line
    for name in sorted(names):
        add("markers", f"{name}: permutation matrix dimension")
