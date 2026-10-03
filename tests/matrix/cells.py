"""Command line for the permutation registry.

    python -m tests.matrix.cells --count
    python -m tests.matrix.cells --explain-na
    python -m tests.matrix.cells --write
    python -m tests.matrix.cells --check
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from tests.matrix.registry import build_cells, valid_cells
from tests.matrix.snapshots import dump_registry, registry_is_current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Permutation matrix registry")
    parser.add_argument("--count", action="store_true")
    parser.add_argument("--explain-na", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    cells = build_cells()
    owned = valid_cells(cells)
    if args.write:
        dump_registry(cells)
    if args.check and not registry_is_current(cells):
        print("matrix registry files do not match the validity function", file=sys.stderr)
        return 1
    if args.count or not any((args.explain_na, args.write, args.check)):
        counts = Counter(cell.phase for cell in owned)
        print(f"valid {len(owned)}")
        print(f"na {len(cells) - len(owned)}")
        for phase, count in sorted(counts.items()):
            print(f"phase {phase} {count}")
    if args.explain_na:
        for cell in cells:
            if not cell.valid:
                print(f"{cell.cell_id} {cell.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
