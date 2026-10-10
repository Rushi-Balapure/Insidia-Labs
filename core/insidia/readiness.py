"""What the current CLI can claim. Fixture checks are not verified detectors.

Phase 1F records a disposition for every policy family, catalog engine, and
review finding. Promoting a row to verified is a later package, not a rename.
"""

from __future__ import annotations

from dataclasses import dataclass

from insidia.catalog import SPECS
from insidia.policy import POLICIES

# These catalog families have no policy path, so a scan cannot select them.
UNSCHEDULED_FAMILIES = (
    "code.go",
    "code.mcp",
    "code.python",
    "code.skills",
    "deps.osv",
)

# Named in public copy before a capability existed. They stay absent until F21.
ABSENT_CAPABILITIES = ("web.sqli", "web.xss")


@dataclass(frozen=True)
class Disposition:
    name: str
    kind: str
    readiness: str
    owner: str
    evidence: str


@dataclass(frozen=True)
class ReviewItem:
    """One finding from the 10 October 2026 review."""

    item_id: str
    owner: str
    gate: str
    requirement: str


REVIEW: tuple[ReviewItem, ...] = (
    ReviewItem("R1", "F02", "regression", "An unauthorized target cannot pass."),
    ReviewItem("R2", "F08", "regression", "The price-49 response is not a detection."),
    ReviewItem("R3", "F10", "implementation", "Score the released CLI, not the harness answer."),
    ReviewItem("R4", "F07", "implementation", "Installed engines are not selected checks."),
    ReviewItem("R5", "F01", "regression", "A failed engine cannot hide behind an empty result."),
    ReviewItem("R6", "F03", "implementation", "Share rate, concurrency, and scope."),
    ReviewItem("R7", "F11", "implementation", "Name the framework edition."),
    ReviewItem("R8", "F12", "implementation", "MCP uses newline-delimited JSON-RPC."),
    ReviewItem("R9", "F06", "implementation", "Keep location, evidence, and engine lineage."),
    ReviewItem("R10", "F04", "implementation", "Redact secrets and unfinished reports."),
    ReviewItem("R11", "F13", "implementation", "Install paths match the documented platforms."),
    ReviewItem("R12", "F16", "implementation", "The first-use docs resolve to a real example."),
)


def inventory() -> tuple[Disposition, ...]:
    """Every current family and engine. Nothing is dropped by omission."""

    rows: list[Disposition] = []
    for control in POLICIES["L1"].controls:
        rows.append(
            Disposition(
                control.family,
                "family",
                "fixture-only",
                "F08",
                "Built-in oracle or upstream adapter. Not an independent detector.",
            )
        )
    for family in UNSCHEDULED_FAMILIES:
        rows.append(
            Disposition(
                family,
                "family",
                "unsupported",
                "F07",
                "Present on a catalog engine and absent from the policy.",
            )
        )
    for name in ABSENT_CAPABILITIES:
        rows.append(
            Disposition(
                name,
                "capability",
                "unsupported",
                "F21",
                "Described in public copy. No policy family selects it.",
            )
        )
    seen: set[str] = set()
    for spec in SPECS:
        if spec.name in seen:
            continue
        seen.add(spec.name)
        rows.append(
            Disposition(
                spec.name,
                "engine",
                "experimental",
                "F09",
                f"Pinned {spec.name} {spec.version}. Selection does not prove a native check ran.",
            )
        )
    return tuple(rows)
