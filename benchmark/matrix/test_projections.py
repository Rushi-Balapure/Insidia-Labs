"""The tables in the validity-matrix plan are rendered from the code."""

from __future__ import annotations

from pathlib import Path

from benchmark.matrix.validity import (
    ATTACK_CONNECTORS,
    ATTACKS,
    BOX_OVERRIDE,
    CHAT,
    CONN_REACH,
    CONNECTORS,
    is_valid,
    iter_combinations,
)

PLAN = Path(__file__).resolve().parents[2] / "plans" / "18-validity-matrix.md"

_CHAT_COLUMNS = ("chat*", "rag", "agent", "multi_agent", "sdk_inproc", "ml_model")
_CLASSIC_COLUMNS = ("web", "api_rest", "api_graphql", "api_grpc", "api_ws", "codebase")
_CONN_COLUMNS = ("direct", "relay", "tunnel", "sdk_bridge")


def _section(heading: str, following: str) -> str:
    text = PLAN.read_text()
    start = text.index(heading)
    end = text.index(following, start)
    return text[start:end]


def _table(section: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0].startswith("---") or set(cells[0]) <= {"-", ":"}:
            continue
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        rows.append(cells)
    return rows[1:]


def _marked(cell: str) -> bool:
    return cell.strip() == "+"


def test_plan_function_matches_the_module() -> None:
    text = PLAN.read_text()
    block = text.split("```python", 1)[1].split("```", 1)[0]
    namespace: dict[str, object] = {}
    exec(block, namespace)  # noqa: S102
    plan_valid = namespace["is_valid"]
    assert callable(plan_valid)
    for connector, box, attack, conn in iter_combinations():
        assert plan_valid(connector, box, attack, conn) == is_valid(connector, box, attack, conn)


def test_projection_a_ai_by_connector() -> None:
    rows = _table(_section("## Projection A", "## Projection B"))
    assert [row[0] for row in rows] == [attack.removeprefix("ai.") for attack in ATTACKS[:24]]
    for row in rows:
        attack = f"ai.{row[0]}"
        allowed = ATTACK_CONNECTORS[attack]
        expected = [
            CHAT <= allowed,
            "rag" in allowed,
            "agent" in allowed,
            "multi_agent" in allowed,
            "sdk_inproc" in allowed,
            "ml_model" in allowed,
        ]
        assert [_marked(cell) for cell in row[1:]] == expected


def test_projection_b_classic_by_connector() -> None:
    rows = _table(_section("## Projection B", "## Projection C"))
    classic = [attack for attack in ATTACKS if not attack.startswith("ai.")]
    assert [row[0] for row in rows] == classic
    for row in rows:
        allowed = ATTACK_CONNECTORS[row[0]]
        expected = [column in allowed for column in _CLASSIC_COLUMNS]
        assert [_marked(cell) for cell in row[1:]] == expected


def test_projection_c_connector_by_connection() -> None:
    rows = _table(_section("## Projection C", "## Projection D"))
    labels = [row[0] for row in rows]
    assert labels[0] == "chat*"
    for row in rows:
        label = row[0]
        members = CHAT if label == "chat*" else {label}
        assert members <= CONNECTORS
        expected = []
        for conn in _CONN_COLUMNS:
            expected.append(members <= CONN_REACH[conn])
        assert [_marked(cell) for cell in row[1:]] == expected


def test_projection_d_box_overrides() -> None:
    section = _section("## Projection D", "## Worked example")
    assert "code.sast_sinks, code.secrets, deps.sca" in section
    assert "ai.embedding_inversion, ai.supply_chain" in section
    assert "ai.predictive_ml" in section
    assert BOX_OVERRIDE["code.sast_sinks"] == {"white"}
    assert BOX_OVERRIDE["code.secrets"] == {"white"}
    assert BOX_OVERRIDE["deps.sca"] == {"white"}
    assert BOX_OVERRIDE["ai.embedding_inversion"] == {"gray", "white"}
    assert BOX_OVERRIDE["ai.supply_chain"] == {"gray", "white"}
    assert BOX_OVERRIDE["ai.predictive_ml"] == {"black", "white"}
    untouched = set(ATTACKS) - set(BOX_OVERRIDE)
    assert untouched
    for attack in untouched:
        assert is_valid(
            next(iter(ATTACK_CONNECTORS[attack])),
            "black",
            attack,
            "direct",
        )[1] != f"{attack} runs only in {sorted(BOX_OVERRIDE.get(attack, []))}"
