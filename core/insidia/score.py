"""Score scan controls against the four OWASP framework maps."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml  # type: ignore[import-untyped]

# Shipped inside the package so `uv tool install` of core/ can score a scan.
# benchmark/mappings/ is the repo copy. test_packaging keeps the two identical.
_MAP_DIR = Path(__file__).resolve().parent / "mappings"
_FILES = (
    "owasp-llm-2026.yaml",
    "owasp-asi-2026.yaml",
    "owasp-web.yaml",
    "owasp-api.yaml",
)


@dataclass(frozen=True)
class Framework:
    name: str
    title: str
    items: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Score:
    framework: str
    title: str
    failed: int
    passed: int
    not_tested: int


def score_frameworks(controls: list[dict[str, str]]) -> tuple[Score, ...]:
    frameworks = _frameworks()
    _reject_unknown(controls, frameworks)
    return tuple(_score(framework, controls) for framework in frameworks)


def coverage(controls: list[dict[str, str]]) -> tuple[tuple[str, str, str], ...]:
    """One row per framework item: id, title, and fail, pass, or not tested."""
    frameworks = _frameworks()
    _reject_unknown(controls, frameworks)
    rows: list[tuple[str, str, str]] = []
    for framework in frameworks:
        ids = {item_id for item_id, _title in framework.items}
        failed, passed = _split(framework, controls, ids)
        for item_id, title in framework.items:
            if item_id in failed:
                result = "fail"
            elif item_id in passed:
                result = "pass"
            else:
                result = "not tested"
            rows.append((f"{framework.name}:{item_id}", title, result))
    return tuple(rows)


def _frameworks() -> tuple[Framework, ...]:
    return tuple(_load(name) for name in _FILES)


def _load(filename: str) -> Framework:
    loaded = yaml.safe_load((_MAP_DIR / filename).read_text())
    if not isinstance(loaded, dict):
        raise ValueError(f"{filename} must be a mapping")
    name = loaded.get("framework")
    title = loaded.get("title")
    raw_items = loaded.get("items")
    if not isinstance(name, str) or not isinstance(title, str) or not isinstance(raw_items, list):
        raise ValueError(f"{filename} needs framework, title, and items")
    items: list[tuple[str, str]] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise ValueError(f"{filename} has an item that is not a mapping")
        item_id = raw.get("id")
        item_title = raw.get("title")
        if not isinstance(item_id, str) or not isinstance(item_title, str):
            raise ValueError(f"{filename} items need a string id and title")
        items.append((item_id, item_title))
    return Framework(name, title, tuple(items))


def _score(framework: Framework, controls: list[dict[str, str]]) -> Score:
    ids = {item_id for item_id, _title in framework.items}
    failed, passed = _split(framework, controls, ids)
    not_tested = len(ids - failed - passed)
    return Score(framework.name, framework.title, len(failed), len(passed), not_tested)


def _split(
    framework: Framework, controls: list[dict[str, str]], ids: set[str]
) -> tuple[set[str], set[str]]:
    failed: set[str] = set()
    passed: set[str] = set()
    prefix = f"{framework.name}:"
    for control in controls:
        result = control.get("result", "")
        for tag in control.get("taxonomy", "").split(","):
            item_id = _item_id(tag, prefix, ids)
            if item_id is None:
                continue
            if result == "fail":
                failed.add(item_id)
            elif result == "pass":
                passed.add(item_id)
    passed -= failed
    return failed, passed


def _reject_unknown(controls: list[dict[str, str]], frameworks: tuple[Framework, ...]) -> None:
    known = {
        framework.name: {item_id for item_id, _title in framework.items} for framework in frameworks
    }
    for control in controls:
        for tag in control.get("taxonomy", "").split(","):
            cleaned = tag.strip()
            prefix, sep, item_id = cleaned.partition(":")
            if sep != ":" or prefix not in known:
                continue
            if item_id not in known[prefix]:
                raise ValueError(f"unknown taxonomy id {cleaned}")


def _item_id(tag: str, prefix: str, ids: set[str]) -> str | None:
    cleaned = tag.strip()
    if not cleaned.startswith(prefix):
        return None
    item_id = cleaned.removeprefix(prefix)
    if item_id not in ids:
        return None
    return item_id
