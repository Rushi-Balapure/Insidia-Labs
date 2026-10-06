"""Capability registry for the probes this CLI can run."""

from __future__ import annotations

from dataclasses import dataclass

from insidia.errors import ConfigError

KNOWN_ENGINES: tuple[tuple[str, str], ...] = (
    ("insidia", "Apache-2.0"),
    ("garak", "Apache-2.0"),
    ("promptfoo", "MIT"),
    ("pyrit", "MIT"),
    ("deepteam", "Apache-2.0"),
    ("mcp-scanner", "Apache-2.0"),
    ("skillspector", "Apache-2.0"),
    ("zap", "Apache-2.0"),
    ("nuclei", "MIT"),
    ("dalfox", "MIT"),
    ("trivy", "Apache-2.0"),
    ("osv-scanner", "Apache-2.0"),
    ("gitleaks", "MIT"),
    ("bandit", "Apache-2.0"),
    ("gosec", "Apache-2.0"),
)


@dataclass(frozen=True)
class Capability:
    family: str
    engine: str
    probe: str
    priority: int
    requires_model: bool
    available: bool


BUILT_IN: tuple[Capability, ...] = (
    Capability("ai.data_leakage", "insidia", "insidia.ai.data_leakage", 100, False, True),
    Capability("web.ssti", "insidia", "insidia.web.ssti", 100, False, True),
)


def select(
    family: str,
    coverage: str,
    *,
    model_available: bool,
    entries: tuple[Capability, ...] = BUILT_IN,
) -> list[Capability]:
    if coverage not in {"standard", "thorough"}:
        raise ConfigError("coverage must be standard or thorough")
    usable = [
        entry
        for entry in entries
        if entry.family == family
        and entry.available
        and (model_available or not entry.requires_model)
    ]
    usable.sort(key=lambda entry: entry.priority, reverse=True)
    if coverage == "standard":
        return usable[:1]
    return usable
