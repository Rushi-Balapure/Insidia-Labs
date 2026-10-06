"""Capability registry for the probes this CLI can run."""

from __future__ import annotations

from dataclasses import dataclass

from insidia.adapters import ADAPTERS
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
    ("katana", "MIT"),
    ("httpx", "MIT"),
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


def capabilities() -> tuple[Capability, ...]:
    """Availability is read when the scan runs, not when this module is imported."""
    from insidia.engines import installed_engines

    installed = installed_engines()
    return tuple(
        Capability(
            spec.family,
            adapter.engine,
            spec.probe,
            spec.priority,
            spec.requires_model,
            adapter.engine == "insidia" or adapter.engine in installed,
        )
        for adapter in ADAPTERS
        for spec in adapter.probes
    )


def select(
    family: str,
    coverage: str,
    *,
    model_available: bool,
    entries: tuple[Capability, ...] | None = None,
) -> list[Capability]:
    if coverage not in {"standard", "thorough"}:
        raise ConfigError("coverage must be standard or thorough")
    pool = capabilities() if entries is None else entries
    usable = [
        entry
        for entry in pool
        if entry.family == family
        and entry.available
        and (model_available or not entry.requires_model)
    ]
    usable.sort(key=lambda entry: entry.priority, reverse=True)
    if coverage == "standard":
        return usable[:1]
    return usable
