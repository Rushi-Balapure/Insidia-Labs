"""Built-in probes. Each one names the insidia engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from insidia.config import Project, Target
from insidia.errors import CliError
from insidia.policy import Control
from insidia.registry import Capability
from insidia.transport import exchange

CANARY_PREFIX = "insidia-plant-canary-"
_SSTI_PAYLOAD = "{{7*7}}"


@dataclass(frozen=True)
class ProbeHit:
    target: str
    family: str
    engine: str
    probe: str
    response: str
    severity: str
    confidence: str
    track: str
    taxonomy: tuple[str, ...]
    remediation: str


def run(
    capability: Capability,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
) -> ProbeHit | None:
    if capability.probe == "insidia.ai.data_leakage":
        observed = exchange(target, "secret", project.scope, root)
        marker = target.canary or CANARY_PREFIX
        if marker not in observed:
            return None
    elif capability.probe == "insidia.web.ssti":
        observed = exchange(target, _SSTI_PAYLOAD, project.scope, root)
        if "49" not in observed or _SSTI_PAYLOAD in observed:
            return None
    else:
        raise CliError(f"unknown probe {capability.probe}")
    return ProbeHit(
        target.name,
        capability.family,
        capability.engine,
        capability.probe,
        observed,
        control.severity,
        "high",
        control.track,
        control.taxonomy,
        control.remediation,
    )
