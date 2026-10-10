"""Normalize probe hits. Several engines can report one location. They do not confirm each other."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, replace

from insidia.mask import mask
from insidia.probes import ProbeHit

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})


@dataclass(frozen=True)
class Observation:
    engine: str
    probe: str
    severity: str
    location: str


@dataclass(frozen=True)
class Finding:
    track: str
    engine: str
    probe: str
    severity: str
    confidence: str
    attack: str
    response: str
    trace_ref: str
    taxonomy: tuple[str, ...]
    remediation: str
    evidence_hash: str
    cross_validated: bool
    target: str
    engines: tuple[str, ...] = ()
    location: str = ""
    observations: tuple[Observation, ...] = ()

    def as_json(self) -> dict[str, object]:
        document = asdict(self)
        document["taxonomy"] = list(self.taxonomy)
        document["engines"] = list(self.engines)
        document["observations"] = [asdict(item) for item in self.observations]
        document["reported_by"] = len(self.engines) or 1
        return document


def normalize(hits: list[ProbeHit]) -> list[Finding]:
    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    order: list[tuple[str, str, str, str]] = []
    for hit in hits:
        response = _around(mask(hit.response), mask(hit.evidence) if hit.evidence else "")
        severity = hit.severity if hit.severity in _SEVERITIES else "unspecified"
        finding = Finding(
            hit.track,
            hit.engine,
            hit.probe,
            severity,
            hit.confidence,
            hit.family,
            response,
            hit.target,
            hit.taxonomy,
            hit.remediation,
            _evidence_hash(mask(hit.evidence) if hit.evidence else response),
            False,
            hit.target,
            location=hit.location,
            observations=(Observation(hit.engine, hit.probe, severity, hit.location),),
        )
        key = (finding.target, finding.attack, finding.location, finding.evidence_hash)
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(finding)
    merged: list[Finding] = []
    for key in order:
        items = grouped[key]
        names = tuple(dict.fromkeys(item.engine for item in items))
        observations = tuple(item.observations[0] for item in items)
        finding = replace(items[0], engines=names, observations=observations)
        merged.append(finding)
    return merged


def _around(text: str, needle: str) -> str:
    """Keep the matched evidence even when it is past the first 500 characters."""

    if not needle:
        return text[:500]
    at = text.find(needle)
    if at < 0:
        return text[:500]
    start = max(0, at - 120)
    end = min(len(text), at + len(needle) + 120)
    return text[start:end]


def _evidence_hash(text: str) -> str:
    folded = " ".join(text.split()).lower()
    return hashlib.sha256(folded.encode()).hexdigest()
