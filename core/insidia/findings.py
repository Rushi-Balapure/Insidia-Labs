"""Normalize probe hits into findings and merge cross-engine duplicates."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, replace

from insidia.mask import mask
from insidia.probes import ProbeHit


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

    def as_json(self) -> dict[str, object]:
        document = asdict(self)
        document["taxonomy"] = list(self.taxonomy)
        document["engines"] = list(self.engines)
        return document


def normalize(hits: list[ProbeHit]) -> list[Finding]:
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    order: list[tuple[str, str, str]] = []
    for hit in hits:
        response = _around(mask(hit.response), mask(hit.evidence) if hit.evidence else "")
        finding = Finding(
            hit.track,
            hit.engine,
            hit.probe,
            hit.severity,
            hit.confidence,
            hit.family,
            response,
            hit.target,
            hit.taxonomy,
            hit.remediation,
            _evidence_hash(mask(hit.evidence) if hit.evidence else response),
            False,
            hit.target,
        )
        key = (finding.target, finding.attack, finding.evidence_hash)
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(finding)
    merged: list[Finding] = []
    for key in order:
        items = grouped[key]
        names = tuple(dict.fromkeys(item.engine for item in items))
        cross = len(set(names)) >= 2
        finding = replace(
            items[0],
            cross_validated=cross,
            confidence="high" if cross else items[0].confidence,
            engines=names,
        )
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
