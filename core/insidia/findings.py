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

    def as_json(self) -> dict[str, object]:
        document = asdict(self)
        document["taxonomy"] = list(self.taxonomy)
        return document


def normalize(hits: list[ProbeHit]) -> list[Finding]:
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    order: list[tuple[str, str, str]] = []
    for hit in hits:
        response = mask(hit.response)[:500]
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
            _evidence_hash(response),
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
        finding = items[0]
        engines = {item.engine for item in items}
        if len(engines) >= 2:
            finding = replace(finding, cross_validated=True, confidence="high")
        merged.append(finding)
    return merged


def _evidence_hash(text: str) -> str:
    folded = " ".join(text.split()).lower()
    return hashlib.sha256(folded.encode()).hexdigest()
