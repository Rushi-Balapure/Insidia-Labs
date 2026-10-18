"""Normalize probe hits. Several engines can report one location. They do not confirm each other."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, replace
from urllib.parse import urlparse

from insidia.mask import mask
from insidia.policy import MARKDOWN_BEACON, fallback_check_id
from insidia.probes import ProbeHit
from insidia.score import control_for, risk_assessment, severity_rank

# findings.json stays a JSON array so existing readers keep working.
# 2.1 adds check_id, title, synopsis, description, references, cve,
# risk_score, risk_factors, and (when the scan knows them) endpoint and target_kind.
FINDINGS_SCHEMA = "2.1"

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational", "info"})


@dataclass(frozen=True)
class Observation:
    engine: str
    probe: str
    severity: str
    location: str
    evidence: str = ""


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
    check_id: str = ""
    title: str = ""
    synopsis: str = ""
    description: str = ""
    references: tuple[str, ...] = ()
    risk_score: float = 0.0
    risk_factors: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    endpoint: str = ""
    target_kind: str = ""

    def as_json(self) -> dict[str, object]:
        document = asdict(self)
        document["schema_version"] = FINDINGS_SCHEMA
        document["taxonomy"] = list(self.taxonomy)
        document["engines"] = list(self.engines)
        document["observations"] = [asdict(item) for item in self.observations]
        document["references"] = list(self.references)
        document["risk_factors"] = list(self.risk_factors)
        document["cve"] = list(self.cve)
        document["risk_score"] = self.risk_score
        document["reported_by"] = len(self.engines) or 1
        return document


def canonical_severity(severity: str) -> str:
    """`info` is an alias of `informational`. Anything else unknown stays unspecified."""
    folded = severity.strip().lower()
    if folded == "info":
        return "informational"
    if folded in _SEVERITIES:
        return folded
    return "unspecified"


def normalize(hits: list[ProbeHit]) -> list[Finding]:
    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    order: list[tuple[str, str, str, str]] = []
    for hit in hits:
        response = _around(mask(hit.response), mask(hit.evidence) if hit.evidence else "")
        severity = canonical_severity(hit.severity)
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
            _evidence_hash(_evidence_key(hit, response)),
            False,
            hit.target,
            location=hit.location,
            observations=(
                Observation(
                    hit.engine,
                    hit.probe,
                    severity,
                    hit.location,
                    mask(hit.evidence) if hit.evidence else "",
                ),
            ),
            check_id=hit.check_id,
            title=hit.title,
            synopsis=hit.synopsis,
            description=hit.description,
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
        finding = score_finding(
            replace(items[0], engines=names, observations=observations)
        )
        merged.append(finding)
    return sorted(merged, key=_order)


def prepare_findings(findings: list[Finding]) -> list[Finding]:
    """Score any finding that does not have factors yet, then sort."""
    return sorted((score_finding(item) for item in findings), key=_order)


def score_finding(finding: Finding, *, non_prod: bool = False) -> Finding:
    """Fill catalog text and the Insidia Risk Score. A second call keeps the first score."""
    if finding.risk_factors:
        return finding
    control = control_for(finding.attack)
    evidence = "\n".join(item.evidence for item in finding.observations)
    text = f"{finding.response}\n{evidence}"
    severity, score, factors, cves = risk_assessment(
        finding.attack,
        text,
        finding.confidence,
        len(finding.engines) or 1,
        non_prod=non_prod,
    )
    if finding.severity == "unspecified":
        severity = "unspecified"
    if control is None:
        return replace(
            finding,
            severity=severity,
            check_id=finding.check_id or fallback_check_id(finding.attack),
            title=finding.title or _human_fallback(finding.attack),
            synopsis=finding.synopsis or finding.remediation,
            description=finding.description or finding.remediation,
            risk_score=score,
            risk_factors=factors,
            cve=cves,
        )
    return replace(
        finding,
        severity=severity,
        check_id=finding.check_id or control.check_id,
        title=finding.title or control.title,
        synopsis=finding.synopsis or control.synopsis,
        description=finding.description or control.description,
        references=finding.references or control.references,
        remediation=finding.remediation or control.remediation,
        risk_score=score,
        risk_factors=factors,
        cve=cves,
    )


def _order(finding: Finding) -> tuple[int, float, str, str, str]:
    return (
        severity_rank(finding.severity),
        -finding.risk_score,
        finding.check_id or finding.attack,
        finding.target,
        finding.location,
    )


def _human_fallback(family: str) -> str:
    tail = family.split(".", 1)[-1].replace("_", " ")
    return tail[:1].upper() + tail[1:] if tail else family


def _around(text: str, needle: str) -> str:
    """Keep the matched evidence even when it is past the first 500 characters."""

    if not needle:
        return text[:500]
    at = text.find(needle)
    if at < 0:
        return text[:500]
    start = max(0, at - 80)
    return text[start : start + 500]


def _evidence_key(hit: ProbeHit, response: str) -> str:
    """What makes two hits the same finding.

    A markdown beacon is one finding per target and host+path. The query string
    is not part of that identity, so echoed prompts do not multiply it.
    """
    evidence = mask(hit.evidence) if hit.evidence else ""
    if hit.check_id == MARKDOWN_BEACON.check_id and evidence:
        identity = _beacon_host_path(evidence)
        if identity:
            return identity
    return evidence or response


def _beacon_host_path(url: str) -> str:
    """Host and path of a beacon URL. The query string is ignored."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return ""
    return f"{host}{parsed.path}"


def _evidence_hash(text: str) -> str:
    folded = " ".join(text.split()).lower()
    return hashlib.sha256(folded.encode()).hexdigest()
