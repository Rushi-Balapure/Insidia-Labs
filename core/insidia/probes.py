"""Run one probe through its engine adapter. The adapter value names the engine."""

from __future__ import annotations

import contextvars
import hmac
import json
import random
import re
import secrets
import socket
import ssl
import tempfile
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TypeGuard
from urllib.parse import urlparse

from insidia import repo_scan
from insidia.adapters import (
    FIXTURE_ONLY,
    ORACLES,
    SENSITIVE_FIELDS,
    Adapter,
    BuiltIn,
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RelayEndpoint,
    RepoPath,
    ReportAdapter,
    ScopedUrl,
    has_standalone,
    markdown_beacon,
)
from insidia.config import Project, Target, resolve_secret
from insidia.errors import (
    CliError,
    ConfigError,
    EngineFailed,
    HttpStatus,
    ProbeError,
    ScopeError,
)
from insidia.policy import MARKDOWN_BEACON, Control, get_policy
from insidia.process import launch_installed
from insidia.scope import ScopeHost, check_url
from insidia.transport import (
    AI_KINDS,
    BoundBudget,
    RateLimiter,
    carries_payload,
    current_budget,
    exchange,
    fetch,
    fetch_target,
    repo_path,
)

Launch = Callable[[Invocation, Path], None]


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
    upstream: str = ""
    evidence: str = ""
    location: str = ""
    check_id: str = ""
    title: str = ""
    synopsis: str = ""
    description: str = ""


@dataclass(frozen=True)
class Attempt:
    """Observations from one engine, plus an error if that engine did not finish."""

    hits: tuple[ProbeHit, ...] = ()
    error: str = ""
    # The engine finished but could not test this target, for example TLS over plain HTTP.
    untested: str = ""
    # Payloads or prompts handed to the target, and HTTP requests made for them.
    probes: int = 0
    requests: int = 0
    # Files, manifests, or dependencies a repository check read. Not a payload total.
    counted: int = 0
    unit: str = ""
    # A finished observation that is not a pass and not a finding. Banner gaps use this.
    info: str = ""


# Shared list so a worker thread can record a payload the scan thread totals.
_probe_tally: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar(
    "insidia_probe_tally", default=None
)
_probe_tally_lock = threading.Lock()


def _count_bucket(bucket: list[int] | None) -> None:
    if bucket is None:
        return
    with _probe_tally_lock:
        bucket[0] += 1


def _count_probe() -> None:
    _count_bucket(_probe_tally.get())


def _bound_limiter(target: Target) -> RateLimiter | None:
    table = current_budget()
    if table is None or target.name not in table:
        return None
    return table[target.name][0]


def _request_count(target: Target) -> int:
    limiter = _bound_limiter(target)
    return 0 if limiter is None else limiter.sent


def _probe_hit(
    spec: ProbeSpec,
    target_name: str,
    engine: str,
    control: Control,
    hit: EngineHit,
) -> ProbeHit:
    """One engine observation. A markdown beacon keeps its own title on this family."""
    chosen = control
    if hit.family and hit.family != spec.family:
        chosen = get_policy("L1").control(hit.family)
    return ProbeHit(
        target_name,
        hit.family or spec.family,
        engine,
        hit.probe or spec.probe,
        hit.response,
        hit.severity or chosen.severity,
        hit.confidence or "high",
        chosen.track,
        chosen.taxonomy,
        hit.remediation or chosen.remediation,
        hit.upstream,
        hit.evidence,
        hit.location,
        check_id=hit.check_id,
        title=hit.title,
        synopsis=hit.synopsis,
        description=hit.description,
    )


# Distinct from the active-HTML probe so SARIF can describe the beacon on its own.
_BEACON_PROBE = "insidia.ai.output_handling_sinks.markdown_beacon"


def _judge_reply(
    spec: ProbeSpec,
    payload: str,
    outcome: str,
    target: Target,
    evidence: str | None,
) -> list[EngineHit]:
    """The family oracle, plus a markdown beacon on any chat-style reply.

    The beacon belongs to output handling, not to the family that received the
    reply. The URL is recorded and not requested.
    """
    found: list[EngineHit] = []
    if evidence is not None:
        found.append(EngineHit(spec.upstream, payload, outcome, evidence))
    if target.kind not in AI_KINDS:
        return found
    url = markdown_beacon(payload, outcome, target)
    if url is None:
        return found
    copy = MARKDOWN_BEACON
    found.append(
        EngineHit(
            spec.upstream,
            payload,
            outcome,
            url,
            family=copy.family,
            probe=_BEACON_PROBE,
            check_id=copy.check_id,
            title=copy.title,
            synopsis=copy.synopsis,
            description=copy.description,
            remediation=copy.remediation,
        )
    )
    return found


def run(
    adapter: Adapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    control: Control,
    launch: Launch = launch_installed,
) -> Attempt:
    if target.kind not in spec.target_kinds:
        return Attempt()
    if _payload_cannot_land(target, spec.family):
        return Attempt(untested=_NO_PAYLOAD)
    bucket = [0]
    token = _probe_tally.set(bucket)
    before = _request_count(target)
    try:
        untested = ""
        counted = 0
        unit = ""
        match adapter:
            case BuiltIn() if target.kind == "repo":
                found, untested, counted, unit = _judge_repo(spec, target, root)
                error = ""
            case BuiltIn():
                found, error, untested = _judge(adapter, spec, target, project.scope, root)
            case RelayAdapter():
                found, error, untested = _relay(adapter, spec, target, project, root, launch)
            case ReportAdapter() if _over_url(adapter):
                found, error = _report(adapter, spec, _scoped_url(target, project.scope), launch)
            case ReportAdapter() if _over_repo(adapter):
                found, error = _report(adapter, spec, RepoPath(repo_path(target, root)), launch)
            case _:
                raise CliError(f"{adapter.engine}: no adapter arm")
        hits = tuple(_probe_hit(spec, target.name, adapter.engine, control, hit) for hit in found)
        # Only this family's hits clear a miss-only note. A markdown beacon is
        # output handling's finding, even when another family's reply carried it.
        # A relay under the prompt minimum stays limited.
        owned = tuple(hit for hit in hits if hit.family == spec.family)
        if owned and not _is_relay_shallow_note(untested):
            untested = ""
        info = ""
        if untested.startswith(_BANNER_GAP_MARK):
            info = untested.removeprefix(_BANNER_GAP_MARK)
            untested = ""
        sent = _request_count(target) - before
        return Attempt(
            hits,
            error,
            untested,
            bucket[0],
            sent if sent > 0 else 0,
            counted,
            unit,
            info,
        )
    finally:
        _probe_tally.reset(token)


_FIXTURE_ONLY_NOTE = "this check only recognises Insidia's benchmark app"
# A judge is the only oracle that could score these on a real app. L1 does not call one.
_JUDGE_ONLY = frozenset(
    {
        "ai.harmful_content_policy",
        "ai.bias",
        "ai.citation_groundedness",
    }
)
_JUDGE_UNUSED_NOTE = "this coverage does not call the judge"
# Fewer prompts than this is a smoke test, not coverage of the family.
_RELAY_MIN_PROMPTS = 3
_SHALLOW_NOTE = " sent only "
_SHALLOW_TAIL = " prompt(s)"
_NO_PAYLOAD = (
    "no {{payload}} placeholder in url, query, or body, "
    "so every probe sent the same request"
)
# Banner and handshake checks read the server itself. They do not inject a payload.
_PAYLOAD_FREE = frozenset({"infra.cve", "infra.tls"})

_REPO_CHECKS = {
    "code.sast_sinks": repo_scan.sinks,
    "code.secrets": repo_scan.secrets,
    "deps.sca": repo_scan.dependencies,
}


def _payload_cannot_land(target: Target, family: str) -> bool:
    """True when every payload would build the same request, so the check cannot run."""
    if target.kind == "repo" or family in _PAYLOAD_FREE or target.url is None:
        return False
    return not carries_payload(target)


def _relay_shallow_note(engine: str, sent: int) -> str:
    """Why a relay that sent too few prompts did not cover the family."""
    return f"{engine}{_SHALLOW_NOTE}{sent}{_SHALLOW_TAIL}"


def _is_relay_shallow_note(note: str) -> bool:
    engine, marker, rest = note.partition(_SHALLOW_NOTE)
    if not engine or not marker or not rest.endswith(_SHALLOW_TAIL):
        return False
    return rest.removesuffix(_SHALLOW_TAIL).isdigit()


def _untested_note(family: str) -> str:
    """Why a fixture-only miss is not a pass. Judge-only families name the unused judge."""
    if family in _JUDGE_ONLY:
        return _JUDGE_UNUSED_NOTE
    return _FIXTURE_ONLY_NOTE


def _judge(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Hits, an error if the check did not finish, and why nothing could be tested."""
    if target.kind == "repo":
        hits, untested, _counted, _unit = _judge_repo(spec, target, root)
        return hits, "", untested
    paired = _PAIRED.get(spec.family)
    if paired is not None:
        return paired(target, scope, root)
    hits, error = _corpus(adapter, spec, target, scope, root)
    if spec.family in FIXTURE_ONLY:
        # A matching plant is still a finding. The note only explains a miss.
        return hits, error, _untested_note(spec.family)
    return hits, error, ""


def _corpus(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str]:
    oracle = ORACLES[spec.family]
    payloads = adapter.corpus[spec]
    # The first entry is the benchmark plant's trigger. Later entries repeat a
    # request this oracle cannot judge on any other app. Cap that one request
    # so a slow target cannot stall the check. A timeout or a miss is not tested.
    timeout: float | None = None
    if spec.family in FIXTURE_ONLY and spec.family not in _ORDERED:
        payloads = payloads[:1]
        timeout = _FIXTURE_ONLY_TIMEOUT
    hits: list[EngineHit] = []
    answered = 0
    rejected = ""
    try:
        for index, (payload, outcome) in enumerate(
            _replies(target, payloads, spec.family, scope, root, timeout)
        ):
            if isinstance(outcome, HttpStatus):
                # An AI endpoint that refuses one prompt still answers the others.
                rejected = str(outcome)
                if _fixture_follow_up_is_useless(spec.family, index, outcome):
                    break
                continue
            answered += 1
            evidence = oracle(payload, outcome, target)
            hits.extend(_judge_reply(spec, payload, outcome, target, evidence))
            if _fixture_follow_up_is_useless(spec.family, index, outcome):
                break
    except ProbeError as exc:
        if timeout is not None and str(exc) == "target timed out":
            return [], ""
        return hits, str(exc)
    if not answered and rejected:
        return hits, f"every payload was rejected: {rejected}"
    return hits, ""


# Each payload depends on the reply to the one before it.
_ORDERED = frozenset({"ai.memory_poisoning"})
_MEMORY_PLANT = "insidia-memory-plant"
# Fixture-only triggers do not inherit a slow target's timeout.
_FIXTURE_ONLY_TIMEOUT = 1.0


def _fixture_follow_up_is_useless(family: str, index: int, outcome: str | HttpStatus) -> bool:
    """A memory plant that did not stick cannot be read back by the next payload."""
    if family not in FIXTURE_ONLY or family not in _ORDERED or index != 0:
        return False
    return not isinstance(outcome, str) or _MEMORY_PLANT not in outcome


def _replies(
    target: Target,
    payloads: tuple[str, ...],
    family: str,
    scope: tuple[ScopeHost, ...],
    root: Path,
    timeout: float | None = None,
) -> Iterator[tuple[str, str | HttpStatus]]:
    """Each payload with its reply, in order. Sent in parallel up to the target's concurrency."""

    def one(payload: str) -> str | HttpStatus:
        try:
            return _send(target, payload, scope, root, timeout)
        except HttpStatus as exc:
            return exc

    workers = min(target.rate_limit.concurrency, len(payloads))
    if workers <= 1 or family in _ORDERED:
        for payload in payloads:
            yield payload, one(payload)
        return
    with ThreadPoolExecutor(workers) as pool:
        futures = [pool.submit(contextvars.copy_context().run, one, item) for item in payloads]
        try:
            for payload, future in zip(payloads, futures, strict=True):
                yield payload, future.result()
        finally:
            for future in futures:
                future.cancel()


def _send(
    target: Target,
    payload: str,
    scope: tuple[ScopeHost, ...],
    root: Path,
    timeout: float | None = None,
) -> str:
    """A web app's error page is its answer to the attack, so it is judged too."""
    _count_probe()
    if timeout is not None:
        target = replace(target, timeout=timeout)
    try:
        return exchange(target, payload, scope, root)
    except HttpStatus as exc:
        if target.kind in AI_KINDS:
            raise
        return exc.body


def _paired_ssti(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A fresh product must appear in the attack response and not in the baseline."""

    left = random.randint(13, 97)
    right = random.randint(13, 97)
    product = str(left * right)
    attack = "{{" + f"{left}*{right}" + "}}"
    fixed = "{{7*7}}"
    try:
        baseline = _send(target, "baseline", scope, root)
        rendered = _send(target, attack, scope, root)
        planted = _send(target, fixed, scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    if (
        attack not in rendered
        and has_standalone(product, rendered)
        and not has_standalone(product, baseline)
    ):
        return [EngineHit("insidia-ssti-arith", attack, rendered, product)], "", ""
    if (
        fixed not in planted
        and has_standalone("49", planted)
        and not has_standalone("49", baseline)
    ):
        return [EngineHit("insidia-ssti-arith", fixed, planted, "49")], "", ""
    return [], "", ""


def _paired_bola(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Two object ids return two different records that hold personal fields.

    An endpoint that ignores the id and returns the caller's own record gives
    the same body every time, so it does not match.
    """
    try:
        legacy = _send(target, "2", scope, root)
        if ORACLES["api.bola_idor"]("2", legacy, target) is not None:
            return [EngineHit("insidia-bola", "2", legacy, "admin")], "", ""
        bodies = {object_id: _send(target, object_id, scope, root) for object_id in ("1", "3")}
    except ProbeError as exc:
        return [], str(exc), ""
    bodies["2"] = legacy
    records = {key: _record(body, key) for key, body in bodies.items()}
    found = {key: record for key, record in records.items() if record is not None}
    distinct = {json.dumps(record, sort_keys=True, default=str) for record in found.values()}
    if len(found) < 2 or len(distinct) < 2:
        return [], "", ""
    first, second = sorted(found)[:2]
    fields = sorted(SENSITIVE_FIELDS & {key.lower() for key in found[second]})
    who = "with no credentials" if target.auth is None else "with one set of credentials"
    evidence = f"ids {first} and {second} each returned a user record ({', '.join(fields)}) {who}"
    hit = EngineHit("insidia-bola", second, bodies[second], evidence, confidence="medium")
    return [hit], "", ""


def _record(body: str, object_id: str) -> dict[str, object] | None:
    try:
        loaded: object = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict) and isinstance(loaded.get("data"), dict):
        loaded = loaded["data"]
    if not isinstance(loaded, dict):
        return None
    record = {str(key): value for key, value in loaded.items()}
    if not SENSITIVE_FIELDS & {key.lower() for key in record}:
        return None
    for key in ("id", "user_id", "userId", "uid"):
        if key in record and str(record[key]) != object_id:
            return None
    return record


def _paired_tls(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A handshake that succeeds with TLS 1.0 or 1.1 only."""
    try:
        planted = _send(target, "proto", scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    if ORACLES["infra.tls"]("proto", planted, target) is not None:
        return [EngineHit("insidia-tls", "proto", planted, planted)], "", ""
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    parsed = urlparse(target.url)
    if parsed.scheme not in {"https", "wss"} or parsed.hostname is None:
        return [], "", f"{parsed.scheme}:// target has no TLS to test"
    check_url(target.url, scope)
    port = parsed.port or 443
    accepted: list[str] = []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        outcome = _handshake(parsed.hostname, port, version)
        if outcome is None:
            return [], "", "this machine's OpenSSL cannot offer TLS 1.0 or 1.1"
        if outcome:
            accepted.append(name)
    if not accepted:
        return [], "", ""
    evidence = f"{parsed.hostname}:{port} accepted {' and '.join(accepted)}"
    return [EngineHit("insidia-tls", "handshake", evidence, evidence)], "", ""


def _handshake(host: str, port: int, version: ssl.TLSVersion) -> bool | None:
    """True if the server accepts only this version, False if it refuses, None if untestable."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper():
            return None
        return False
    except OSError:
        return False


# Versions with a well-known remote exploit or no upstream security fixes.
# A banner that is not listed is not evidence that the server is current.
# The prefix never reaches a report. run() lifts it onto Attempt.info.
_BANNER_GAP_MARK = "banner-gap\n"
_BANNERS: tuple[tuple[re.Pattern[str], Callable[[tuple[int, ...]], bool], str], ...] = (
    (re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)"), lambda v: v == (2, 4, 49), "CVE-2021-41773"),
    (re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)"), lambda v: v == (2, 4, 50), "CVE-2021-42013"),
    (re.compile(r"Apache/(\d+)\.(\d+)"), lambda v: v < (2, 4), "Apache httpd 2.2 or older is EOL"),
    (
        re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)"),
        lambda v: (1, 3, 9) <= v <= (1, 4, 0),
        "CVE-2013-2028",
    ),
    (
        re.compile(r"OpenSSL/1\.0\.1([a-f]?)\b"),
        lambda v: True,
        "CVE-2014-0160 (Heartbleed)",
    ),
    (re.compile(r"Microsoft-IIS/(\d+)\.(\d+)"), lambda v: v <= (6, 0), "CVE-2017-7269"),
    (re.compile(r"PHP/(\d+)\.(\d+)"), lambda v: v < (8, 1), "PHP before 8.1 is EOL"),
    (re.compile(r"Python/(\d+)\.(\d+)"), lambda v: v < (3, 9), "Python before 3.9 is EOL"),
)


def _banner_gap(banner: str) -> str:
    """A recognised version the built-in list does not mark. This is not a pass."""
    shown = " ".join(banner.split())
    if len(shown) > 180:
        shown = shown[:179].rstrip() + "…"
    return (
        f"{shown} identified; no match in the built-in list ({len(_BANNERS)} entries); "
        "banner-based, low confidence; not a vulnerability assessment"
    )


def _paired_cve(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A server or framework banner that names a known-vulnerable or EOL version."""
    try:
        planted = _send(target, "banner", scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    if ORACLES["infra.cve"]("banner", planted, target) is not None:
        return [EngineHit("insidia-banner", "banner", planted, planted)], "", ""
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    try:
        _status, headers, _body = fetch(
            target.url,
            scope,
            headers=dict(target.headers),
            limiter=_bound_limiter(target),
        )
    except ProbeError as exc:
        return [], str(exc), ""
    banner = " ".join(
        headers[name]
        for name in ("server", "x-powered-by", "x-aspnet-version")
        if name in headers
    )
    if not re.search(r"\d+\.\d+", banner):
        return [], "", "the server does not disclose a version"
    for pattern, vulnerable, label in _BANNERS:
        found = pattern.search(banner)
        if found is None:
            continue
        version = tuple(int(part) for part in found.groups() if part.isdigit())
        if vulnerable(version):
            evidence = f"{found.group(0)}: {label}"
            return [EngineHit("insidia-banner", "GET", banner, evidence)], "", ""
    return [], "", _BANNER_GAP_MARK + _banner_gap(banner)


# A database error that is already on the baseline page is the app's normal reply.
_SQL_ERROR = re.compile(
    r"sqlite3\.OperationalError"
    r"|unrecognized token"
    r"|syntax error near"
    r"|SQLSTATE"
    r"|You have an error in your SQL syntax"
    r"|PG::SyntaxError"
    r"|ORA-\d*"
    r"|near\s+[\"'].{0,40}?syntax error",
    re.IGNORECASE,
)
_SQLI_BASELINE = "aa"
_SQLI_TRUE = "' OR '1'='1"
_SQLI_FALSE = "' AND '1'='2"
_SQLI_QUOTE = "'"
# Echoing a short payload changes the length by a few bytes. A real boolean
# leak returns the rows the true condition added.
_SQLI_GROWTH = 48


def _paired_sqli(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Error-based and boolean-based SQL injection, each compared with a baseline.

    A quote that produces a database error only on the attack, or a true
    condition that returns more rows than both the baseline and a false
    condition, is a finding. The same error on every reply is not.
    """
    try:
        baseline = _send(target, _SQLI_BASELINE, scope, root)
        quoted = _send(target, _SQLI_QUOTE, scope, root)
        truth = _send(target, _SQLI_TRUE, scope, root)
        falsehood = _send(target, _SQLI_FALSE, scope, root)
    except ProbeError as exc:
        return [], str(exc), ""
    for payload, body in ((_SQLI_QUOTE, quoted), (_SQLI_TRUE, truth), (_SQLI_FALSE, falsehood)):
        evidence = _sql_error(baseline, payload, body)
        if evidence is not None:
            return [EngineHit("insidia-sqli", payload, body, evidence)], "", ""
    evidence = _boolean_sqli(baseline, truth, falsehood)
    if evidence is not None:
        return [EngineHit("insidia-sqli", _SQLI_TRUE, truth, evidence)], "", ""
    return [], "", ""


def _sql_error(baseline: str, attack: str, response: str) -> str | None:
    found = _SQL_ERROR.search(response)
    if found is None:
        return None
    evidence = found.group(0)
    folded = evidence.lower()
    if folded in baseline.lower() or folded in attack.lower():
        return None
    return evidence


def _boolean_sqli(baseline: str, truth: str, falsehood: str) -> str | None:
    base_rows, true_rows, false_rows = (
        _listed_rows(baseline),
        _listed_rows(truth),
        _listed_rows(falsehood),
    )
    if base_rows is not None and true_rows is not None and false_rows is not None:
        if true_rows > base_rows and true_rows > false_rows:
            return (
                f"{true_rows} rows for a true condition, "
                f"{base_rows} for the baseline, {false_rows} for a false condition"
            )
        return None
    if (
        len(truth) >= len(baseline) + _SQLI_GROWTH
        and len(truth) >= len(falsehood) + _SQLI_GROWTH
        and len(truth) > int(len(baseline) * 1.5)
        and len(truth) > int(len(falsehood) * 1.5)
    ):
        return (
            f"true condition is {len(truth)} bytes, "
            f"baseline {len(baseline)}, false condition {len(falsehood)}"
        )
    return None


def _listed_rows(body: str) -> int | None:
    try:
        loaded: object = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, list):
        return len(loaded)
    if isinstance(loaded, dict):
        for key in ("data", "accounts", "results", "rows", "items"):
            value = loaded.get(key)
            if isinstance(value, list):
                return len(value)
    return None


_REDIRECT_HOST = "insidia-redirect.invalid"
_OPEN_REDIRECTS = (f"https://{_REDIRECT_HOST}/", f"//{_REDIRECT_HOST}")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_JS_REDIRECT = re.compile(
    r"""(?i)(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*['"]([^'"]+)['"]"""
    r"""|location\s*\.\s*replace\(\s*['"]([^'"]+)['"]"""
)


def _paired_open_redirect(
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """A 3xx or client redirect to the canary host. The canary host is never requested."""
    del root
    try:
        for payload in _OPEN_REDIRECTS:
            _count_probe()
            status, headers, body = fetch_target(target, payload, scope, follow=False)
            evidence = _redirect_evidence(status, headers, body)
            if evidence is not None:
                return [EngineHit("insidia-open-redirect", payload, evidence, evidence)], "", ""
    except ProbeError as exc:
        return [], str(exc), ""
    return [], "", ""


def _redirect_evidence(status: int, headers: dict[str, str], body: str) -> str | None:
    if status in _REDIRECT_STATUSES:
        location = headers.get("location", "")
        if _redirect_host(location) == _REDIRECT_HOST:
            return f"{status} Location: {location.strip()}"
    for url in _client_redirects(body):
        if _redirect_host(url) == _REDIRECT_HOST:
            return f"client redirect to {url}"
    return None


def _redirect_host(url: str) -> str:
    return (urlparse(url.strip()).hostname or "").lower().rstrip(".")


def _client_redirects(body: str) -> tuple[str, ...]:
    found: list[str] = []
    for tag in re.findall(r"(?is)<meta\b[^>]*>", body):
        if re.search(r"(?i)http-equiv\s*=\s*['\"]?\s*refresh\b", tag) is None:
            continue
        match = re.search(r"(?i)\burl\s*=\s*['\"]?\s*([^'\"\s>]+)", tag)
        if match is not None:
            found.append(match.group(1))
    for match in _JS_REDIRECT.finditer(body):
        url = match.group(1) or match.group(2)
        if url:
            found.append(url)
    return tuple(found)


_PAIRED: dict[
    str, Callable[[Target, tuple[ScopeHost, ...], Path], tuple[list[EngineHit], str, str]]
] = {
    "web.ssti": _paired_ssti,
    "web.sqli": _paired_sqli,
    "web.open_redirect": _paired_open_redirect,
    "api.bola_idor": _paired_bola,
    "infra.tls": _paired_tls,
    "infra.cve": _paired_cve,
}


def _judge_repo(
    spec: ProbeSpec, target: Target, root: Path
) -> tuple[list[EngineHit], str, int, str]:
    """Hits across the repository's files, why nothing could be tested, and the real total."""
    result = _REPO_CHECKS[spec.family](repo_path(target, root))
    hits = [
        EngineHit(f"insidia-{hit.rule}", hit.rule, hit.line, hit.evidence, hit.location)
        for hit in result.hits
    ]
    return hits, result.untested, result.counted, result.unit


def _report[View: (ScopedUrl, RepoPath)](
    adapter: ReportAdapter[View],
    spec: ProbeSpec,
    view: View,
    launch: Launch,
) -> tuple[list[EngineHit], str]:
    with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
        workspace = Path(name).resolve()
        invocation = adapter.prepare(spec, view, workspace)
        report = (workspace / invocation.report).resolve()
        if workspace not in report.parents:
            raise ScopeError(f"{adapter.engine} report path leaves its workspace")
        try:
            launch(invocation, workspace)
        except EngineFailed as exc:
            return [], str(exc)
        try:
            return adapter.parse(report, spec), ""
        except EngineFailed as exc:
            return [], str(exc)


def _relay(
    adapter: RelayAdapter,
    spec: ProbeSpec,
    target: Target,
    project: Project,
    root: Path,
    launch: Launch,
) -> tuple[list[EngineHit], str, str]:
    token = secrets.token_hex(16)
    pairs: list[tuple[str, str]] = []
    budget = current_budget()
    bucket = _probe_tally.get()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth, f"Bearer {token}"):
                self.send_response(401)
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            if length > 1_000_000:
                self.send_response(413)
                self.end_headers()
                return
            try:
                body = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            prompt = body.get("prompt") if isinstance(body, dict) else None
            if not isinstance(prompt, str):
                self.send_response(400)
                self.end_headers()
                return
            try:
                # The relay thread does not inherit the scan tally. Count the prompt here.
                _count_bucket(bucket)
                with BoundBudget(budget):
                    response = exchange(target, prompt, project.scope, root)
            except (CliError, OSError):
                self.send_response(502)
                self.end_headers()
                return
            pairs.append((prompt, response))
            payload = json.dumps({"text": response}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                # The engine gave up before the target answered. Nothing to send to.
                return

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = _with_model(RelayEndpoint(f"http://127.0.0.1:{port}/send", token), project)
        with tempfile.TemporaryDirectory(prefix=f"insidia-{adapter.engine}-") as name:
            workspace = Path(name).resolve()
            invocation = adapter.prepare(spec, endpoint, workspace)
            failed: EngineFailed | None = None
            try:
                launch(invocation, workspace)
            except EngineFailed as exc:
                failed = exc
            oracle = ORACLES[spec.family]
            hits: list[EngineHit] = []
            for prompt, response in pairs:
                evidence = oracle(prompt, response, target)
                hits.extend(_judge_reply(spec, prompt, response, target, evidence))
            if failed is not None:
                return hits, str(failed), ""
            if not pairs:
                return [], "engine finished without contacting the target", ""
            if spec.family in FIXTURE_ONLY:
                return hits, "", _untested_note(spec.family)
            if len(pairs) < _RELAY_MIN_PROMPTS:
                return hits, "", _relay_shallow_note(adapter.engine, len(pairs))
            return hits, "", ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _with_model(endpoint: RelayEndpoint, project: Project) -> RelayEndpoint:
    """Hand the user's own attacker model to engines that must call one."""
    role = project.attacker
    if role is None or role.provider != "openai-compatible":
        return endpoint
    if role.base_url is None or role.model is None:
        return endpoint
    check_url(role.base_url, project.scope)
    key = resolve_secret(role.secret_ref) if role.secret_ref else None
    return RelayEndpoint(
        endpoint.url,
        endpoint.token,
        role.base_url.rstrip("/"),
        role.model,
        key,
    )


def _scoped_url(target: Target, scope: tuple[ScopeHost, ...]) -> ScopedUrl:
    if target.url is None:
        raise ConfigError(f"{target.name} needs a url")
    check_url(target.url, scope)
    return ScopedUrl(target.url, tuple(target.query.items()))


def _over_url(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[ScopedUrl]]:
    return adapter.view is ScopedUrl


def _over_repo(
    adapter: ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath],
) -> TypeGuard[ReportAdapter[RepoPath]]:
    return adapter.view is RepoPath
