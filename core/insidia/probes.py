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
from dataclasses import dataclass
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
from insidia.policy import Control
from insidia.process import launch_installed
from insidia.scope import ScopeHost, check_url
from insidia.transport import (
    AI_KINDS,
    BoundBudget,
    carries_payload,
    current_budget,
    exchange,
    fetch,
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


@dataclass(frozen=True)
class Attempt:
    """Observations from one engine, plus an error if that engine did not finish."""

    hits: tuple[ProbeHit, ...] = ()
    error: str = ""
    # The engine finished but could not test this target, for example TLS over plain HTTP.
    untested: str = ""


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
    untested = ""
    match adapter:
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
    hits = tuple(
        ProbeHit(
            target.name,
            spec.family,
            adapter.engine,
            spec.probe,
            hit.response,
            hit.severity or control.severity,
            hit.confidence or "high",
            control.track,
            control.taxonomy,
            control.remediation,
            hit.upstream,
            hit.evidence,
            hit.location,
        )
        for hit in found
    )
    return Attempt(hits, error, "" if hits else untested)


_FIXTURE_ONLY_NOTE = "this check only recognises Insidia's benchmark app"
# Fewer prompts than this is a smoke test, not coverage of the family.
_RELAY_MIN_PROMPTS = 3
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


def _judge(
    adapter: BuiltIn,
    spec: ProbeSpec,
    target: Target,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> tuple[list[EngineHit], str, str]:
    """Hits, an error if the check did not finish, and why nothing could be tested."""
    if target.kind == "repo":
        hits, untested = _judge_repo(spec, target, root)
        return hits, "", untested
    paired = _PAIRED.get(spec.family)
    if paired is not None:
        return paired(target, scope, root)
    hits, error = _corpus(adapter, spec, target, scope, root)
    if spec.family in FIXTURE_ONLY:
        return hits, error, _FIXTURE_ONLY_NOTE
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
    hits: list[EngineHit] = []
    answered = 0
    rejected = ""
    try:
        for payload, outcome in _replies(target, payloads, spec.family, scope, root):
            if isinstance(outcome, HttpStatus):
                # An AI endpoint that refuses one prompt still answers the others.
                rejected = str(outcome)
                continue
            answered += 1
            evidence = oracle(payload, outcome, target)
            if evidence is not None:
                hits.append(EngineHit(spec.upstream, payload, outcome, evidence))
    except ProbeError as exc:
        return hits, str(exc)
    if not answered and rejected:
        return hits, f"every payload was rejected: {rejected}"
    return hits, ""


# Each payload depends on the reply to the one before it.
_ORDERED = frozenset({"ai.memory_poisoning"})


def _replies(
    target: Target,
    payloads: tuple[str, ...],
    family: str,
    scope: tuple[ScopeHost, ...],
    root: Path,
) -> Iterator[tuple[str, str | HttpStatus]]:
    """Each payload with its reply, in order. Sent in parallel up to the target's concurrency."""

    def one(payload: str) -> str | HttpStatus:
        try:
            return _send(target, payload, scope, root)
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


def _send(target: Target, payload: str, scope: tuple[ScopeHost, ...], root: Path) -> str:
    """A web app's error page is its answer to the attack, so it is judged too."""
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
        _status, headers, _body = fetch(target.url, scope, headers=dict(target.headers))
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
    return [], "", f"no known-vulnerable version in {banner[:60]}"


_PAIRED: dict[
    str, Callable[[Target, tuple[ScopeHost, ...], Path], tuple[list[EngineHit], str, str]]
] = {
    "web.ssti": _paired_ssti,
    "api.bola_idor": _paired_bola,
    "infra.tls": _paired_tls,
    "infra.cve": _paired_cve,
}


def _judge_repo(spec: ProbeSpec, target: Target, root: Path) -> tuple[list[EngineHit], str]:
    """Hits across the repository's files, and why nothing could be tested."""
    result = _REPO_CHECKS[spec.family](repo_path(target, root))
    hits = [
        EngineHit(f"insidia-{hit.rule}", hit.rule, hit.line, hit.evidence, hit.location)
        for hit in result.hits
    ]
    return hits, result.untested


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
                if evidence is not None:
                    hits.append(EngineHit(spec.upstream, prompt, response, evidence))
            if failed is not None:
                return hits, str(failed), ""
            if not pairs:
                return [], "engine finished without contacting the target", ""
            if spec.family in FIXTURE_ONLY:
                return hits, "", _FIXTURE_ONLY_NOTE
            if len(pairs) < _RELAY_MIN_PROMPTS:
                return hits, "", f"{adapter.engine} sent only {len(pairs)} prompt(s)"
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
