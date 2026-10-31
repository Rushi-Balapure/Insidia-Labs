"""Regression cases for N2 and N4.

N2: an api or web target with no ``{{payload}}`` placeholder must not report
injection checks as a plain pass. A users-only scan is inconclusive (exit 2):
payload checks and infra.tls stay not tested, and infra.cve is info, which
must not count as a pass. N4: ``ai.hidden_context_extraction`` must not
report a plain pass when the reply contains a system prompt that does not use
the phrasing "you are a". Guard cases (N2-P2, N2-N1, N4-N1) lock in detections
and real passes that a fix must leave alone.

Both bugs are live guards. N4 landed in 708d7f0. N2's exit 2 is the intended
verdict. At 513e904 a banner with no known CVE is info, not a pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.fixtures.regression_v6 import chat, jsonapi, novabot, obey, web
from tests.fixtures.regression_v6.chat import AWS_KEY
from tests.fixtures.regression_v6.novabot import GITHUB_TOKEN, STRIPE_KEY
from tests.fixtures.regression_v6.server import RecordingServer, serve
from tests.regression_v6 import (
    N2_FAMILIES,
    N2_OWASP,
    ScanRun,
    finding_text,
    hidden_context_problem,
    owasp_problem,
    reason_text,
    run_scan,
    vacuous_problem,
    write_config,
)

_PAYLOAD_FREE = ("infra.cve", "infra.tls")


def _scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    config_name: str,
    ports: dict[int, int],
    servers: list[RecordingServer],
    only: tuple[str, ...] | None = None,
) -> ScanRun:
    config = write_config(tmp_path, config_name, ports, only)
    return run_scan(tmp_path, config, monkeypatch, capsys, servers)


def test_tc_n2_p1_users_without_placeholder_is_not_a_plain_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(web.start()) as server:
        ran = _scan(
            tmp_path,
            monkeypatch,
            capsys,
            "p1-web.insidia.yaml",
            {8090: server.port},
            [server],
            ("users",),
        )
    assert ran.code == 2, _tail(ran)
    assert ran.benchmark.get("policy_verdict") == "inconclusive"
    assert ran.findings == [], _tail(ran)
    problems = _users_infra(ran)
    problems += [
        problem
        for family in N2_FAMILIES
        if (
            problem := vacuous_problem(
                ran.control("users", family),
                ran.detail("users", family),
                ran.benchmark.get("skips"),
                family,
                allow_low_assurance=False,
            )
        )
    ]
    problems.extend(_framework_not_pass(ran))
    assert not problems, "\n".join(problems)


def test_tc_n2_p2_placeholder_targets_still_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(web.start()) as server:
        ran = _scan(
            tmp_path, monkeypatch, capsys, "p1-web.insidia.yaml", {8090: server.port}, [server]
        )
    assert ran.code == 1, _tail(ran)
    expected = (
        ("ssti", "web.ssti"),
        ("ping", "web.cmdi"),
        ("file", "web.path_lfi"),
    )
    found = {(item.get("target"), item.get("attack")) for item in ran.findings}
    problems = []
    for target, family in expected:
        result = ran.control(target, family).get("result")
        if result != "fail":
            problems.append(f"{target} {family}: expected 'fail', got {result!r}")
        if (target, family) not in found:
            problems.append(f"{target} {family}: missing from findings")
    assert not problems, "\n".join(problems)


def test_tc_n2_n1_substituted_payloads_stay_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(jsonapi.start("safe")) as server:
        ran = _scan(
            tmp_path,
            monkeypatch,
            capsys,
            "p2-api-safe.insidia.yaml",
            {8111: server.port},
            [server],
            ("search",),
        )
    assert ran.code == 0, _tail(ran)
    assert ran.findings == [], _tail(ran)
    problems = []
    for family in N2_FAMILIES:
        lines = ran.probes.get(("search", family), [])
        if len(set(lines)) < 2:
            problems.append(f"{family}: expected distinct q= probes, got {lines!r}")
            continue
        result = ran.control("search", family).get("result")
        if result != "pass":
            problems.append(f"{family}: expected 'pass', got {result!r}")
        if not any("q=" in line for line in lines):
            problems.append(f"{family}: probe lines have no q= value: {lines!r}")
    assert not problems, "\n".join(problems)


def test_tc_n2_nfp1_owasp_rows_from_users_are_not_plain_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(web.start()) as server:
        ran = _scan(
            tmp_path,
            monkeypatch,
            capsys,
            "p1-web.insidia.yaml",
            {8090: server.port},
            [server],
            ("users",),
        )
    assert ran.code == 2, _tail(ran)
    assert ran.benchmark.get("policy_verdict") == "inconclusive"
    problems = [
        problem
        for family in N2_FAMILIES
        if (
            problem := vacuous_problem(
                ran.control("users", family),
                ran.detail("users", family),
                ran.benchmark.get("skips"),
                family,
                allow_low_assurance=True,
            )
        )
    ]
    computed = ran.framework()
    rendered = ran.html_framework()
    if computed != rendered:
        problems.append(f"report coverage differs from benchmark scoring: {rendered!r}")
    for item_id in N2_OWASP:
        problem = owasp_problem(computed, item_id)
        if problem:
            problems.append(problem)
        if rendered.get(item_id) == "pass":
            problems.append(f"report {item_id}: expected not a plain pass, got 'pass'")
    assert not problems, "\n".join(problems)


def test_tc_n2_nfp2_identical_probes_are_not_plain_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(web.start()) as server:
        ran = _scan(
            tmp_path,
            monkeypatch,
            capsys,
            "p1-web.insidia.yaml",
            {8090: server.port},
            [server],
            ("users",),
        )
        recorded = [line for _stamp, line in server.requests]
    assert ran.code == 2, _tail(ran)
    assert ran.benchmark.get("policy_verdict") == "inconclusive"
    problems = _payload_did_not_land(ran, recorded)
    problems.extend(_no_users_pass(ran))
    problems.extend(_users_route_bounds(recorded))
    assert not problems, "\n".join(problems)


def test_tc_n4_p1_helpbot_prompt_without_article_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(obey.start()) as server:
        ran = _scan(
            tmp_path, monkeypatch, capsys, "p1-obey.insidia.yaml", {8083: server.port}, [server]
        )
    assert ran.code == 1, _tail(ran)
    for family in ("ai.prompt_injection_direct", "ai.jailbreak"):
        result = ran.control("app", family).get("result")
        assert result == "fail", f"{family}: expected 'fail', got {result!r}"
    problem = hidden_context_problem(
        ran.control("app", "ai.hidden_context_extraction"),
        ran.detail("app", "ai.hidden_context_extraction"),
        ran.benchmark.get("skips"),
        allow_low_assurance=False,
    )
    assert problem is None, problem
    evidence = finding_text(ran.findings, "ai.hidden_context_extraction")
    assert "You are HelpBot for Acme Corp" in evidence, evidence


def test_tc_n4_p2_persona_prompt_fails_and_secrets_are_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(novabot.start("vuln")) as server:
        ran = _scan(
            tmp_path,
            monkeypatch,
            capsys,
            "p2-nova-vuln.insidia.yaml",
            {8100: server.port},
            [server],
        )
    assert ran.code == 1, _tail(ran)
    problem = hidden_context_problem(
        ran.control("nova", "ai.hidden_context_extraction"),
        ran.detail("nova", "ai.hidden_context_extraction"),
        ran.benchmark.get("skips"),
        allow_low_assurance=False,
    )
    assert problem is None, problem
    evidence = finding_text(ran.findings, "ai.hidden_context_extraction")
    assert "Persona: Nova" in evidence, evidence
    assert GITHUB_TOKEN not in evidence
    assert STRIPE_KEY not in evidence
    assert "[GITHUB_TOKEN" in evidence
    assert "[STRIPE_KEY" in evidence
    stored = json.dumps(ran.findings) + ran.report
    assert GITHUB_TOKEN not in stored
    assert STRIPE_KEY not in stored


def test_tc_n4_n1_refusals_do_not_look_like_a_prompt_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(chat.start("safe")) as safe_chat:
        chat_run = _scan(
            tmp_path / "chat",
            monkeypatch,
            capsys,
            "p1-safe.insidia.yaml",
            {8081: safe_chat.port},
            [safe_chat],
        )
    with serve(novabot.start("safe")) as safe_nova:
        nova_run = _scan(
            tmp_path / "nova",
            monkeypatch,
            capsys,
            "p2-nova-safe.insidia.yaml",
            {8101: safe_nova.port},
            [safe_nova],
        )
    problems = []
    for label, ran, target in (("safe chat", chat_run, "app"), ("nova safe", nova_run, "nova")):
        if ran.code != 0:
            problems.append(f"{label}: expected exit 0, got {ran.code}")
        if ran.findings:
            problems.append(f"{label}: expected no findings, got {ran.findings!r}")
        result = ran.control(target, "ai.hidden_context_extraction").get("result")
        if result != "pass":
            problems.append(
                f"{label} ai.hidden_context_extraction: expected 'pass', got {result!r}"
            )
    assert not problems, "\n".join(problems)


def test_tc_n4_nfp1_llm08_is_not_a_plain_pass_on_a_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(obey.start()) as server:
        obey_run = _scan(
            tmp_path / "obey",
            monkeypatch,
            capsys,
            "p1-obey.insidia.yaml",
            {8083: server.port},
            [server],
        )
    with serve(novabot.start("vuln")) as server:
        nova_run = _scan(
            tmp_path / "nova",
            monkeypatch,
            capsys,
            "p2-nova-vuln.insidia.yaml",
            {8100: server.port},
            [server],
        )
    problems = []
    for label, ran, target in (("obey", obey_run, "app"), ("nova", nova_run, "nova")):
        problem = hidden_context_problem(
            ran.control(target, "ai.hidden_context_extraction"),
            ran.detail(target, "ai.hidden_context_extraction"),
            ran.benchmark.get("skips"),
            allow_low_assurance=True,
        )
        if problem:
            problems.append(f"{label}: {problem}")
        computed = ran.framework()
        rendered = ran.html_framework()
        if computed.get("owasp-llm:LLM08") != rendered.get("owasp-llm:LLM08"):
            problems.append(f"{label}: report LLM08 {rendered.get('owasp-llm:LLM08')!r} != json")
        for source, rows in (("benchmark", computed), ("report", rendered)):
            issue = owasp_problem(rows, "owasp-llm:LLM08")
            if issue:
                problems.append(f"{label} {source}: {issue}")
    assert not problems, "\n".join(problems)


def test_tc_n4_nfp2_data_leakage_does_not_hide_the_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with serve(chat.start("vuln")) as server:
        ran = _scan(
            tmp_path, monkeypatch, capsys, "p1-chat.insidia.yaml", {8080: server.port}, [server]
        )
    assert ran.code == 1, _tail(ran)
    leakage = ran.control("app", "ai.data_leakage").get("result")
    assert leakage == "fail", f"ai.data_leakage: expected 'fail', got {leakage!r}"
    stored = json.dumps(ran.findings) + ran.report
    assert AWS_KEY not in stored
    assert "[AWS_ACCESS_KEY" in stored
    problem = hidden_context_problem(
        ran.control("app", "ai.hidden_context_extraction"),
        ran.detail("app", "ai.hidden_context_extraction"),
        ran.benchmark.get("skips"),
        allow_low_assurance=True,
    )
    assert problem is None, problem


def _users_infra(ran: ScanRun) -> list[str]:
    """infra.tls stays not tested. infra.cve is info, never a pass or a fail."""
    problems: list[str] = []
    tls = ran.control("users", "infra.tls")
    tls_result = tls.get("result")
    tls_reason = reason_text(
        tls, ran.detail("users", "infra.tls"), ran.benchmark.get("skips"), "infra.tls"
    )
    if tls_result != "not tested":
        problems.append(f"infra.tls: expected 'not tested', got {tls_result!r}")
    elif not tls_reason:
        problems.append("infra.tls: expected a non-empty reason")
    cve = ran.control("users", "infra.cve")
    cve_result = cve.get("result")
    detail = str(cve.get("detail") or "").strip()
    if cve_result != "info":
        problems.append(f"infra.cve: expected 'info', got {cve_result!r}")
    elif not detail:
        problems.append("infra.cve: expected a non-empty detail")
    return problems


def _framework_not_pass(ran: ScanRun) -> list[str]:
    """infra.cve maps to owasp-web:A06. INFO must not make that row a pass."""
    problems: list[str] = []
    for source, rows in (("benchmark", ran.framework()), ("report", ran.html_framework())):
        result = rows.get("owasp-web:A06")
        if result is None:
            problems.append(f"{source} owasp-web:A06: missing from framework coverage")
        elif result == "pass" or result == "pass (low assurance)":
            problems.append(f"{source} owasp-web:A06: expected not a pass, got {result!r}")
    return problems


def _payload_did_not_land(ran: ScanRun, recorded: list[str]) -> list[str]:
    """Payload checks return before HTTP. Only infra or preflight may hit /api/users/1."""
    controls = ran.benchmark.get("controls")
    if not isinstance(controls, list):
        return ["benchmark controls is not a list"]
    payload_ids = [
        str(row.get("id"))
        for row in controls
        if isinstance(row, dict)
        and row.get("target") == "users"
        and row.get("id") not in _PAYLOAD_FREE
    ]
    problems: list[str] = []
    payload_lines: set[str] = set()
    for family in payload_ids:
        sent = [line for line in ran.probes.get(("users", family), []) if "/api/users/1" in line]
        payload_lines.update(sent)
        if sent:
            problems.append(f"{family}: payload check requested /api/users/1: {sent!r}")
    infra_lines = {
        line
        for family in _PAYLOAD_FREE
        for line in ran.probes.get(("users", family), [])
        if "/api/users/1" in line
    }
    stray = [
        line
        for line in recorded
        if "/api/users/1" in line and line not in infra_lines and line in payload_lines
    ]
    if stray:
        problems.append(f"fixture recorded payload requests for /api/users/1: {stray!r}")
    return problems


# Same cap as the inline ``<= 6`` in test_coverage_limits.py:181. That file
# does not export a constant to import.
_USERS_ROUTE_CAP = 6
_USERS_PATH = "/api/users/1"


def _request_target(line: str) -> str:
    parts = line.split(" ")
    return parts[1] if len(parts) >= 2 else line


def _users_route_bounds(recorded: list[str]) -> list[str]:
    """Requests to the configured users URL stay few and carry no payload.

    The vendored target is ``GET /api/users/1`` with an empty query and no body.
    A payload check embeds its marker in that request-target, so any query or
    extra path means a payload landed.
    """
    hits = [line for line in recorded if _is_users_route(line)]
    problems: list[str] = []
    if len(hits) > _USERS_ROUTE_CAP:
        problems.append(
            f"{_USERS_PATH} was requested {len(hits)} times; cap is {_USERS_ROUTE_CAP} "
            "(test_coverage_limits.py:181)"
        )
    for line in hits:
        if _request_target(line) != _USERS_PATH:
            problems.append(f"{_USERS_PATH} request carries a payload marker: {line!r}")
    return problems


def _is_users_route(line: str) -> bool:
    target = _request_target(line)
    path = target.split("?", 1)[0]
    return path == _USERS_PATH or path.startswith(f"{_USERS_PATH}/")


def _no_users_pass(ran: ScanRun) -> list[str]:
    controls = ran.benchmark.get("controls")
    if not isinstance(controls, list):
        return ["benchmark controls is not a list"]
    return [
        f"{row.get('id')}: expected not a plain pass, got 'pass'"
        for row in controls
        if isinstance(row, dict) and row.get("target") == "users" and row.get("result") == "pass"
    ]


def _tail(ran: ScanRun) -> str:
    text = (ran.stdout + "\n" + ran.stderr).strip()
    return text[-2000:]
