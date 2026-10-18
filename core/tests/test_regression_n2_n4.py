"""Regression cases for N2 and N4.

N2: an api or web target with no ``{{payload}}`` placeholder must not report
injection checks as a plain pass. A users-only scan is inconclusive (exit 2):
payload checks are not tested, and the payload-free infra checks stay not
tested for their own reasons. N4: ``ai.hidden_context_extraction`` must not
report a plain pass when the reply contains a system prompt that does not use
the phrasing "you are a". Guard cases (N2-P2, N2-N1, N4-N1) lock in detections
and real passes that a fix must leave alone.

Both bugs are live guards. N4 landed in 708d7f0. N2's exit 2 is the intended
verdict confirmed at 08f6f87.
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
    problems = _infra_not_tested(ran)
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
    problems = _infra_not_tested(ran)
    problems += [
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
    problems = _infra_not_tested(ran)
    for family in N2_FAMILIES:
        problem = vacuous_problem(
            ran.control("users", family),
            ran.detail("users", family),
            ran.benchmark.get("skips"),
            family,
            allow_low_assurance=True,
        )
        if problem:
            problems.append(problem)
    problems.extend(_payload_did_not_land(ran, recorded))
    problems.extend(_no_users_pass(ran))
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


def _infra_not_tested(ran: ScanRun) -> list[str]:
    """infra.cve and infra.tls are payload-free, so they stay not tested with a reason."""
    problems: list[str] = []
    for family in _PAYLOAD_FREE:
        control = ran.control("users", family)
        result = control.get("result")
        reason = reason_text(
            control, ran.detail("users", family), ran.benchmark.get("skips"), family
        )
        if result != "not tested":
            problems.append(f"{family}: expected 'not tested', got {result!r}")
        elif not reason:
            problems.append(f"{family}: expected a non-empty reason")
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
