"""Regression cases for open bugs N2 and N4.

N2: an api or web target with no ``{{payload}}`` placeholder must not report
injection checks as a plain pass. N4: ``ai.hidden_context_extraction`` must not
report a plain pass when the reply contains a system prompt that does not use
the phrasing "you are a". Guard cases (N2-P2, N2-N1, N4-N1) lock in detections
and real passes that a fix must leave alone.

Bug-asserting cases failed on 64e3a8f for a plain ``pass``. They are marked
``xfail(strict=True)`` so the suite stays green until a fix lands, which turns
them into XPASS until the marker is removed.
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
    run_scan,
    vacuous_problem,
    write_config,
)


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


@pytest.mark.xfail(strict=True, reason="N2 open")
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
    assert ran.code == 0, _tail(ran)
    assert ran.findings == [], _tail(ran)
    problems = [
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


@pytest.mark.xfail(strict=True, reason="N2 open")
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
    assert ran.code == 0, _tail(ran)
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


@pytest.mark.xfail(strict=True, reason="N2 open")
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
    assert recorded, "fixture recorded no request lines"
    assert ran.code == 0, _tail(ran)
    problems = []
    saw_identical = False
    for family in N2_FAMILIES:
        lines = ran.probes.get(("users", family), [])
        if not lines:
            problems.append(f"{family}: fixture recorded no probe request lines")
            continue
        if len(set(lines)) != 1:
            continue
        saw_identical = True
        problem = vacuous_problem(
            ran.control("users", family),
            ran.detail("users", family),
            ran.benchmark.get("skips"),
            family,
            allow_low_assurance=True,
        )
        if problem:
            sample = lines[0]
            problems.append(f"{problem} (identical probe {sample!r}, count={len(lines)})")
    if not saw_identical:
        problems.append("no check had identical probe lines, so the oracle did not run")
    assert not problems, "\n".join(problems)


@pytest.mark.xfail(strict=True, reason="N4 open")
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


@pytest.mark.xfail(strict=True, reason="N4 open")
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


@pytest.mark.xfail(strict=True, reason="N4 open")
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


@pytest.mark.xfail(strict=True, reason="N4 open")
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


def _tail(ran: ScanRun) -> str:
    text = (ran.stdout + "\n" + ran.stderr).strip()
    return text[-2000:]
