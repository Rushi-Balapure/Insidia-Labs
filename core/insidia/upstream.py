"""Phase 1B adapters. Each engine is one value. The runner does not grow a branch."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse, urlunparse

from insidia.adapters import (
    EngineHit,
    Invocation,
    ProbeSpec,
    RelayAdapter,
    RelayEndpoint,
    RepoPath,
    ReportAdapter,
    ScopedUrl,
)
from insidia.catalog import BY_NAME, SPECS, SSTI_PAYLOAD, STATIC_PROMPT, EngineSpec

PROMPTFOO_ENV = {
    "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true",
    "PROMPTFOO_DISABLE_TELEMETRY": "1",
    "PROMPTFOO_DISABLE_SHARING": "1",
    "PROMPTFOO_DISABLE_UPDATE": "1",
}
_SSTI_PRODUCT = "49"


def build() -> tuple[RelayAdapter | ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath], ...]:
    adapters: list[RelayAdapter | ReportAdapter[ScopedUrl] | ReportAdapter[RepoPath]] = []
    for spec in SPECS:
        probe = _probe(spec)
        if spec.kind == "relay":
            adapters.append(
                RelayAdapter(spec.name, spec.license, (probe,), _relay_prepare(spec.name))
            )
        elif spec.kind == "web":
            adapters.append(
                ReportAdapter(
                    spec.name,
                    spec.license,
                    (probe,),
                    ScopedUrl,
                    _web_prepare(spec.name),
                    _web_parser(spec.name),
                )
            )
        else:
            adapters.append(
                ReportAdapter(
                    spec.name,
                    spec.license,
                    (probe,),
                    RepoPath,
                    _repo_prepare(spec.name),
                    _repo_parser(spec.name),
                )
            )
    return tuple(adapters)


def _probe(spec: EngineSpec) -> ProbeSpec:
    return ProbeSpec(
        f"{spec.name}.{spec.family}",
        spec.upstream,
        spec.family,
        spec.priority,
        False,
        spec.target_kinds,
    )


def _relay_prepare(engine: str) -> Callable[[ProbeSpec, RelayEndpoint, Path], Invocation]:
    def prepare(spec: ProbeSpec, endpoint: RelayEndpoint, workspace: Path) -> Invocation:
        if engine == "garak":
            return _garak(endpoint, workspace)
        if engine == "promptfoo":
            return _promptfoo(endpoint, workspace)
        if engine == "pyrit":
            return _pyrit(endpoint, workspace)
        if engine == "deepteam":
            return _deepteam(endpoint, workspace)
        raise ValueError(engine)

    return prepare


def _garak(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    # Stock garak probes do not send this word. The workspace probe config does.
    (workspace / "probe.json").write_text(
        json.dumps({"test": {"Blank": {"prompts": [STATIC_PROMPT], "active": True}}})
    )
    generator = {
        "rest": {
            "RestGenerator": {
                "uri": endpoint.url,
                "method": "post",
                "headers": {
                    "Authorization": f"Bearer {endpoint.token}",
                    "Content-Type": "application/json",
                },
                "req_template_json_object": {"prompt": "$INPUT"},
                "response_json": True,
                "response_json_field": "text",
                "parallel_requests": 8,
                "request_timeout": 30,
                "proxies": None,
            }
        }
    }
    (workspace / "generator.json").write_text(json.dumps(generator))
    return Invocation(
        _program("garak"),
        (
            "--target_type",
            "rest.RestGenerator",
            "--target_name",
            endpoint.url,
            "--generator_option_file",
            str(workspace / "generator.json"),
            "--probes",
            "test.Blank",
            "--probe_option_file",
            str(workspace / "probe.json"),
            "--parallel_requests",
            "8",
            "--generations",
            "1",
            "--report_prefix",
            str(workspace / "run"),
        ),
        "run.report.jsonl",
        timeout=180,
    )


def _promptfoo(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    (workspace / "prompt.txt").write_text(STATIC_PROMPT + "\n")
    (workspace / "provider.cjs").write_text(_PROVIDER_JS)
    config = "\n".join(
        (
            "prompts:",
            "  - file://prompt.txt",
            "providers:",
            "  - file://provider.cjs",
            "tests:",
            "  - vars: {}",
            "outputPath: report.json",
            "",
        )
    )
    (workspace / "promptfooconfig.yaml").write_text(config)
    env = dict(PROMPTFOO_ENV)
    env["INSIDIA_RELAY_URL"] = endpoint.url
    env["INSIDIA_RELAY_TOKEN"] = endpoint.token
    return Invocation(
        _program("promptfoo"),
        ("eval", "-c", "promptfooconfig.yaml", "--no-cache", "-o", "report.json"),
        "report.json",
        env=env,
        timeout=180,
    )


def _pyrit(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    (workspace / "single_turn.py").write_text(_PYRIT_PY)
    return Invocation(
        _program("pyrit"),
        (str(workspace / "single_turn.py"),),
        "report.json",
        env=_script_env(endpoint),
        timeout=180,
    )


def _deepteam(endpoint: RelayEndpoint, workspace: Path) -> Invocation:
    (workspace / "callback.py").write_text(_DEEPTEAM_PY)
    return Invocation(
        _program("deepteam"),
        (str(workspace / "callback.py"),),
        "report.json",
        env=_script_env(endpoint),
        timeout=180,
    )


def _script_env(endpoint: RelayEndpoint) -> dict[str, str]:
    return {
        "INSIDIA_RELAY_URL": endpoint.url,
        "INSIDIA_RELAY_TOKEN": endpoint.token,
    }


def _web_prepare(engine: str) -> Callable[[ProbeSpec, ScopedUrl, Path], Invocation]:
    def prepare(spec: ProbeSpec, view: ScopedUrl, workspace: Path) -> Invocation:
        report = "report.jsonl" if engine in {"nuclei", "katana"} else "report.json"
        url = _request_url(view, SSTI_PAYLOAD)
        args: tuple[str, ...]
        if engine == "nuclei":
            path = _nuclei_path(view)
            # Nuclei evaluates {{7*7}} as its own syntax. The template keeps the
            # expression percent-encoded so the sandbox still sees it.
            (workspace / "ssti.yaml").write_text(_nuclei_yaml(path))
            args = (
                "-u",
                _origin(view.url),
                "-t",
                str(workspace / "ssti.yaml"),
                "-jsonl",
                "-o",
                report,
                "-silent",
                "-disable-update-check",
                "-no-interactsh",
            )
        elif engine == "zap":
            (workspace / "plan.yaml").write_text(_zap_plan(url, workspace, report))
            args = ("-cmd", "-silent", "-autorun", str(workspace / "plan.yaml"))
        elif engine == "dalfox":
            args = ("url", url, "--format", "json", "--output", report, "--silence")
        elif engine == "katana":
            args = ("-u", url, "-silent", "-jsonl", "-o", report, "-d", "1")
        elif engine == "httpx":
            args = ("-u", url, "-silent", "-json", "-o", report, "-irr")
        else:
            raise ValueError(engine)
        return Invocation(_program(engine), args, report, timeout=180)

    return prepare


def _repo_prepare(engine: str) -> Callable[[ProbeSpec, RepoPath, Path], Invocation]:
    def prepare(spec: ProbeSpec, view: RepoPath, workspace: Path) -> Invocation:
        report = str(workspace / "report.json")
        source = str(view.path)
        args: tuple[str, ...]
        if engine == "mcp-scanner":
            args = (
                "--analyzers",
                "yara",
                "behavioral",
                source,
                "--format",
                "raw",
                "-o",
                report,
            )
        elif engine == "skillspector":
            args = ("scan", source, "--no-llm", "--format", "json", "-o", report)
        elif engine == "trivy":
            args = (
                "fs",
                "--format",
                "json",
                "--output",
                report,
                "--skip-version-check",
                source,
            )
        elif engine == "osv-scanner":
            args = (
                "scan",
                "source",
                "--recursive",
                "--format",
                "json",
                "--output-file",
                report,
                source,
            )
        elif engine == "gitleaks":
            args = (
                "detect",
                "--source",
                source,
                "--report-format",
                "json",
                "--report-path",
                report,
                "--no-git",
                "--exit-code",
                "0",
            )
        elif engine == "bandit":
            args = ("-r", source, "-f", "json", "-o", report, "-q")
        elif engine == "gosec":
            args = ("-fmt", "json", "-out", report, "-no-fail", f"{source}/...")
        else:
            raise ValueError(engine)
        return Invocation(_program(engine), args, "report.json", timeout=180)

    return prepare


def _web_parser(engine: str) -> Callable[[Path, ProbeSpec], list[EngineHit]]:
    def parse(report: Path, spec: ProbeSpec) -> list[EngineHit]:
        hits: list[EngineHit] = []
        for body in _web_bodies(engine, report):
            if _ssti_product(body) is None:
                continue
            hits.append(EngineHit(spec.upstream, SSTI_PAYLOAD, body[:2000], _SSTI_PRODUCT))
        return hits

    return parse


def _repo_parser(engine: str) -> Callable[[Path, ProbeSpec], list[EngineHit]]:
    def parse(report: Path, spec: ProbeSpec) -> list[EngineHit]:
        loaded = _load_json(report)
        if loaded is None:
            return []
        reader = _REPO_RULES.get(engine)
        if reader is None:
            return []
        return [EngineHit(spec.upstream, spec.probe, rule, rule) for rule in reader(loaded)]

    return parse


def _web_bodies(engine: str, report: Path) -> list[str]:
    if engine in {"httpx", "katana"} or not report.is_file():
        return []
    text = report.read_text(errors="replace")
    if engine == "nuclei":
        return _nuclei_bodies(text)
    loaded = _loads(text)
    if engine == "zap":
        return _zap_bodies(loaded)
    if engine == "dalfox":
        return _dalfox_bodies(loaded)
    return []


def _ssti_product(body: str) -> str | None:
    if SSTI_PAYLOAD in body or _SSTI_PRODUCT not in body:
        return None
    return _SSTI_PRODUCT


def _nuclei_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for line in text.splitlines():
        loaded = _loads(line.strip())
        if not isinstance(loaded, dict):
            continue
        raw = loaded.get("response")
        if isinstance(raw, str):
            bodies.append(_http_body(raw))
    return bodies


def _zap_bodies(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    sites = loaded.get("site")
    if not isinstance(sites, list):
        return []
    bodies: list[str] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict) or not _zap_ssti(alert):
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list):
                continue
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                body = instance.get("response-body")
                if isinstance(body, str):
                    bodies.append(body)
    return bodies


def _zap_ssti(alert: dict[str, object]) -> bool:
    name = f"{alert.get('name', '')} {alert.get('alert', '')}".lower()
    return alert.get("pluginid") == "90035" or "template injection" in name


def _dalfox_bodies(loaded: object) -> list[str]:
    if isinstance(loaded, list):
        rows: object = loaded
    elif isinstance(loaded, dict):
        rows = loaded.get("findings")
    else:
        return []
    if not isinstance(rows, list):
        return []
    bodies: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not _dalfox_ssti(row):
            continue
        raw = row.get("response")
        if isinstance(raw, str):
            bodies.append(_http_body(raw))
    return bodies


def _dalfox_ssti(row: dict[str, object]) -> bool:
    text = " ".join(
        str(row.get(key, ""))
        for key in ("message_str", "inject_type", "cwe", "type_description")
    ).lower()
    return "ssti" in text or "template injection" in text or "cwe-1336" in text


def _http_body(raw: str) -> str:
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in raw:
            return raw.split(separator, 1)[1]
    return raw


def _load_json(report: Path) -> object | None:
    if not report.is_file():
        return None
    return _loads(report.read_text(errors="replace").strip())


def _loads(text: str) -> object | None:
    if not text:
        return None
    try:
        loaded: object = json.loads(text)
    except json.JSONDecodeError:
        return None
    return loaded


def _bandit_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("results")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("test_id")
        if not isinstance(rule, str) or not rule:
            rule = row.get("issue_text")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _trivy_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    results = loaded.get("Results")
    if not isinstance(results, list):
        return []
    found: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            rule = vuln.get("VulnerabilityID")
            if isinstance(rule, str) and rule:
                found.append(rule)
    return found


def _osv_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    results = loaded.get("results")
    if not isinstance(results, list):
        return []
    found: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            vulns = package.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                rule = vuln.get("id")
                if isinstance(rule, str) and rule:
                    found.append(rule)
    return found


def _gitleaks_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, list):
        return []
    found: list[str] = []
    for row in loaded:
        if not isinstance(row, dict):
            continue
        rule = row.get("RuleID")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _gosec_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("Issues")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("rule_id")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


def _mcp_rules(loaded: object) -> list[str]:
    rows = loaded if isinstance(loaded, list) else None
    if rows is None:
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        findings = row.get("findings")
        if not isinstance(findings, dict):
            continue
        for analyzer in findings.values():
            if not isinstance(analyzer, dict) or not analyzer.get("total_findings"):
                continue
            names = analyzer.get("threat_names")
            if not isinstance(names, list):
                continue
            found.extend(name for name in names if isinstance(name, str) and name)
    return found


def _skillspector_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("issues")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("id")
        if isinstance(rule, str) and rule:
            found.append(rule)
    return found


_REPO_RULES: dict[str, Callable[[object], list[str]]] = {
    "bandit": _bandit_rules,
    "trivy": _trivy_rules,
    "osv-scanner": _osv_rules,
    "gitleaks": _gitleaks_rules,
    "gosec": _gosec_rules,
    "mcp-scanner": _mcp_rules,
    "skillspector": _skillspector_rules,
}


def _request_url(view: ScopedUrl, payload: str) -> str:
    if not view.query:
        return view.url
    rendered = [
        (key, value.replace("{{prompt}}", payload).replace("{{payload}}", payload))
        for key, value in view.query
    ]
    parsed = urlparse(view.url)
    return urlunparse(parsed._replace(query=urlencode(rendered)))


def _nuclei_path(view: ScopedUrl) -> str:
    encoded = quote(SSTI_PAYLOAD, safe="*")
    parsed = urlparse(view.url)
    path = parsed.path or "/"
    if not view.query:
        return path
    parts = [
        f"{quote(key, safe='')}="
        + value.replace("{{prompt}}", encoded).replace("{{payload}}", encoded)
        for key, value in view.query
    ]
    return f"{path}?{'&'.join(parts)}"


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _nuclei_yaml(path: str) -> str:
    # Nuclei treats a path without a scheme as a URL and refuses it. BaseURL
    # is its own placeholder for the scoped origin. The payload stays encoded.
    # A matcher is required or nuclei writes no result.
    return (
        "id: insidia-web-ssti\n"
        "info:\n"
        "  name: insidia ssti\n"
        "  author: insidia\n"
        "  severity: high\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        f'      - "{{{{BaseURL}}}}{path}"\n'
        "    matchers:\n"
        "      - type: word\n"
        "        part: body\n"
        "        words:\n"
        '          - "49"\n'
    )


def _zap_plan(url: str, workspace: Path, report: str) -> str:
    return (
        "env:\n"
        "  contexts:\n"
        "    - name: insidia\n"
        "      urls:\n"
        f"        - {url}\n"
        "  parameters:\n"
        "    failOnError: false\n"
        "    progressToStdout: false\n"
        "jobs:\n"
        "  - type: requestor\n"
        "    requests:\n"
        "      - url: "
        f"{url}\n"
        "        method: GET\n"
        "  - type: report\n"
        "    parameters:\n"
        "      template: traditional-json\n"
        f"      reportDir: {workspace}\n"
        f"      reportFile: {report}\n"
    )


def _program(engine: str) -> str:
    from insidia.engines import program_for

    if engine not in BY_NAME:
        raise ValueError(engine)
    return program_for(engine)


_PROVIDER_JS = """\
class InsidiaRelay {
  id() {
    return "insidia-relay";
  }

  async callApi(prompt) {
    const text = typeof prompt === "string" ? prompt : prompt.prompt;
    const response = await fetch(process.env.INSIDIA_RELAY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + process.env.INSIDIA_RELAY_TOKEN,
      },
      body: JSON.stringify({ prompt: text }),
    });
    const body = await response.json();
    return { output: body.text };
  }
}

module.exports = InsidiaRelay;
"""

_PYRIT_PY = """\
import asyncio
import os

from pyrit.executor.attack import PromptSendingAttack
from pyrit.prompt_target import HTTPTarget
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


def _text(*, response):
    body = response.json()
    text = body["text"]
    if not isinstance(text, str):
        raise RuntimeError("relay response was not text")
    return text


async def _run() -> None:
    await initialize_pyrit_async(IN_MEMORY, load_defaults=False)
    url = os.environ["INSIDIA_RELAY_URL"]
    token = os.environ["INSIDIA_RELAY_TOKEN"]
    raw = "\\n".join(
        (
            f"POST {url} HTTP/1.1",
            "Content-Type: application/json",
            f"Authorization: Bearer {token}",
            "",
            '{"prompt": "{PROMPT}"}',
        )
    )
    target = HTTPTarget(http_request=raw, callback_function=_text, use_tls=False)
    attack = PromptSendingAttack(objective_target=target)
    await attack.execute_async(objective="secret")


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
"""

_DEEPTEAM_PY = """\
import json
import os
import urllib.request

from deepteam import red_team
from deepteam.attacks.single_turn import Base64
from deepteam.vulnerabilities import Bias


async def model_callback(prompt: str) -> str:
    payload = json.dumps({"prompt": prompt}).encode()
    request = urllib.request.Request(
        os.environ["INSIDIA_RELAY_URL"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + os.environ["INSIDIA_RELAY_TOKEN"],
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode())
    text = body["text"]
    if not isinstance(text, str):
        raise RuntimeError("relay response was not text")
    return text


def main() -> None:
    red_team(
        model_callback=model_callback,
        vulnerabilities=[Bias(types=["race"])],
        attacks=[Base64()],
        async_mode=False,
        ignore_errors=False,
    )


if __name__ == "__main__":
    main()
"""
