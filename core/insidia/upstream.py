"""Phase 1B adapters. Each engine is one value. The runner does not grow a branch."""

from __future__ import annotations

import json
import re
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
    has_standalone,
)
from insidia.catalog import BY_NAME, SPECS, SSTI_PAYLOAD, STATIC_PROMPT, EngineSpec
from insidia.errors import EngineFailed

PROMPTFOO_ENV = {
    "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true",
    "PROMPTFOO_DISABLE_TELEMETRY": "1",
    "PROMPTFOO_DISABLE_SHARING": "1",
    "PROMPTFOO_DISABLE_UPDATE": "1",
}
_SSTI_PRODUCT = "49"
# NuGuard imports litellm, which fetches a price table from GitHub unless told not to.
NUGUARD_ENV = {
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    "LITELLM_TELEMETRY": "False",
}
_NUGUARD_SEVERITIES = frozenset({"critical", "high", "medium"})


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
        spec.name == "deepteam",
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
                "request_timeout": 180,
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
    if endpoint.model_url is None or endpoint.model is None:
        raise EngineFailed("deepteam needs an openai-compatible models.attacker")
    (workspace / "callback.py").write_text(_DEEPTEAM_PY)
    env = _script_env(endpoint)
    env["INSIDIA_MODEL_URL"] = endpoint.model_url
    env["INSIDIA_MODEL_NAME"] = endpoint.model
    env["DEEPTEAM_TELEMETRY_OPT_OUT"] = "YES"
    env["DEEPEVAL_TELEMETRY_OPT_OUT"] = "YES"
    if endpoint.model_key:
        env["INSIDIA_MODEL_KEY"] = endpoint.model_key
    # DeepTeam writes its own attack prompts and scores them with your model.
    # A local model is slower than a hosted one, so the run gets more time.
    return Invocation(
        _program("deepteam"),
        (str(workspace / "callback.py"),),
        "report.json",
        env=env,
        timeout=900,
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
            args = ("url", "--url", url, "--format", "json", "--output", report, "--silence")
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
        if engine == "nuguard":
            (workspace / "nuguard_run.py").write_text(_NUGUARD_PY)
            return Invocation(
                _program("nuguard"),
                (str(workspace / "nuguard_run.py"), source, str(workspace)),
                "report.json",
                env=NUGUARD_ENV,
                timeout=300,
            )
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
        if engine == "gitleaks":
            return _gitleaks_hits(loaded, spec)
        if isinstance(loaded, dict) and "error" in loaded and "Results" not in loaded:
            raise EngineFailed(f"{engine} reported an error")
        reader = _REPO_RULES.get(engine)
        if reader is None:
            return []
        return [EngineHit(spec.upstream, spec.probe, rule, rule) for rule in reader(loaded)]

    return parse


def _web_bodies(engine: str, report: Path) -> list[str]:
    if not report.is_file():
        raise EngineFailed("engine report is missing")
    text = report.read_text(errors="replace")
    if not text.strip():
        if engine == "nuclei":
            return []
        raise EngineFailed("engine report is empty")
    if engine in {"httpx", "katana"}:
        return []
    if engine == "nuclei":
        return _nuclei_bodies(text)
    loaded = _loads(text)
    if engine == "zap":
        return _zap_bodies(loaded)
    if engine == "dalfox":
        return _dalfox_bodies(loaded)
    return []


def _ssti_product(body: str) -> str | None:
    if SSTI_PAYLOAD in body or not has_standalone(_SSTI_PRODUCT, body):
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
        str(row.get(key, "")) for key in ("message_str", "inject_type", "cwe", "type_description")
    ).lower()
    return "ssti" in text or "template injection" in text or "cwe-1336" in text


def _http_body(raw: str) -> str:
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in raw:
            return raw.split(separator, 1)[1]
    return raw


def _load_json(report: Path) -> object:
    if not report.is_file():
        raise EngineFailed("engine report is missing")
    text = report.read_text(errors="replace").strip()
    if not text:
        raise EngineFailed("engine report is empty")
    loaded = _loads(text)
    if loaded is None:
        raise EngineFailed("engine report is empty")
    return loaded


def _loads(text: str) -> object | None:
    if not text:
        return None
    try:
        loaded: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EngineFailed("engine report is not valid JSON") from exc
    return loaded


def _bandit_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        raise EngineFailed("bandit report has an unexpected shape")
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


def _gitleaks_hits(loaded: object, spec: ProbeSpec) -> list[EngineHit]:
    if not isinstance(loaded, list):
        raise EngineFailed("gitleaks report has an unexpected shape")
    hits: list[EngineHit] = []
    for row in loaded:
        if not isinstance(row, dict):
            raise EngineFailed("gitleaks report has a malformed record")
        rule = row.get("RuleID")
        if not isinstance(rule, str) or not rule:
            raise EngineFailed("gitleaks report has a malformed record")
        file = row.get("File")
        line = row.get("StartLine")
        location = ""
        if isinstance(file, str) and file:
            location = f"{file}:{line}" if isinstance(line, int) else file
        evidence = row.get("Match")
        if not isinstance(evidence, str) or not evidence:
            evidence = rule
        severity = row.get("Severity")
        hits.append(
            EngineHit(
                spec.upstream,
                spec.probe,
                evidence,
                evidence,
                location,
                severity if isinstance(severity, str) else "",
            )
        )
    return hits


def _trivy_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict) or not isinstance(loaded.get("Results"), list):
        raise EngineFailed("trivy report has an unexpected shape")
    results = loaded["Results"]
    assert isinstance(results, list)
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


def _nuguard_rules(loaded: object) -> list[str]:
    if not isinstance(loaded, dict):
        return []
    rows = loaded.get("findings")
    if not isinstance(rows, list):
        return []
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("severity") not in _NUGUARD_SEVERITIES:
            continue
        rule = _nuguard_rule(row)
        if rule:
            found.append(rule)
    return found


def _nuguard_rule(row: dict[str, object]) -> str:
    identifier = row.get("finding_id")
    if isinstance(identifier, str):
        matched = re.search(r"NGA(?:-SC)?-\d+", identifier, re.IGNORECASE)
        if matched:
            return matched.group(0).upper()
    title = row.get("title")
    return title if isinstance(title, str) else ""


_REPO_RULES: dict[str, Callable[[object], list[str]]] = {
    "nuguard": _nuguard_rules,
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

_NUGUARD_PY = """\
import os
import subprocess
import sys
from pathlib import Path

source, workspace = sys.argv[1], Path(sys.argv[2])
exe = Path(sys.executable).with_name("nuguard.exe" if os.name == "nt" else "nuguard")
sbom = workspace / "app.sbom.json"
subprocess.run(
    [str(exe), "sbom", "generate", "--source", source, "--output", str(sbom), "--no-llm"],
    check=True,
)
# analyze exits 1 when it finds something. The report is the success signal.
subprocess.run(
    [
        str(exe), "analyze", "--sbom", str(sbom), "--source", source,
        "--format", "json", "--output", str(workspace / "report.json"),
        "--no-llm", "--no-osv", "--no-grype", "--no-trivy", "--no-checkov",
        "--no-semgrep", "--supply-chain-verify", "off",
    ],
)
sys.exit(0 if (workspace / "report.json").is_file() else 1)
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
    # httpx waits 5 seconds by default. A local model needs longer than that.
    target = HTTPTarget(http_request=raw, callback_function=_text, use_tls=False, timeout=180)
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

from deepeval.models import DeepEvalBaseLLM
from deepteam import red_team
from deepteam.attacks.single_turn import Base64
from deepteam.vulnerabilities import Bias


class AttackerModel(DeepEvalBaseLLM):
    # DeepTeam writes and scores its attacks with a model. This one is the
    # models.attacker you configured. No other service is called.
    def __init__(self):
        super().__init__(os.environ["INSIDIA_MODEL_NAME"])

    def load_model(self):
        return self

    def get_model_name(self):
        return os.environ["INSIDIA_MODEL_NAME"]

    def _ask(self, prompt):
        body = json.dumps(
            {
                "model": os.environ["INSIDIA_MODEL_NAME"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("INSIDIA_MODEL_KEY")
        if key:
            headers["Authorization"] = "Bearer " + key
        request = urllib.request.Request(
            os.environ["INSIDIA_MODEL_URL"] + "/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=300) as response:
            document = json.loads(response.read().decode())
        text = document["choices"][0]["message"]["content"]
        return text if isinstance(text, str) else ""

    def generate(self, prompt, schema=None):
        if schema is None:
            return self._ask(prompt)
        text = self._ask(prompt + " Reply with one JSON object and nothing else.")
        start = text.find("{")
        end = text.rfind("}")
        return schema.model_validate_json(text[start : end + 1])

    async def a_generate(self, prompt, schema=None):
        return self.generate(prompt, schema)


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
    with urllib.request.urlopen(request, timeout=180) as response:
        body = json.loads(response.read().decode())
    text = body["text"]
    if not isinstance(text, str):
        raise RuntimeError("relay response was not text")
    return text


def main() -> None:
    model = AttackerModel()
    red_team(
        model_callback=model_callback,
        vulnerabilities=[Bias(types=["race"])],
        attacks=[Base64()],
        simulator_model=model,
        evaluation_model=model,
        async_mode=False,
        ignore_errors=False,
    )


if __name__ == "__main__":
    main()
"""
