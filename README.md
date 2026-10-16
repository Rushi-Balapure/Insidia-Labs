<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/readme/hero-dark.png">
    <img src="brand/readme/hero-light.png" alt="Insidia Labs. Open-source security testing for AI apps, agents, and the web apps and APIs around them." width="100%">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-ED7B39?style=flat-square&labelColor=101028"></a>
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-E33D86?style=flat-square&labelColor=101028">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-B93486?style=flat-square&labelColor=101028">
  <img alt="Linux, macOS, Windows" src="https://img.shields.io/badge/os-linux%20%7C%20macos%20%7C%20windows-8D307C?style=flat-square&labelColor=101028">
  <a href="https://insidialabs.com"><img alt="Website" src="https://img.shields.io/badge/web-insidialabs.com-F6C13F?style=flat-square&labelColor=101028"></a>
  <a href="https://insidialabs.com/docs/"><img alt="Docs" src="https://img.shields.io/badge/docs-insidialabs.com%2Fdocs-ED7B39?style=flat-square&labelColor=101028"></a>
</p>

<p align="center">
  <a href="https://insidialabs.com"><b>Website</b></a> ·
  <a href="#install"><b>Install</b></a> ·
  <a href="#quickstart"><b>Quickstart</b></a> ·
  <a href="#insidiayaml"><b>insidia.yaml</b></a> ·
  <a href="https://insidialabs.com/docs/"><b>Docs</b></a> ·
  <a href="#development"><b>Development</b></a>
</p>

<br>

Insidia is an open-source CLI for security testing AI apps, agents, and the web apps and APIs around them. It runs checks locally and writes findings to HTML, JSON, and SARIF. A scan does not need an account.

The public site is [insidialabs.com](https://insidialabs.com). Documentation is on the same host at [insidialabs.com/docs](https://insidialabs.com/docs/).

This is a pre-release project. Built-in checks are currently classified as fixture-only, and external engine integrations as experimental. See the [readiness inventory](core/insidia/readiness.py) for current limitations and the [master plan](plans/00-master-plan.md) for planned work.

## Install

Python 3.12 or newer. Install from this repository. Insidia is not on PyPI.

```bash
# uv (recommended)
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"

# pipx
pipx install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

Pin a commit or tag by adding it before the fragment: `...Insidia-Labs@<rev>#subdirectory=core`.

`insidia engines install garak zap` installs those engines. With no names, `insidia engines install` only reports that the built-in probes are already available. `insidia doctor` checks Python, the config file, model endpoints, and which engines can run here, such as ZAP, which needs Java. It does not check that your app answers. `insidia --version` prints the version and build commit. No release has been published yet, so there is no signed wheel or container image; install from git as above. The install page on the site is [insidialabs.com/docs/start/install](https://insidialabs.com/docs/start/install/).

## Quickstart

From the project you want to test:

```bash
insidia init
insidia doctor
insidia scan --policy L1 --yes
insidia report --open
```

`insidia init` writes `insidia.yaml`. A scan reads that file and does not take a URL. The generated target is a sample chat endpoint at `http://127.0.0.1:8080/chat`; it does not start an app. Before scanning, edit `targets` to match your running app's URL, request format, and response selector.

| Exit code | Meaning |
| --- | --- |
| `0` | The run finished and the policy passed. |
| `1` | A check found a problem, so the policy failed. This holds even if another check did not finish. |
| `2` | The run was incomplete with no finding, or an error stopped it. |
| `130` | The run was cancelled. |

`--json` prints the run id, findings, and skips. `--yes` is only required when `scope` includes a host other than localhost. The same steps are on [the quickstart](https://insidialabs.com/docs/start/quickstart/).

## insidia.yaml

This is the file `insidia init` writes:

```yaml
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
  - host: 127.0.0.1
  - host: "::1"
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
    request_template: '{"messages": {{conversation_json}}}'
    response_selector: "$.choices[0].message.content"
    rate_limit:
      rps: 5
      concurrency: 1
models: {}
```

| Field | What it means |
| --- | --- |
| `version` | Must be `1`. |
| `policy` | `L1` is the policy a scan runs. `L2` and `L3` are not available. |
| `coverage` | `standard` runs one engine per check. `thorough` runs every installed engine that covers it. |
| `scope` | Hostnames Insidia may contact. A host other than localhost, `127.0.0.1`, or `::1` needs `authorized: true`, which you set. |
| `targets` | Apps, APIs, or repositories to test. The key (`app` above) is the name in the report. `kind` is `chat`, `agent`, `rag`, `mcp`, `web`, `api`, or `repo`. |
| `models` | Optional `attacker` and `judge`. `{}` means no model. A model `base_url` host must also be in `scope`. |

```yaml
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
    auth:
      header: Authorization
      secret_ref: env:APP_TOKEN
      scheme: Bearer
```

`secret_ref` is `env:` plus a variable name. The value stays in the environment and is not written into the file. Unknown fields are rejected. Every field, including rate limits, request templates, and repository targets, is on [insidialabs.com/docs/start/config](https://insidialabs.com/docs/start/config/). Scope rules are on [insidialabs.com/docs/start/scope](https://insidialabs.com/docs/start/scope/).

### Hand it to a coding agent

Paste this into Claude Code, Cursor, Codex, or any agent that can run a shell:

```text
Test this app with Insidia. Only scan localhost, and open the report when you're done.
```

You confirm the hosts. The agent should install the CLI, keep the scope you named, read `.insidia/runs/<run-id>/findings.json`, and open `report.html`. The skill is `skills/insidia/SKILL.md` (`npx skills add Rushi-Balapure/Insidia-Labs`, which needs Node.js 22 or later). `insidia mcp` is the local MCP server over stdio. It reads newline-delimited JSON-RPC or Content-Length framing and negotiates MCP 2025-06-18, 2025-03-26, or 2024-11-05. The CLI remains the contract: `--json`, `--yes`, and stable exit codes.

## Planned coverage

These are the areas Insidia is built to cover. Not every row has a check that works on any app yet. Several built-in checks only recognise Insidia's own benchmark app, and those show as "not tested" in a report unless they find something or an installed engine covers them. The coverage table in each report says what that scan actually tested.

| AI and agent layer | Application layer |
| --- | --- |
| Direct and indirect prompt injection | Template injection, command injection, path access, and SSRF |
| Jailbreaks and policy bypass | BOLA/IDOR, BFLA, mass assignment, JWT |
| System prompt and secret leakage | Secrets in code and history |
| Tool misuse and excessive agency | Vulnerable dependencies and container images |
| RAG and memory poisoning, cross-tenant bleed | Scripted chains from the AI layer into the app |
| MCP and skill supply chain | |

Each finding names the engine that sent the attack. For relay engines such as garak and promptfoo, Insidia's own check judges the reply. With `--coverage thorough`, a finding that several engines reported names each one. A secret in evidence is masked, for example `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`. The support notes are on [what it tests](https://insidialabs.com/docs/concepts/what-it-tests/).

### Coverage

| Mode | What runs |
| --- | --- |
| `standard` (default) | One engine per attack family, the highest-priority one |
| `thorough` | Every installed engine that covers the family. A finding seen by more than one engine names each engine. That is not independent confirmation |

```bash
insidia scan --policy L1 --coverage thorough --yes
```

A scan with no model still runs every check that does not need one. Checks that need a model are skipped and listed in `benchmark.json`. A skip is not a pass.

## Benchmark

`insidia scan --policy L1` runs the baseline. L2 and L3 are not available. The same notes are on [the benchmark page](https://insidialabs.com/benchmark).

| Level | What it adds |
| --- | --- |
| **L1** | Baseline checks. No model. The default from `insidia init`. Available. |
| **L2** | Unavailable. It is not a separate judge-scored level yet. |
| **L3** | Unavailable. It is not a separate model-generated level yet. |

The run directory `.insidia/runs/<run-id>/` contains:

| File | Contents |
| --- | --- |
| `benchmark.json` | Policy name, pass or fail, control results, skips |
| `findings.json` | Findings, including engine, probe, severity, and taxonomy |
| `results.sarif` | SARIF for CI code scanning |
| `report.html` | One HTML file. `insidia report --open` opens it |

The scanner matrix under [`benchmark/`](benchmark) contains sandboxed targets and planted ground truth for regression testing. Passing those fixtures does not establish detection accuracy on independent apps. The matrix is separate from the policy you run on your own app.

Point a model at any OpenAI-compatible endpoint, including Ollama, by listing it in `insidia.yaml` and adding that host to `scope`.

## Commands

```text
insidia init                 write insidia.yaml in this directory
insidia doctor               check Python, the config file, and installed engines
insidia engines list         show each engine, its license, and whether it is installed
insidia engines install ENGINE ...
insidia policy list|show|validate
insidia scan                 run the checks in insidia.yaml and write a report
insidia report [run-id]      print or open the HTML report
insidia rerun [run-id]       scan again with the recorded policy and config
insidia mcp                  serve local MCP tools on stdin and stdout
insidia --version            print the version and build commit
```

Flags that go before or after the command: `--config PATH` (default `insidia.yaml`), `--json`, `--yes`, `--quiet` / `-q`, and `--no-color`. `insidia scan` also takes `--policy` and `--coverage`. The same list is on [the CLI reference](https://insidialabs.com/docs/reference/cli/). `insidia -h` prints it in the terminal.

## Site

| Page | Where |
| --- | --- |
| Home | [insidialabs.com](https://insidialabs.com) |
| Docs | [insidialabs.com/docs](https://insidialabs.com/docs/) |
| Install | [insidialabs.com/docs/start/install](https://insidialabs.com/docs/start/install/) |
| Quickstart | [insidialabs.com/docs/start/quickstart](https://insidialabs.com/docs/start/quickstart/) |
| insidia.yaml | [insidialabs.com/docs/start/config](https://insidialabs.com/docs/start/config/) |
| CLI reference | [insidialabs.com/docs/reference/cli](https://insidialabs.com/docs/reference/cli/) |
| Film | [insidialabs.com/film](https://insidialabs.com/film) |
| Credits | [insidialabs.com/credits](https://insidialabs.com/credits) |
| Security | [insidialabs.com/security](https://insidialabs.com/security) |
| Changelog | [insidialabs.com/changelog](https://insidialabs.com/changelog) |

## Repository

| Path | What it holds |
| --- | --- |
| [`core/`](core) | The `insidia` package: CLI, configuration, scope guard, engines, probes, findings, and reports |
| [`benchmark/`](benchmark) | Scanner matrix, framework mappings, sandboxed targets, and regression tests |
| [`skills/insidia/`](skills/insidia) | Instructions for coding agents to install and run Insidia |
| [`Dockerfile`](Dockerfile) | CLI container image with the pinned scanner engines |
| [`site/`](site) | Marketing site, published at [insidialabs.com](https://insidialabs.com) |
| [`docs/`](docs) | Documentation, published at [insidialabs.com/docs](https://insidialabs.com/docs/) |
| [`brand/`](brand/README.md) | Logo, colors, and README artwork |
| [`plans/`](plans) | Roadmap, design documents, and implementation plans |

Start reading the scanner at [`core/insidia/cli.py`](core/insidia/cli.py), which handles commands. [`scan.py`](core/insidia/scan.py) coordinates scans, [`probes.py`](core/insidia/probes.py) executes checks, and [`adapters.py`](core/insidia/adapters.py) defines built-in probes and detection rules. External engine integrations live in [`upstream.py`](core/insidia/upstream.py).

## Development

CLI, from `core/`:

```bash
uv sync
uv run ruff check .
uv run mypy insidia
uv run pytest
```

Marketing site, from `site/`:

```bash
npm ci
npm test
npm run build  # builds the marketing site and docs
npm run links  # checks built links, anchors, and assets
npm run dev    # http://127.0.0.1:4321
```

For Vercel build settings and custom-domain setup, see [the site deployment guide](site/README.md).

Docs, from `docs/`:

```bash
npm ci
npm run check
npm run dev
```

## Credits

Each project keeps its own license. The full notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

| AI and agent layer | Application layer |
| --- | --- |
| [garak](https://github.com/NVIDIA/garak) · Apache-2.0 | [ZAP](https://github.com/zaproxy/zaproxy) · Apache-2.0 |
| [promptfoo](https://github.com/promptfoo/promptfoo) · MIT | [Nuclei](https://github.com/projectdiscovery/nuclei) · MIT |
| [PyRIT](https://github.com/Azure/PyRIT) · MIT | [Dalfox](https://github.com/hahwul/dalfox) · MIT |
| [DeepTeam](https://github.com/confident-ai/deepteam) · Apache-2.0 | [Trivy](https://github.com/aquasecurity/trivy) · Apache-2.0 |
| [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) · Apache-2.0 | [osv-scanner](https://github.com/google/osv-scanner) · Apache-2.0 |
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) · Apache-2.0 | [gitleaks](https://github.com/gitleaks/gitleaks) · MIT |
| [NuGuard](https://github.com/NuGuardAI/nuguard) · Apache-2.0 | [Bandit](https://github.com/PyCQA/bandit) · Apache-2.0 |
| | [gosec](https://github.com/securego/gosec) · Apache-2.0 |

Also [katana](https://github.com/projectdiscovery/katana) and [httpx](https://github.com/projectdiscovery/httpx), both MIT.

## License

[Apache-2.0](LICENSE). The Sora font in `brand/fonts/` is under the SIL Open Font License. The Insidia Labs name and logo are trademarks and are not part of the Apache license. See [NOTICE](NOTICE).

Contributing and disclosure: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md).

<br>

<p align="center">
  <img src="brand/logo/insidia-mark-512.png" alt="" width="56"><br>
  <sub>Built in Pune, India · <a href="mailto:insidialabs@gmail.com">insidialabs@gmail.com</a> · <a href="https://insidialabs.com">insidialabs.com</a></sub>
</p>
