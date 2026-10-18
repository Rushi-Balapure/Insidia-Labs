---
title: Engines
description: The open-source engines Insidia runs, and the modules Insidia builds.
---

Insidia runs these projects and names them on each finding. Each keeps its own license.

| Engine | License | Layer |
| --- | --- | --- |
| [garak](https://github.com/NVIDIA/garak) | Apache-2.0 | AI |
| [promptfoo](https://github.com/promptfoo/promptfoo) | MIT | AI |
| [PyRIT](https://github.com/Azure/PyRIT) | MIT | AI |
| [DeepTeam](https://github.com/confident-ai/deepteam) | Apache-2.0 | AI |
| [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | MCP and skills |
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) | Apache-2.0 | MCP and skills |
| [NuGuard](https://github.com/NuGuardAI/nuguard) | Apache-2.0 | Agent code and AI-SBOM |
| [ZAP](https://github.com/zaproxy/zaproxy) | Apache-2.0 | Web and API |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Web and API |
| [Dalfox](https://github.com/hahwul/dalfox) | MIT | Web and API |
| [katana](https://github.com/projectdiscovery/katana) | MIT | Web |
| [httpx](https://github.com/projectdiscovery/httpx) | MIT | Web |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependencies and images |
| [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependencies |
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets |
| [Bandit](https://github.com/PyCQA/bandit) | Apache-2.0 | Python SAST |
| [gosec](https://github.com/securego/gosec) | Apache-2.0 | Go SAST |

Findings whose engine is `insidia` come from Insidia's own modules: indirect injection, RAG bleed, tool-trace checks, and scripted chains, among others.

```bash
insidia engines list
insidia engines install garak zap
```

A downloaded binary is checked against a pinned SHA-256 for that engine, version, and platform before it is unpacked or run. A mismatch stops the install. A platform with no pin is refused unless you pass `--allow-unverified`. Set `INSIDIA_ENGINE_MIRROR` to an `http` or `https` base URL to fetch those GitHub release files from a mirror. Only the `https://github.com` prefix changes. The pin stays on the canonical URL.

Nuclei, katana, and httpx start with the update check off. A scan does not contact ProjectDiscovery to look for a newer release. Trivy and osv-scanner stay offline unless you set `INSIDIA_VULN_DB=1`. Without it, Trivy is started with `--skip-db-update` and `--skip-java-db-update`, and osv-scanner is started with `--offline`. With it, Trivy contacts `mirror.gcr.io` and `ghcr.io`, and osv-scanner contacts `api.osv.dev` and may contact `api.deps.dev`. That traffic is outside `scope`, and the variable is not a scope bypass. See [Data handling](/docs/security/data/).

`insidia engines install` downloads toolchains from PyPI, GitHub releases, and the ZAP host.

Promptfoo remote generation stays off unless you turn it on. A local scan should not send your prompts to an engine vendor.

Notices for shipped dependencies are in `THIRD_PARTY_NOTICES.md` in the repository.
