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

Promptfoo remote generation stays off unless you turn it on. A local scan should not send your prompts to an engine vendor.

Notices for shipped dependencies are in `THIRD_PARTY_NOTICES.md` in the repository.
