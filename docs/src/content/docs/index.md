---
title: Insidia Labs
description: Install the Insidia CLI, scan localhost, and open the HTML report.
---

Insidia tests an AI app and the application around it in one local run. The CLI is free, pre-release, and installed from GitHub. [Insidia Cloud](cloud.md), the hosted attacker, is not open yet.

## Using a coding agent?

Install the skill:

```bash
npx skills add Rushi-Balapure/Insidia-Labs
```

Then paste this into Claude Code, Cursor, Codex, or any agent that can run a shell:

```text
Test this app with Insidia. Only scan localhost, and open the report when you're done.
```

You confirm the hosts. The agent installs the CLI, writes `insidia.yaml`, runs the scan, reads the findings, and opens the report. Do not let it add a host you did not name.

The skill lives at `skills/insidia/SKILL.md`. An agent that speaks MCP can run `insidia mcp`. Start with [Use a coding agent](start/agent.md), or [Install](start/install.md) if you would rather run it yourself.

## Run it yourself

1. [Install](start/install.md) the CLI.
2. Follow the [quickstart](start/quickstart.md).
3. Read [scope](start/scope.md) before you add a host.
