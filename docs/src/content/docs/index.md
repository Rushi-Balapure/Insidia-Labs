---
title: Insidia Labs
description: Install the Insidia CLI, scan localhost, and open the HTML report.
---

Insidia tests an AI app and the application around it in one local run. The CLI is free, pre-release, and installed from GitHub. [Insidia Cloud](cloud.md), the hosted attacker, is not open yet.

## Using a coding agent?

Paste this into Claude Code, Cursor, Codex, or any agent that can run a shell:

```text
Test this app with Insidia. Only scan localhost, and open the report when you're done.
```

You confirm the hosts. The agent installs the CLI, writes `insidia.yaml`, runs the scan, reads the findings, and opens the report. Do not let it add a host you did not name.

The installable skill and the MCP server ship with the public launch. Until then, the CLI is the contract. Start with [Install](start/install.md) if you would rather run it yourself.

## Run it yourself

1. [Install](start/install.md) the CLI.
2. Follow the [quickstart](start/quickstart.md).
3. Read [scope](start/scope.md) before you add a host.
