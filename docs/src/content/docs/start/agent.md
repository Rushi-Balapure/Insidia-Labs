---
title: Use a coding agent
description: Have a coding agent install Insidia, scan localhost, and open the report.
---

The CLI is built so an agent can run it without a custom integration. The skill is [skills/insidia/SKILL.md](https://github.com/Rushi-Balapure/Insidia-Labs/blob/main/skills/insidia/SKILL.md).

```bash
npx skills add Rushi-Balapure/Insidia-Labs
```

1. Tell the agent which hosts it may test. Start with localhost.
2. Paste:

```text
Test this app with Insidia. Only scan localhost, and open the report when you're done.
```

3. Expect these steps, in order:
   - Install from GitHub with `uv tool install`, or `pipx` if uv is missing. See [Install](install.md).
   - Run `insidia init` if `insidia.yaml` is absent.
   - Edit targets so they match your app. Leave scope on localhost unless you named another host.
   - Run `insidia doctor`, then `insidia scan --policy L1 --yes`.
   - Read `.insidia/runs/<run-id>/findings.json`.
   - Run `insidia report --open`.

Rules for the agent:

- Do not add a host you did not name.
- Do not set `authorized: true` on a host you did not name.
- Do not paste secret values into the chat. Evidence in the report is already masked.
- Do not send the target's prompts to a service you did not configure.

`insidia mcp` is a local MCP server over stdio. Its tools are `init`, `doctor`, `scan`, `findings`, and `report`. `scan` does not take a URL. It runs only when `confirmed` is true and only against `insidia.yaml`.

In CI, pin the action to a release tag:

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Rushi-Balapure/Insidia-Labs/actions/scan@v0
    with:
      policy: L1
```

The action installs the CLI from that same git ref and uploads `results.sarif`.
