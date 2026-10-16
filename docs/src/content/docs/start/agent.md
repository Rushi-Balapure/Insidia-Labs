---
title: Use a coding agent
description: Have a coding agent install Insidia, scan localhost, and open the report.
---

The CLI is built so an agent can run it without a custom integration. The skill is [skills/insidia/SKILL.md](https://github.com/Rushi-Balapure/Insidia-Labs/blob/main/skills/insidia/SKILL.md).

```bash
npx skills add Rushi-Balapure/Insidia-Labs
```

`npx skills` needs Node.js 22 or later; on Node 20 it exits with an error before installing anything. Check with `node --version`.

1. Tell the agent which hosts it may test. Start with localhost.
2. Paste:

```text
Test this app with Insidia. Only scan localhost, and open the report when you're done.
```

3. Expect these steps, in order:
   - Install from GitHub with `uv tool install`, or `pipx` if uv is missing. See [Install](/docs/start/install/).
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

The agent should treat exit code `2` as an incomplete run, not a pass, and `130` as a cancelled one. See [exit codes](/docs/reference/cli/).

`insidia mcp` is a local MCP server over stdio. It accepts newline-delimited JSON-RPC, as current MCP clients send, and the older Content-Length framing, and it negotiates protocol versions 2025-06-18, 2025-03-26, and 2024-11-05. Its tools are `init`, `doctor`, `scan`, `findings`, and `report`. `scan` does not take a URL. It runs only when `confirmed` is true and only against `insidia.yaml`.

To automate the same scan, follow [Run in CI](/docs/guides/ci/). That guide covers runner setup, CLI installation, SARIF, and preserving reports after a failure.
