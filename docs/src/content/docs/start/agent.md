---
title: Use a coding agent
description: Have a coding agent install Insidia, scan localhost, and open the report.
---

The CLI is built so an agent can run it without a custom integration.

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

`insidia mcp` and `npx skills add` are the public-launch interfaces. They are not in this pre-release. Shell access to the CLI is enough.
