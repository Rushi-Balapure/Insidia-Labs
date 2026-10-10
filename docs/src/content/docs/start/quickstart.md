---
title: Quickstart
description: Write a config, scan localhost, and open the report.
---

From the project you want to test:

```bash
insidia init
insidia doctor
insidia scan --policy L1 --yes
insidia report --open
```

`insidia init` writes `insidia.yaml` in the current directory. The scope is localhost, and the sample target is a chat endpoint at `http://127.0.0.1:8080/chat`. Change `targets` to match your app before you treat the result as meaningful. Target kinds are `chat`, `agent`, `rag`, `mcp`, `web`, `api`, and `repo`.

`insidia scan` exits 0 when the policy passes and 1 when it fails. `--json` prints the run id, findings, and skips as JSON. `--yes` confirms a scope that includes a non-local host. Without `--yes`, that scan stops.

The run lands in `.insidia/runs/<run-id>/`. See [Report](/docs/concepts/report/).

If doctor says an engine is missing, install it:

```bash
insidia engines list
insidia engines install
```

Next: [Scope](/docs/start/scope/).
