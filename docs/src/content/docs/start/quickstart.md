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

`insidia init` writes `insidia.yaml` in the current directory. The scope is localhost, and the sample target is a chat endpoint at `http://127.0.0.1:8080/chat`. Change `targets` so `url` is your app before you treat the result as meaningful. Every field in that file is listed in [insidia.yaml](/docs/start/config/).

`insidia scan` exits 0 for a completed policy pass, 1 for a completed policy failure, and 2 for an incomplete run or an error. A cancelled run exits 130. `--json` includes the run id, execution status, policy verdict, findings, and skips. `--yes` confirms a scope that includes a non-local host. Without `--yes`, that scan stops.

The run lands in `.insidia/runs/<run-id>/`. See [Report](/docs/concepts/report/).

If doctor says an engine is missing, install it:

```bash
insidia engines list
insidia engines install garak zap
```

Next: [insidia.yaml](/docs/start/config/), then [Scope](/docs/start/scope/).
