---
title: Insidia Cloud
description: The hosted attacker is not open yet. The CLI does not need it.
---

Insidia Cloud is the paid hosted service: an attacker and a judge that run on Insidia's GPUs, custom attacks for your app's tools, and later a dashboard that launches scans. The code in the `cloud/` directory is Apache-2.0. The thing you would pay for is the operation.

It is not open in this pre-release. There is no `insidia login` command yet. A scan does not call Insidia Cloud unless you later point a model role at it.

Design-partner access is planned for December 2026, for three teams, against staging, with written authorization. Write to [insidialabs@gmail.com](mailto:insidialabs@gmail.com).

Until then, configure your own model or run with none:

```yaml
models:
  attacker:
    provider: openai-compatible
    base_url: http://127.0.0.1:11434/v1
    model: qwen3
```

Add `127.0.0.1` to scope if it is not already there. Checks that need a model stay skipped when `models` is empty.

General-purpose models often refuse to write attacks. That is a reason the hosted attacker exists. This page does not claim a measured lift over those models.
