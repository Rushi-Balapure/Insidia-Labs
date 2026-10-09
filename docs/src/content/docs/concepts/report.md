---
title: Report
description: The files a scan writes, and how to open the HTML report.
---

```bash
insidia report --open
insidia report <run-id> --open
```

`--open` launches the HTML file in a browser. The file is self-contained. It does not call home.

Each run directory `.insidia/runs/<run-id>/` contains:

| File | What it is |
| --- | --- |
| `report.html` | The policy result, a framework table (failed, passed, not tested), then a findings table: target, engine, probe, severity, and evidence. |
| `findings.json` | The same findings as JSON, for an agent or a script. |
| `results.sarif` | SARIF results. A high severity is an error. Anything else in the file is a warning. |
| `benchmark.json` | Policy name, pass or fail, control results, and skips. |

Evidence that looks like a secret is masked before it is written. You will see a token such as `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`, not the raw value.

`insidia report` prints the path and exits 0 when the file is present. The scan's exit code is the policy result: 0 passed, 1 failed. Use the scan's exit code in CI, not the report command's.

The HTML file in this pre-release is a readable table. A styled report with per-framework bars is later work. The data you need for that view is already in `benchmark.json` and `findings.json`.
