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
| `report.html` | Execution and policy status, framework scores, control coverage, and findings with engine, severity, masked evidence, fix guidance, and rerun commands. |
| `findings.json` | The same findings as JSON, for an agent or a script. |
| `results.sarif` | SARIF results. A high severity is an error. Anything else in the file is a warning. |
| `benchmark.json` | Policy name, execution status, policy verdict, control results, skips, and framework scores. |
| `manifest.json` | The run's policy, coverage, configuration digest, and checksums of the four result files. Used to verify artifacts and rerun a scan. |

Evidence that looks like a secret is masked before it is written. You will see a token such as `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`, not the raw value.

`insidia report` prints the path and exits 0 when the file is present. A scan exits 0 for a completed pass, 1 for a completed failure, 2 for an incomplete run or an error, and 130 for cancellation. Use the scan's exit code in CI, not the report command's. Opening a report does not establish that all required checks completed.

The HTML report follows your system's light or dark theme and works offline. Its framework tables describe the controls tested in that run; they are not a security certification.
