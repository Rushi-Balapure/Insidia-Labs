---
title: Report
description: Read Insidia scan findings, evidence, remediation guidance, and skipped checks. Open the HTML report or use JSON, SARIF, and benchmark output in automation.
---

```bash
insidia report --open
insidia report <run-id> --open
```

`--open` launches the HTML file in a browser. The file is self-contained. It does not call home.

## Review the result

1. Check **execution status** first. An incomplete run cannot pass, even when it has no findings.
2. Read the **policy verdict** and control coverage. Inspect skips and errors to understand which checks did not complete.
3. Review findings by severity, then read the engine name, masked evidence, and fix guidance. A finding is a starting point for investigation; check that the evidence applies to your app.
4. Fix the issue and scan again. Compare the affected control and finding across runs, along with execution status.

For a run that did not complete, start with [Troubleshooting](/docs/guides/troubleshooting/).

## Run files

Each run directory `.insidia/runs/<run-id>/` contains:

| File | What it is |
| --- | --- |
| `report.html` | Execution and policy status, framework scores, control coverage, and findings with engine, severity, masked evidence, fix guidance, and rerun commands. |
| `findings.json` | The same findings as JSON, for an agent or a script. |
| `results.sarif` | SARIF results. A high severity is an error. Anything else in the file is a warning. |
| `benchmark.json` | Policy name, execution status, policy verdict, control results, skips, and framework scores. |
| `manifest.json` | The run's policy, coverage, configuration digest, and checksums of the four result files. Used to verify artifacts and rerun a scan. |

Evidence that looks like a secret is masked before it is written. You will see a token such as `[AWS_ACCESS_KEY len=20 fp=3f9a1c07]`, not the raw value.

`insidia report` prints the path and exits 0 when the file is present. A scan exits 0 for a completed pass, 1 when any check found a problem, 2 for an incomplete run with no finding or an error, and 130 for cancellation. Use the scan's exit code in CI, not the report command's. Opening a report does not establish that all required checks completed.

The HTML report follows your system's light or dark theme and works offline. Its framework tables describe the controls tested in that run; they are not a security certification.

## Check a fix

```bash
insidia rerun
```

This repeats the latest run's policy and coverage using the current config. You can pass a run id to repeat an earlier run. If the config has changed, the CLI stops: review the changes before using `insidia rerun --yes`.

To choose different coverage or a different config deliberately, use `insidia scan` with the corresponding flags. See [CLI reference](/docs/reference/cli/).
