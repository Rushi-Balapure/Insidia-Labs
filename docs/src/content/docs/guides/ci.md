---
title: Run in CI
description: Run L1 in GitHub Actions, preserve reports, and distinguish policy failures from incomplete scans.
---

First, get a [local scan](/docs/start/quickstart/) working. Check in the reviewed `insidia.yaml` so CI runs the same targets and scope.

## Prepare the runner

The [Insidia scan action](https://github.com/Rushi-Balapure/Insidia-Labs/blob/main/actions/scan/action.yml) reads `insidia.yaml` at the repository root. Before it runs:

1. Check out your repository.
2. Set up Python 3.12 or newer.
3. Install your app's dependencies, start it on localhost, and wait until it is ready. A repository-only target does not need a server.
4. Install any optional engines your configuration needs on that runner. A fresh runner does not inherit the tools installed on your laptop.
5. Provide credentials through CI environment variables referenced by `secret_ref`, if your target needs them.

Keep localhost as the initial scope. The action passes `--yes`; a non-local target still needs explicit authorization in your configuration.

## Add the scan step

For GitHub repositories with code scanning enabled, add `security-events: write` to the job's permissions so the action can upload SARIF. Retain `contents: read` for checkout:

```yaml
permissions:
  contents: read
  security-events: write
```

Add these steps **after your app is ready**, inside the job's `steps` list:

```yaml
- name: Scan with Insidia
  uses: Rushi-Balapure/Insidia-Labs/actions/scan@main
  with:
    policy: L1

- name: Save scan reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: insidia-reports
    path: .insidia/runs/
    include-hidden-files: true
    if-no-files-found: warn
    retention-days: 14
```

`@main` follows development changes. Replace it with a tested commit SHA for a repeatable CI gate, and pin the other actions to tested revisions too. Insidia's action installs the CLI from the same ref as the action.

The artifact step runs after a failed scan as well as a pass. `include-hidden-files` is needed because `.insidia` is a hidden directory; limit the upload to the run artifacts as shown. See the [upload-artifact documentation](https://github.com/actions/upload-artifact#uploading-hidden-files).

The scan action attempts to upload `results.sarif` whenever a run produced it. The HTML report and other run files remain available through the artifact step. A setup error before the scan writes a run may leave no artifacts.

## Interpret the result

| Scan exit code | CI meaning |
| --- | --- |
| `0` | All applicable checks completed and the policy passed. |
| `1` | A check found a problem and the policy failed, even if another check did not finish. Review findings. |
| `2` | Execution was incomplete with no finding, or an error stopped the scan. Resolve the error or missing coverage. |
| `130` | Execution was cancelled. |

The action returns the scan's exit code. Keep failures visible in the job; `continue-on-error` would let a policy failure or incomplete run proceed without failing that step.

Use `execution_status` and `policy_verdict` together when consuming JSON from a shell command. A failed verdict can appear in an incomplete run, and an empty findings list does not establish a pass.

## Use a different CI system

Install the CLI from a tested revision using the [installation guide](/docs/start/install/), start the target, and run:

```bash
insidia scan --policy L1 --json
```

Preserve that command's exit code and archive `.insidia/runs/` even when it fails. If you use `--config PATH`, artifacts are written beside that config instead. `insidia report` returning `0` only confirms an existing report; it is not the scan result.

Next: [Read a report](/docs/concepts/report/) or [Troubleshooting](/docs/guides/troubleshooting/).
