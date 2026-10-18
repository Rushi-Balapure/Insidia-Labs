---
title: Run in CI
description: Run L1 from a pinned GitHub Action, or upload SARIF yourself, and tell a policy failure from an incomplete scan.
---

First, get a [local scan](/docs/start/quickstart/) working. Check in the reviewed `insidia.yaml` so CI runs the same targets and scope.

## Prepare the runner

The CLI reads `insidia.yaml` at the repository root. Before running a scan:

1. Check out the git tag or full commit SHA you intend to test. Do not check out a branch name.
2. Set up Python 3.12 or newer.
3. Install your app's dependencies, start it on localhost, and wait until it is ready. A repository-only target does not need a server.
4. Install any optional engines your configuration needs on that runner. A fresh runner does not inherit the tools installed on your laptop.
5. Provide credentials through CI environment variables referenced by `secret_ref`, if your target needs them.

Keep localhost as the initial scope. A non-local target needs `authorized: true` in `insidia.yaml`. `insidia scan --yes` confirms that you meant to scan a non-local host. It does not bypass the scope check.

## Use the scan action

The repository ships a composite action at `actions/scan`. It installs one Insidia version, runs `insidia --json scan --policy <policy> --yes`, and uploads `results.sarif` from the `run_dir` in that JSON to GitHub code scanning, plus `report.html`, `findings.json`, and the SARIF file as a workflow artifact.

`version` is required. An empty or missing version fails the job before any scan. Pass the package version from the action checkout's `core/pyproject.toml`. The action installs `$INSIDIA_CORE` from the action checkout when its pyproject version matches. A mismatch or a missing core fails the job. It never installs `insidia` from PyPI.

The calling workflow checks out the repository to scan, and it must grant only these permissions:

```yaml
permissions:
  contents: read
  security-events: write
```

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  with:
    ref: ${{ github.sha }}

- uses: ./actions/scan
  with:
    version: "0.1.0"
    policy: L1
    fail-on-inconclusive: "true"
```

`github.sha` is the full commit for that workflow run. For a release, run the workflow on the tag or SHA you named and pass the `core/pyproject.toml` version shipped with the action. `0.1.0` above is the current package version; use the version in the action checkout you are testing.

`fail-on-inconclusive` controls exit code 2 only. Exit code 1 still fails the job. Exit code 0 passes. The default is `true`.

The action installs `$INSIDIA_CORE` from the action checkout when its pyproject version matches. A mismatch or a missing core fails the job. It never installs `insidia` from PyPI. The scan step writes stdout from `insidia --json scan` to `insidia-scan.json` before it returns the exit code, so a finished scan still records `run_dir` when the exit code is not 0. The action copies reports only from that `run_dir`. The path must be relative, or absolute and resolved inside the workspace. The final path must be a real directory, not a symlink, under `.insidia/runs`, and its basename must be a scan run id (`YYYYMMDDTHHMMSSZ-` plus six hex digits). If the JSON file is missing, `run_dir` is missing, or those checks fail, the action uploads nothing. It does not list `.insidia/runs` and it does not sort folder names, so a planted folder is not uploaded.

The action reads `insidia.yaml` from the repository. It has no input for a host. `.github/workflows/insidia-scan.yml` is an example that starts a small Python server on `127.0.0.1` and scans only that fixture. It is safe to run on a pull request: it checks out the pull request commit, does not clone another repository, and does not scan a host other than `127.0.0.1`.

Code scanning must be enabled for the SARIF upload to succeed. The upload uses `github/codeql-action/upload-sarif` pinned to commit `6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee` (`v4.39.0`). The artifact upload uses `actions/upload-artifact` pinned to commit `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (`v7.0.2`).

## Upload SARIF yourself

You can keep the scan step in your own workflow and upload the files without the composite action. Check out the tag or commit SHA, install that checkout with `uv`, and run the scan. Pass the policy through the environment if it is an input. Do not expand `${{ inputs.* }}` or `${{ github.* }}` inside a `run` script. Save stdout from `insidia --json scan` and copy reports from the `run_dir` in that JSON. Do not select a folder by sorting names under `.insidia/runs`.

```yaml
permissions:
  contents: read
  security-events: write

- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  with:
    ref: ${{ github.sha }}

- uses: astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e # v6

- name: Install Insidia from this checkout
  run: uv tool install --python 3.12 ./core

- name: Scan with Insidia
  run: |
    set -euo pipefail
    set +e
    insidia --json scan --policy L1 --yes > insidia-scan.json
    code=$?
    set -e
    exit "$code"

- name: Collect scan reports
  if: always()
  run: |
    set -euo pipefail
    dest="insidia-reports"
    rm -rf "$dest"
    mkdir -p "$dest"
    run_dir=""
    if [ -f insidia-scan.json ]; then
      run_dir="$(python3 - insidia-scan.json <<'PY'
    import json
    import os
    import re
    import sys
    from pathlib import Path

    pattern = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    try:
        document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(0)
    if not isinstance(document, dict):
        raise SystemExit(0)
    raw = document.get("run_dir")
    if not isinstance(raw, str) or raw == "":
        raise SystemExit(0)
    try:
        candidate = Path(raw)
        given = candidate if candidate.is_absolute() else workspace / candidate
        if given.is_symlink():
            raise SystemExit(0)
        resolved = given.resolve(strict=True)
        if resolved.is_symlink() or not resolved.is_dir():
            raise SystemExit(0)
        relative = resolved.relative_to(workspace)
    except (OSError, ValueError):
        raise SystemExit(0)
    if relative.parts != (".insidia", "runs", resolved.name):
        raise SystemExit(0)
    if pattern.fullmatch(resolved.name) is None:
        raise SystemExit(0)
    text = str(resolved)
    if "\n" in text or "\x00" in text:
        raise SystemExit(0)
    print(text)
    PY
      )"
    fi
    if [ -n "$run_dir" ]; then
      for name in results.sarif report.html findings.json; do
        if [ -f "$run_dir/$name" ] && [ ! -L "$run_dir/$name" ]; then
          cp -- "$run_dir/$name" "$dest/$name"
        fi
      done
    fi

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: insidia-reports/results.sarif

- name: Save scan reports
  if: always()
  uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
  with:
    name: insidia-reports
    path: insidia-reports/
    if-no-files-found: warn
    include-hidden-files: true
    retention-days: 14
```

The copy step runs after a failed scan as well as a pass. The scan writes `insidia-scan.json` before it returns the exit code, so a finished scan still has a `run_dir`. Copy the run files out of that directory before uploading them. If the JSON file or `run_dir` is missing, or the directory is not a real run directory under `.insidia/runs`, copy nothing. A setup error before the scan writes a run may leave no artifacts.

## Interpret the result

| Scan exit code | CI meaning |
| --- | --- |
| `0` | All applicable checks completed and the policy passed. |
| `1` | A check found a problem and the policy failed, even if another check did not finish. Review findings. |
| `2` | Execution was incomplete with no finding, or an error stopped the scan. Resolve the error or missing coverage. |
| `130` | Execution was cancelled. |

The scan step returns the CLI's exit code. Keep failures visible in the job; `continue-on-error` would let a policy failure or incomplete run proceed without failing that step. With the scan action, set `fail-on-inconclusive` to `false` only when exit code 2 should not fail the job. Exit code 1 still fails.

Use `execution_status` and `policy_verdict` together when consuming JSON from a shell command. A failed verdict can appear in an incomplete run, and an empty findings list does not establish a pass.

## Use a different CI system

Install the CLI from a tested tag or commit SHA using the [installation guide](/docs/start/install/), start the target, and run:

```bash
insidia scan --policy L1 --json
```

Preserve that command's exit code and archive `.insidia/runs/` even when it fails. If you use `--config PATH`, artifacts are written beside that config instead. `insidia report` returning `0` only confirms an existing report; it is not the scan result.

Next: [Read a report](/docs/concepts/report/) or [Troubleshooting](/docs/guides/troubleshooting/).
