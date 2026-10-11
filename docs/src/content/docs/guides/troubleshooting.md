---
title: Troubleshooting
description: Resolve configuration errors, unreachable targets, incomplete scans, and rerun problems.
---

Start with the command's error message and the latest report. A scan that exits `2` needs attention even when it has no findings.

## Missing configuration

Commands read `insidia.yaml` from your current directory by default. Run `insidia init` in your project if the file does not exist, then configure your target before scanning.

If the file is elsewhere, pass its path:

```bash
insidia doctor --config ./services/api/insidia.yaml
insidia scan --config ./services/api/insidia.yaml --policy L1
insidia report --config ./services/api/insidia.yaml --open
```

Runs are written beside the config, inside `.insidia/runs/`. Use the same `--config` path when opening a report or rerunning a scan.

## Configuration rejected

Unknown fields and unsupported values are errors. Compare your file with the [configuration reference](/docs/start/config/). Use `policy: L1`; L2 and L3 cannot run in this release.

For a repository target, use `kind: repo` and `path`. Other targets need a URL. Although the schema accepts a `command` target, local command execution is not available yet; expose a local HTTP endpoint instead.

## Target unreachable or response errors

Check these before repeating a scan:

1. Your app is running, and its host and port match `targets.<name>.url`.
2. Its host is listed in `scope`.
3. Its `method`, `request_template`, and `response_selector` match your app's API.
4. If it needs authentication, the environment variable named by `auth.secret_ref` is set in the terminal running Insidia.

Doctor validates the config and checks configured model endpoints. It does not test the target app's request and response shape. An exit code of `0` from doctor does not mean a scan will complete.

## Model setup problems

L1 does not require a model. To use no model, leave `models: {}`.

When you configure an attacker or judge, provide both `base_url` and `model`. Supported providers are `openai-compatible`, `anthropic`, and `gemini`. For Ollama, use `openai-compatible` with a base URL ending in `/v1`. The model host must also be in `scope`.

Read each `model.*` line in doctor's output. Its exit code reflects Python and configuration validity; a model connection problem can still appear in the checklist when doctor exits `0`.

## Scan incomplete or checks skipped

Open the [report](/docs/concepts/report/) and inspect execution status, control coverage, and skips. For scripts, `insidia scan --json --policy L1` includes `execution_status`, `policy_verdict`, and `skips`.

- A connection or engine error needs to be resolved before repeating the run.
- A check with no runnable probe may need an [installed engine](/docs/concepts/engines/) or a supported target type.
- Installing more tools does not add new checks to the policy. See [What it tests](/docs/concepts/what-it-tests/).

A policy verdict of `fail` can coexist with an incomplete execution: one check found a problem while another did not finish. A skip is not evidence of a pass.

## Scope confirmation

A non-local host requires `authorized: true` in `scope` and `--yes` at scan time. Add authorization only for hosts you have permission to test. Passing `--yes` does not bypass an unauthorized host. See [Scope](/docs/start/scope/).

## Rerun says the configuration changed

`insidia rerun` compares your current config with the digest recorded in the run. Review the changes, then use `insidia rerun --yes` if you intend to scan with the current file and the recorded policy and coverage.

## No report or no runs yet

A configuration error can stop a scan before a run is written. Resolve that error and scan again. If you already have a run, use the same config path as the original scan and pass its run id to `insidia report` when needed.

For an unresolved CLI problem, [open a GitHub issue](https://github.com/Rushi-Balapure/Insidia-Labs/issues) with the command, CLI revision, and masked error. For a vulnerability in Insidia itself, follow [the disclosure policy](https://github.com/Rushi-Balapure/Insidia-Labs/blob/main/SECURITY.md).
