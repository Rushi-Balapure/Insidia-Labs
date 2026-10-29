---
name: insidia
description: Scan a local AI app or web target with Insidia and open the HTML report. Use when the user asks to test an app with Insidia, run an AI or application security scan, or check prompt injection, data leakage, or web flaws on a host they named.
---

# Insidia

Insidia scans an app on the user's machine and writes one HTML report. The CLI is the contract. Prefer `insidia mcp` when the agent speaks MCP. Otherwise run the commands below.

## Install

From the public GitHub repo. Do not use PyPI.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs-Argus@v1.0.0#subdirectory=core"
```

If `uv` is missing:

```bash
pipx install "git+https://github.com/Rushi-Balapure/Insidia-Labs-Argus@v1.0.0#subdirectory=core"
```

The `@v1.0.0` in the URL pins the release. `insidia --version` prints the version and the commit it was built from.

When Insidia is already installed, run `insidia upgrade --check`. If it reports a newer release, tell the user and run `insidia upgrade` only when they agree. A copy too old to have `upgrade` is updated by rerunning the install command with `--force`.

This skill installs with `npx skills add Rushi-Balapure/Insidia-Labs-Argus`, which needs Node.js 22 or later.

## Sequence

1. Ask the user which hosts may be tested. Start with localhost when they have not named another host.
2. Run `insidia init` when `insidia.yaml` is absent. It writes a localhost scope. Do not overwrite an existing file.
3. Edit targets so the URL matches the user's app. Leave scope on localhost unless the user named another host.
4. Run `insidia doctor`.
5. Run `insidia scan --policy L1 --yes` only after the user has confirmed the hosts in `insidia.yaml`. The scan does not open a browser.
6. Read `.insidia/runs/<run-id>/findings.json`. Each finding names `engine`, `probe`, `severity`, and `remediation`. Evidence is already masked.
7. Propose a fix from the `remediation` field. Do not invent a different attack to try.
8. Run `insidia report --open` so the user sees `report.html`.
9. After a fix, run the same scan again and compare the new `findings.json`.

`insidia scan` exit codes:

- `0`: the run completed and the policy passed. Still check the report's coverage; "not tested" items were not checked.
- `1`: a check found a problem. This holds even when another check did not finish.
- `2`: the run was incomplete with no finding, or an error stopped it. Read the error or the skipped checks and fix the setup. Do not report this as a pass.
- `130`: the user cancelled the scan.

`--json` prints a single object with `run_id`, `execution_status`, `policy_verdict`, `findings`, `skips`, and `run_dir`. Read `execution_status` and `policy_verdict`, not only `passed`.

## MCP

`insidia mcp` speaks MCP over stdio. Tools are `init`, `doctor`, `scan`, `findings`, and `report`. `scan` runs only when `confirmed` is true, and it reads `insidia.yaml`. It does not take a URL. A localhost scope can run that way. Any other host needs `insidia mcp --allow-remote` or `INSIDIA_MCP_ALLOW_REMOTE=1` set by the person who starts the server. Do not treat `confirmed: true` as permission for a non-local host.

## Rules

- Confirm the target with the user before the first scan.
- Do not add a host the user did not name.
- Do not set `authorized: true` on a host the user did not name.
- Do not paste secret values, tokens, or raw model prompts into the chat. Quote the masked evidence and the `remediation` text.
- Do not send the target's prompts to a service the user did not configure.
- Open the report when the scan finishes.
