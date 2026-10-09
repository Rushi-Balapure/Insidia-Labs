---
name: insidia
description: Scan a local AI app or web target with Insidia and open the HTML report. Use when the user asks to test an app with Insidia, run an AI or application security scan, or check prompt injection, data leakage, or web flaws on a host they named.
---

# Insidia

Insidia scans an app on the user's machine and writes one HTML report. The CLI is the contract. Prefer `insidia mcp` when the agent speaks MCP. Otherwise run the commands below.

## Install

From the public GitHub repo. Do not use PyPI.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

If `uv` is missing:

```bash
pipx install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

A release tag pins the version: add `@vX.Y.Z` before `#subdirectory=core`. The same tag has a signed wheel on the GitHub release and the image `ghcr.io/rushi-balapure/insidia`.

If the user wants the container:

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/rushi-balapure/insidia:vX.Y.Z doctor
```

Pin the tag the user named. Do not pull `:latest` unless they asked for it.

## Sequence

1. Ask the user which hosts may be tested. Start with localhost when they have not named another host.
2. Run `insidia init` when `insidia.yaml` is absent. It writes a localhost scope. Do not overwrite an existing file.
3. Edit targets so the URL matches the user's app. Leave scope on localhost unless the user named another host.
4. Run `insidia doctor`.
5. Run `insidia scan --policy L1 --yes` only after the user has confirmed the hosts in `insidia.yaml`.
6. Read `.insidia/runs/<run-id>/findings.json`. Each finding names `engine`, `probe`, `severity`, and `remediation`. Evidence is already masked.
7. Propose a fix from the `remediation` field. Do not invent a different attack to try.
8. Run `insidia report --open` so the user sees `report.html`.
9. After a fix, run the same scan again and compare the new `findings.json`.

`insidia scan` exits 0 when the policy passes and 1 when it fails. `--json` prints a single object with `run_id`, `passed`, `findings`, and `run_dir`.

## MCP

`insidia mcp` speaks MCP over stdio. Tools are `init`, `doctor`, `scan`, `findings`, and `report`. `scan` runs only when `confirmed` is true, and it reads `insidia.yaml`. It does not take a URL.

## Rules

- Confirm the target with the user before the first scan.
- Do not add a host the user did not name.
- Do not set `authorized: true` on a host the user did not name.
- Do not paste secret values, tokens, or raw model prompts into the chat. Quote the masked evidence and the `remediation` text.
- Do not send the target's prompts to a service the user did not configure.
- Open the report when the scan finishes.
