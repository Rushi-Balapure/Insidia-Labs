# Insidia CLI

Insidia scans an AI app and the application around it on your machine and writes one HTML report. The CLI is free. It does not need an account. Insidia Cloud, the hosted attacker, is not open yet.

## Install

Python 3.12 or newer. Insidia is not on PyPI.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs@v1.0.0#subdirectory=core"
```

`pipx install` accepts the same URL. `insidia --version` prints the version and the commit you have.

## Upgrade

```bash
insidia upgrade --check
insidia upgrade
```

`insidia upgrade` installs the latest release with uv, pipx, or pip, whichever installed your copy, and keeps your engines.

## Scan

```bash
insidia init
insidia doctor
insidia scan --policy L1 --yes
insidia report --open
```

`insidia init` writes a localhost scope. A host other than localhost needs `authorized: true`, which you set. The scan exits 0 when the policy passes, 1 when a check finds a problem, 2 when the run is incomplete, and 130 when you cancel it.

## Coding agents

```bash
npx skills add Rushi-Balapure/Insidia-Labs
```

This needs Node.js 22 or later.

Paste: "Test this app with Insidia. Only scan localhost, and open the report when you're done."

You confirm the hosts. The skill tells the agent not to add a host you did not name and not to paste secrets. `insidia mcp` is the local MCP server for an agent that speaks MCP. `scan` does not take a URL.

## CI

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs@v1.0.0#subdirectory=core"
insidia scan --policy L1 --json
```

Run these commands after checking out your repository and starting its target app. Pin the install URL to a release tag and preserve `.insidia/runs/` even when the scan fails. The [CI guide](/docs/guides/ci/) includes runner setup and artifact steps.
