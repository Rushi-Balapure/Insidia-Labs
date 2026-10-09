# Insidia CLI

Insidia scans an AI app and the application around it on your machine and writes one HTML report. The CLI is free. It does not need an account. Insidia Cloud, the hosted attacker, is not open yet.

## Install

Python 3.12 or newer. Insidia is not on PyPI.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

`pipx install` accepts the same URL. A tag pins the version: add `@vX.Y.Z` before `#subdirectory=core`.

Each tag also attaches a wheel and `SHA256SUMS`. The wheel is signed with Sigstore. Verify it with the `.bundle` file on the release, then:

```bash
uv tool install ./insidia-0.1.0-py3-none-any.whl
```

The container image `ghcr.io/rushi-balapure/insidia` has the CLI and every pinned engine. Pin the same tag. The image is signed with Sigstore.

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/rushi-balapure/insidia:vX.Y.Z doctor
```

## Scan

```bash
insidia init
insidia doctor
insidia scan --policy L1 --yes
insidia report --open
```

`insidia init` writes a localhost scope. A host other than localhost needs `authorized: true`, which you set. The scan exits 0 when the policy passes and 1 when it fails.

## Coding agents

```bash
npx skills add Rushi-Balapure/Insidia-Labs
```

Paste: "Test this app with Insidia. Only scan localhost, and open the report when you're done."

You confirm the hosts. The skill tells the agent not to add a host you did not name and not to paste secrets. `insidia mcp` is the local MCP server for an agent that speaks MCP. `scan` does not take a URL.

## CI

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Rushi-Balapure/Insidia-Labs/actions/scan@v0
    with:
      policy: L1
```

The action installs the CLI from that git ref and uploads SARIF.
