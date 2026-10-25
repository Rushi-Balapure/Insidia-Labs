---
title: Install
description: Install the free Insidia security testing CLI from GitHub with uv or pipx. Check Python requirements, verify the installation, and get ready to scan localhost.
---

You need Python 3.12 or newer. Insidia is not published to a package registry.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs@v1.0.0#subdirectory=core"
```

The same URL works with pipx:

```bash
pipx install "git+https://github.com/Rushi-Balapure/Insidia-Labs@v1.0.0#subdirectory=core"
```

The `@v1.0.0` in the URL is the current release. Replace it with another tag or a commit to pin something else.

Check the install:

```bash
insidia --version
```

This prints the version and the commit the copy was built from, such as `insidia 1.0.0 (v1.0.0)`. Include that line in a bug report.

## Upgrade

```bash
insidia upgrade --check
insidia upgrade
```

`--check` asks GitHub for the latest release and reports whether it is newer than your copy. `insidia upgrade` reinstalls from that release's tag with the tool that installed Insidia: uv, pipx, or pip. Engines in Insidia's managed directory are kept. `--json` prints the result as one object.

A copy installed before 1.0.0 has no `upgrade` command. Rerun the install command above with `--force` once. Windows cannot replace Insidia while it runs, so there `insidia upgrade` prints the install command for you to run after it exits.

Run `insidia init` in your project before `insidia doctor`; doctor needs a configuration file. Install specific engine toolchains into Insidia's managed directory by naming them, for example `insidia engines install garak zap`. With no names, `insidia engines install` only reports that built-in probes are available.

Each [release](https://github.com/Rushi-Balapure/Insidia-Labs/releases) attaches a Sigstore-signed wheel with `SHA256SUMS` and publishes a signed container image to `ghcr.io/rushi-balapure/insidia`. Release notes are in the [changelog](https://github.com/Rushi-Balapure/Insidia-Labs/blob/main/CHANGELOG.md).

Next: [Quickstart](/docs/start/quickstart/).
