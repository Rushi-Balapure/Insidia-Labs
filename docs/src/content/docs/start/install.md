---
title: Install
description: Install the free Insidia security testing CLI from GitHub with uv or pipx. Check Python requirements, verify the installation, and get ready to scan localhost.
---

You need Python 3.12 or newer. Insidia is not published to a package registry.

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

The same URL works with pipx:

```bash
pipx install "git+https://github.com/Rushi-Balapure/Insidia-Labs#subdirectory=core"
```

Pin a commit or tag by adding it before `#subdirectory=core`.

Check the install:

```bash
insidia --version
```

This prints the version and the commit the copy was built from, such as `insidia 0.1.0 (3542f9e1c0ab)`. Include that line in a bug report.

Run `insidia init` in your project before `insidia doctor`; doctor needs a configuration file. Install specific engine toolchains into Insidia's managed directory by naming them, for example `insidia engines install garak zap`. With no names, `insidia engines install` only reports that built-in probes are available.

No release has been published yet. The release workflow is meant to attach a Sigstore-signed wheel with `SHA256SUMS` and to publish a container image when a version is tagged, but none exists today. Install from git as shown above.

Next: [Quickstart](/docs/start/quickstart/).
