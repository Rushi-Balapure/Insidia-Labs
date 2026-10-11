---
title: Install
description: Install the Insidia CLI from GitHub with uv or pipx.
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
insidia --help
```

Run `insidia init` in your project before `insidia doctor`; doctor needs a configuration file. Install specific engine toolchains into Insidia's managed directory by naming them, for example `insidia engines install garak zap`. With no names, `insidia engines install` only reports that built-in probes are available.

A version tag attaches a wheel, `SHA256SUMS`, and a Sigstore bundle. Verify the bundle, then:

```bash
uv tool install ./insidia-0.1.0-py3-none-any.whl
```

The image `ghcr.io/rushi-balapure/insidia` contains the CLI and every pinned engine. It is signed with Sigstore. Pin the release tag:

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/rushi-balapure/insidia:vX.Y.Z doctor
```

Next: [Quickstart](/docs/start/quickstart/).
