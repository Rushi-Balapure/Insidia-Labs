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
insidia doctor
```

`insidia engines install` fetches engine toolchains into a directory Insidia manages. `insidia engines install --docker` uses containers instead, for engines that support it. A signed wheel and a container image with every engine pinned ship with the public launch.

Next: [Quickstart](quickstart.md).
