---
title: CLI
description: Commands and flags the insidia binary accepts.
---

Global flags, accepted on every command, before or after it (`insidia --json doctor` and `insidia doctor --json` are the same):

| Flag | Meaning |
| --- | --- |
| `--json` | Print a JSON object instead of text. |
| `--yes` | Do not ask for confirmation. Required when scope contains a non-local host. |
| `--config PATH` | Config file. Default `insidia.yaml`. |
| `--quiet`, `-q` | Print only the result. |
| `--no-color` | Plain text, no color. |

What goes in the config file is [insidia.yaml](/docs/start/config/). `insidia -h` prints the same command list, with one line on what each command does.

## init

```bash
insidia init --url http://127.0.0.1:PORT/path
insidia init --url http://127.0.0.1:8080/hello --kind web
```

Writes `insidia.yaml` in the current directory, or the file given by `--config`. `--url` sets `targets.app.url`. The host is added to scope only when it is localhost, `127.0.0.1`, or `::1`. A non-local host is refused; set `authorized: true` yourself before scanning it. `--kind` defaults to `chat` when the path ends with `/chat`, and is inferred otherwise. Without `--url`, the file uses `http://127.0.0.1:8080/chat` and the command tells you to set `targets.app.url`. Refuses to overwrite an existing file.

## doctor

Prints a checklist of the Python environment, engines, and model endpoints. Exits non-zero when a required check fails. Docker and engines that need a missing runtime, such as ZAP without Java, are reported but optional.

## engines

```bash
insidia engines list
insidia engines install
insidia engines install garak zap
insidia engines install --docker
```

`list`, or `insidia engines` alone, prints each known engine, its license, and whether it is installed. An engine that was downloaded but needs a runtime this machine lacks says what it needs. A check whose only engines are not installed is reported as not tested, with the engine to install. To install toolchains, name the engines, for example `insidia engines install garak zap`. With no names, `install` reports that built-in probes are available. `--docker` checks for Docker; named engine images are not available through this command yet.

A downloaded engine binary is checked against a pinned SHA-256 for that engine, version, and platform before it is unpacked. If the bytes do not match, the install stops. If this platform has no pin, the install stops unless you pass `--allow-unverified`.

## policy

```bash
insidia policy list
insidia policy show L1
insidia policy validate
```

`validate` loads the policy named in your config. Only `L1` can be validated or scanned. `L2` and `L3` are listed definitions for future levels. See [Benchmark](/docs/concepts/benchmark/).

## scan

```bash
insidia scan --policy L1 --coverage standard --yes --json
```

| Flag | Values |
| --- | --- |
| `--policy` | Use `L1`. The parser accepts `L2` and `L3`, but execution rejects them as unavailable. Default is the policy in the config. |
| `--coverage` | `standard` or `thorough`. Default is the coverage in the config. |
| `--open` | Open the report in a browser when the scan finishes. Without it, the scan only prints the report path, so it is safe in CI, over SSH, and from an agent. |

Exit codes: **0** for a completed pass, **1** when any check found a problem, **2** for an incomplete run with no finding or an error, and **130** for cancellation. A finding exits 1 even when another target or check did not finish, so a CI gate on 1 never misses it. JSON includes `execution_status` and `policy_verdict`; review both. A scan never opens a browser unless you pass `--open`. Progress is printed while each control runs.

## report

```bash
insidia report --open
insidia report 20261008T120000Z-abc123
```

Prints the report path for the latest run, or the run id you pass. `--open` also opens it in a browser and says whether that worked; on a machine with no browser it prints the path instead. See [Report](/docs/concepts/report/).

## rerun

```bash
insidia rerun
insidia rerun 20261008T120000Z-abc123
```

Scans again with the policy and coverage recorded for that run. If `insidia.yaml` changed, the command stops until you pass `--yes`.

## mcp

```bash
insidia mcp
insidia mcp --allow-remote
```

Speaks MCP over stdio. Tools: `init`, `doctor`, `scan`, `findings`, `report`. `scan` requires `confirmed: true` and reads `insidia.yaml`. It does not accept a URL. Localhost, `127.0.0.1`, and `::1` run by default. A scope that names any other host is refused unless the person who starts the server passes `--allow-remote` or sets `INSIDIA_MCP_ALLOW_REMOTE=1`. The calling model cannot turn that on. See [Use a coding agent](/docs/start/agent/).
