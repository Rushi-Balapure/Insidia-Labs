---
title: CLI
description: Commands and flags the insidia binary accepts.
---

Global flags, accepted on every command:

| Flag | Meaning |
| --- | --- |
| `--json` | Print a JSON object instead of text. |
| `--yes` | Do not ask for confirmation. Required when scope contains a non-local host. |
| `--config PATH` | Config file. Default `insidia.yaml`. |
| `--quiet`, `-q` | Print only the result. |
| `--no-color` | Plain text, no color. |

What goes in the config file is [insidia.yaml](/docs/start/config/). `insidia -h` prints the same command list, with one line on what each command does.

## init

Writes `insidia.yaml` in the current directory. Refuses to overwrite an existing file.

## doctor

Prints a checklist of the Python environment, engines, and model endpoints. Exits non-zero when a required check fails.

## engines

```bash
insidia engines list
insidia engines install
insidia engines install garak zap
insidia engines install --docker
```

`list` prints each known engine, its license, and whether it is installed. To install toolchains, name the engines, for example `insidia engines install garak zap`. With no names, `install` reports that built-in probes are available. `--docker` checks for Docker; named engine images are not available through this command yet.

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

Exit codes: **0** for a completed pass, **1** for a completed policy failure, **2** for an incomplete run or an error, and **130** for cancellation. Even if an incomplete scan found vulnerabilities, it exits 2. JSON includes `execution_status` and `policy_verdict`; review both. Without `--json`, the CLI attempts to open the report when the scan finishes. Progress is printed while each control runs.

## report

```bash
insidia report --open
insidia report 20261008T120000Z-abc123
```

Opens or prints the latest run, or the run id you pass. See [Report](/docs/concepts/report/).

## rerun

```bash
insidia rerun
insidia rerun 20261008T120000Z-abc123
```

Scans again with the policy and coverage recorded for that run. If `insidia.yaml` changed, the command stops until you pass `--yes`.

## mcp

```bash
insidia mcp
```

Speaks MCP over stdio. Tools: `init`, `doctor`, `scan`, `findings`, `report`. `scan` requires `confirmed: true` and reads `insidia.yaml`. It does not accept a URL. See [Use a coding agent](/docs/start/agent/).
