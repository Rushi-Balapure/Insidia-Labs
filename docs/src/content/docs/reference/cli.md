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

`list` prints each known engine, its license, and whether it is installed.

## policy

```bash
insidia policy list
insidia policy show L1
insidia policy validate
```

`validate` loads the policy named in your config. Names are `L1`, `L2`, and `L3`. See [Benchmark](/docs/concepts/benchmark/).

## scan

```bash
insidia scan --policy L1 --coverage standard --yes --json
```

| Flag | Values |
| --- | --- |
| `--policy` | `L1`, `L2`, `L3`. Default is the policy in the config. |
| `--coverage` | `standard` or `thorough`. Default is the coverage in the config. |

Exit 0 when the policy passes and 1 when it fails. The last line says the scan ran, whether the policy passed, and where the report is. A policy failure is not a crash. Without `--json`, the report opens in a browser when the scan finishes. Progress is printed while each control runs.

## report

```bash
insidia report --open
insidia report 20261008T120000Z-abc123
```

Opens or prints the latest run, or the run id you pass. See [Report](/docs/concepts/report/).

## mcp

```bash
insidia mcp
```

Speaks MCP over stdio. Tools: `init`, `doctor`, `scan`, `findings`, `report`. `scan` requires `confirmed: true` and reads `insidia.yaml`. It does not accept a URL. See [Use a coding agent](/docs/start/agent/).
