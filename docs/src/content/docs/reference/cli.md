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

`validate` loads the policy named in your config. Names are `L1`, `L2`, and `L3`. See [Benchmark](../concepts/benchmark.md).

## scan

```bash
insidia scan --policy L1 --coverage standard --yes --json
```

| Flag | Values |
| --- | --- |
| `--policy` | `L1`, `L2`, `L3`. Default is the policy in the config. |
| `--coverage` | `standard` or `thorough`. Default is the coverage in the config. |

Exit 0 when the policy passes, 1 when it fails, and a non-zero `CliError` code when the scan cannot run (bad scope, no runnable controls).

## report

```bash
insidia report --open
insidia report 20261008T120000Z-abc123
```

Opens or prints the latest run, or the run id you pass. See [Report](../concepts/report.md).
