---
title: Benchmark
description: The L1, L2, and L3 policies, and the separate scanner matrix.
---

## Policy you run on your app

```bash
insidia policy list
insidia scan --policy L1 --yes
```

| Policy | What the CLI records |
| --- | --- |
| `L1` | Baseline checks. This is what `insidia init` selects. No model is required. |
| `L2` | The same control list, labeled L2. Judge-scored checks run when a model is configured. |
| `L3` | The same control list, labeled L3. Model-generated attacks run when an attacker model is configured. |

L1, L2, and L3 share one control list in this pre-release. The policy name is stored on the run so later levels can add checks without a new command. `insidia policy show L2` prints the summary the CLI ships with.

`benchmark.json` in the run directory has the policy name, pass or fail, each control's result, and the skips. A control is `fail` when a probe hit it, `pass` when the probes ran clean, and `skipped` when nothing runnable was available.

## Matrix that measures scanners

[`benchmark/`](https://github.com/Rushi-Balapure/Insidia-Labs/tree/main/benchmark) in the repository is a different thing: sandboxed vulnerable targets and a matrix of planted bugs. Engine work is accepted when the cells it owns find those plants. That matrix is not the score of your application.
