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
| `L2` | Not available. A separate judge-scored level has not shipped. |
| `L3` | Not available. A separate model-generated level has not shipped. |

The CLI lists all three policy names, but scans and policy validation accept only L1. `insidia policy show L2` can display its definition; that does not mean you can scan with it.

`benchmark.json` records the policy verdict, execution status, control results, and skips. A completed scan can pass or fail. Missing, unsupported, or interrupted required checks make the run incomplete; an incomplete run cannot pass. A skip is not a pass.

## Scanner regression matrix

[`benchmark/`](https://github.com/Rushi-Balapure/Insidia-Labs/tree/main/benchmark) contains sandboxed targets with planted vulnerabilities. The matrix tests adapter and transport behavior against these fixtures. Passing it does not measure detector accuracy on real applications or establish release readiness. Independent validation is part of the current productization work. Your application's policy result is separate.
