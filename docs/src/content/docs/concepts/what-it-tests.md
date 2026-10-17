---
title: What it tests
description: AI-layer checks, application checks, and scripted chains between them.
---

One scan covers two layers.

**AI and agents.** Direct and indirect prompt injection, jailbreaks, hidden-context extraction, secret leakage, tool misuse, RAG and memory poisoning, and MCP or skill supply chain.

**Applications.** Template, command, and SQL injection, path access, SSRF, broken object and function authorization, mass assignment, and JWT checks, plus repository secrets and dependency checks. XSS is not a separate policy check in this release. Installing an engine that supports XSS does not add it to the policy.

**The seam.** Agent checks include dangerous tool arguments, secondary injection through tool output, and tool-chain hijacking. Coverage depends on the target type and the evidence the adapter can observe. Adaptive attack discovery is planned for [Insidia Cloud](/docs/cloud/), which is not open yet.

Set coverage when you scan:

| Flag | Behavior |
| --- | --- |
| `--coverage standard` | One engine per family. This is the default. |
| `--coverage thorough` | Every installed engine that covers the family. A finding seen by more than one engine names each engine. That is not independent confirmation. |

L1 is the baseline and requires no model. A check that cannot run is recorded in the run artifacts. A skip is not a pass, and an incomplete run cannot pass. Review execution status as well as findings before treating a scan as a CI gate.

The engines are named in [Engines](/docs/concepts/engines/).
