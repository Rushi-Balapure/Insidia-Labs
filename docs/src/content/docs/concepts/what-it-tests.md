---
title: What it tests
description: AI-layer checks, application checks, and scripted chains between them.
---

One scan covers two layers.

**AI and agents.** Direct and indirect prompt injection, jailbreaks, hidden-context extraction, secret leakage, tool misuse, RAG and memory poisoning, and MCP or skill supply chain.

**Applications.** Web and API flaws such as injection, XSS, SSRF, and broken authorization, plus secrets, vulnerable dependencies, and container images.

**The seam.** A scripted chain starts in the model and lands in the app. The example used in the product story is a prompt injection that becomes a tool argument, then a SQL injection. The finding shows both steps. Chains an agent discovers on its own are part of [Insidia Cloud](/docs/cloud/), which is not open yet.

Set coverage when you scan:

| Flag | Behavior |
| --- | --- |
| `--coverage standard` | One engine per family. This is the default. |
| `--coverage thorough` | Every installed engine that covers the family. A finding seen by more than one engine names each engine. That is not independent confirmation. |

Checks that need a model run only when `models.attacker` is set. Otherwise they are skipped and written to `benchmark.json`. A skip is not a pass.

The engines are named in [Engines](/docs/concepts/engines/).
