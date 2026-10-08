---
title: Data handling
description: What a local Insidia scan sends, and what it writes down.
---

A CLI scan sends traffic to the targets in `insidia.yaml` and, if you configured them, to your attacker and judge endpoints. It does not phone home. There is no telemetry switch in this pre-release because there is no telemetry.

Secrets in evidence are masked before they are written. The report shows a type, a length, and a fingerprint, not the raw value.

The marketing site at insidialabs.com is a separate static site. A waitlist email is not written into a product database.

When Insidia Cloud opens, hosted findings are stored with per-organization encryption and are not training data. That service is described in [Insidia Cloud](../cloud.md) and is not part of a local scan.

Only test systems you own or have permission to test. Report a vulnerability in Insidia itself to [insidialabs@gmail.com](mailto:insidialabs@gmail.com).
