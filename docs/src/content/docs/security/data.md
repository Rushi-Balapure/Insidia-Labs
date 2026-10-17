---
title: Data handling
description: What a local Insidia scan sends, and what it writes down.
---

A CLI scan sends traffic to the targets in `insidia.yaml` and, if you configured them, to your attacker and judge endpoints. Insidia itself does not phone home. There is no telemetry switch in this pre-release because there is no telemetry.

Nuclei, katana, and httpx start with the update check off, so a scan does not contact ProjectDiscovery to look for a newer release. Trivy and osv-scanner do not download a vulnerability database unless you set `INSIDIA_VULN_DB=1`. Without that, Trivy is started with `--skip-db-update` and `--skip-java-db-update`, and osv-scanner is started with `--offline`. Those are the tools' own flags. If a local database is not already present, the tool exits with an error and does not connect to download one.

`INSIDIA_VULN_DB=1` allows those downloads. Trivy then fetches its vulnerability database from `mirror.gcr.io` (`mirror.gcr.io/aquasec/trivy-db`) and, if that fails, from `ghcr.io` (`ghcr.io/aquasecurity/trivy-db`). Its Java index database uses `mirror.gcr.io` (`mirror.gcr.io/aquasec/trivy-java-db`) and `ghcr.io` (`ghcr.io/aquasecurity/trivy-java-db`). osv-scanner queries `api.osv.dev` for vulnerabilities and may contact `api.deps.dev` to resolve transitive dependencies. That traffic is outside `scope`. The variable does not authorize a non-local target. The other engines do not download a vulnerability database.

`insidia engines install` downloads toolchains from PyPI, GitHub releases, and the ZAP host. That download runs when you install an engine, not during a scan.

Secrets in evidence are masked before they are written. The report shows a type, a length, and a fingerprint, not the raw value.

The marketing site at insidialabs.com is a separate static site. A waitlist email is not written into a product database.

When Insidia Cloud opens, hosted findings are stored with per-organization encryption and are not training data. That service is described in [Insidia Cloud](/docs/cloud/) and is not part of a local scan.

Only test systems you own or have permission to test. Report a vulnerability in Insidia itself to [insidialabs@gmail.com](mailto:insidialabs@gmail.com).
