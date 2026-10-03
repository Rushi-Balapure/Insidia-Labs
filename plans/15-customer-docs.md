# Customer Documentation

Cross-cutting. The docs site is scaffolded in Phase 0, and every later phase ships the docs for its own features as part of its exit criteria.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A security engineer who has never talked to us can go from sign-up to a first triaged finding without help. They can also answer the questions their own security, legal, and procurement teams will ask: what do you send to my systems, what do you store, and where. A developer can automate everything from the docs alone.

## Principles
- **Task first.** Most pages answer "how do I...". Concepts are explained only as far as a task needs them, with a link to the deeper page.
- **Two paths everywhere.** Every setup guide has a "Direct (no install)" tab and a "Runner" tab, and says plainly what the direct path cannot do.
- **Insidia Engine only.** Docs follow the same confidentiality rule as the product. No upstream engine, library, or project name appears anywhere, including code samples, screenshots, config keys, and error messages. The denylist CI test runs on the docs build.
- **Nothing hand-copied that can be generated.** API reference comes from the OpenAPI schema, CLI reference from the runner's command definitions, probe and taxonomy pages from `taxonomy-data/` and the `probes` table, and egress IPs from the deployment config. Hand-written copies drift.
- **Every sample runs.** Quickstart commands and API samples are executed in CI against staging. A broken sample fails the build.
- **Plain language.** Short sentences, no unexplained acronyms, and the same terms as the dashboard labels. Written for a reader who is competent but new to AI security.

## Tooling
- **Starlight** (Astro, MIT) in a new top-level `docs/` folder, docs-as-code in the same repo, so a feature pull request includes its docs change.
- Styled with the dashboard's design tokens from `dashboard/src/design/` and following the apple-design skill (see [04-phase2-dashboard.md](04-phase2-dashboard.md#design-system-apple-design-skill)): system font, size-specific tracking, reduced-motion support, light and dark themes.
- Full-text search built into the static site (Pagefind, MIT), with no third-party search service receiving customer queries.
- Hosted as a static site at `docs.<our domain>`. Public by default. On-prem and enterprise-only pages sit behind sign-in.
- The dashboard links to the matching docs page from every screen, and error messages carry a stable code that links to a troubleshooting entry (`INS-RUN-003` goes to `/troubleshooting/INS-RUN-003`).
- Versioned per release. On-prem customers get docs matching the version they run.

## Information architecture
1. **Get started**
   - What Insidia tests (AI and agent security, web and API security) and what it does not
   - Quickstart: scan a hosted chatbot directly (no install), about 10 minutes
   - Quickstart: scan a local app with the runner, about 15 minutes
   - Choosing direct or runner: a decision guide and the feature availability table
   - Your trial: what the 3 model-free trial scans include, what is locked, and how to upgrade
2. **Concepts**
   - Organizations, projects, targets, scans, findings
   - Connection modes (direct, runner relay, runner tunnel)
   - Test modes (black, gray, white box) and what each needs from you
   - Coverage modes (Standard, Thorough, Custom) and what "cross-validated" means
   - How findings are confirmed: oracles and canaries, in plain terms, so customers trust the results
   - Severity and scoring (CVSS for web and API, AIVSS for AI)
   - How it works: the customer-facing diagram with a single Insidia Engine box
3. **Connect a target** (one page per target type, each with a request template example and a Validate step)
   - Chat and completion APIs: OpenAI-compatible, Anthropic-style, Bedrock, Azure, custom HTTP, WebSocket, streaming
   - RAG applications: what to give us for corpus and retrieval tests
   - Tool-using agents and MCP servers
   - Multi-agent systems
   - Web applications: authenticated scanning, login flows, scope and exclusions
   - REST and GraphQL APIs: importing an OpenAPI spec or GraphQL schema, two-identity setup for access-control tests
   - Ownership verification for direct mode (DNS TXT, well-known file, meta tag) and allowlisting our egress IPs
   - Credentials: using your cloud secret manager, OAuth clients, or stored write-only secrets; why to use dedicated test accounts
4. **Runner**
   - System requirements and network requirements (outbound only; exact hosts and ports)
   - Install on Linux, macOS, Windows, Docker, and Kubernetes (Helm); verifying the signed binary
   - Enroll, run as a service, upgrade, uninstall
   - Relay mode compared with tunnel mode
   - Host allowlist, local secrets (environment variables, files, Vault), redaction rules
   - Local audit log
   - `discover`, `extract`, and one-shot `scan` for CI
   - Troubleshooting (connection, certificates, proxies, TLS inspection boxes)
5. **Run scans**
   - Profiles (OWASP LLM Top 10 2026, OWASP Agentic, OWASP Web and API, custom)
   - Budgets, rate limits, and what happens when a budget runs out
   - Scheduling and continuous scanning
   - Safe testing: kill switch, production compared with staging, content-safety tests and their gating
6. **Findings and remediation**
   - Triage workflow and statuses (open, accepted, fixed, false positive, baselined)
   - Reading evidence: transcripts, HTTP pairs, tool traces, masked secrets and matching a fingerprint to your key
   - **Remediation guides, one per attack family:** what the issue is, why it matters, how to fix it in common stacks, and how to verify the fix with a rescan. These are generated from probe metadata plus hand-written guidance, and they are the pages customers use most.
   - Baselines and regression tracking
7. **Compliance and reports**
   - Framework pages: OWASP LLM 2026, OWASP Agentic, OWASP Web and API, MITRE ATLAS and ATT&CK, NIST AI RMF and AI 600-1, EU AI Act, ISO/IEC 42001, PCI DSS. Each explains which Insidia tests map to which controls (generated from `taxonomy-data/`) and what Insidia cannot prove on its own.
   - Report types (executive PDF, technical HTML, evidence pack, SARIF, JSON, AI-BOM) and how to share them with auditors
8. **Integrations**
   - CI: GitHub Actions, GitLab, generic CLI; failing a build on severity
   - Jira, Slack, webhooks (with signature verification), SIEM export
   - Burp extension (Phase 9)
9. **API and CLI reference**
   - Authentication, API key scopes, rate limits, pagination, errors, webhooks
   - Generated endpoint reference with request and response examples
   - Generated runner CLI reference
10. **Security and trust** (written with the security team, reviewed by counsel)
    - What data we collect, per connection mode, and what never leaves your network in runner mode
    - Encryption: per-organization keys, what is encrypted (every customer value, see [14-database-schema.md](14-database-schema.md)), secret handling, and secret redaction in evidence
    - Retention defaults and settings; deleting an organization (crypto-shredding)
    - Staff access policy: none by default, time-boxed grants approved by you, visible in your audit log
    - Regions, subprocessors, and egress IP list
    - Authorized testing policy: only test systems you own or are permitted to test
    - Vulnerability disclosure for Insidia itself
11. **Administration** (Phase 10)
    - SSO (SAML, OIDC), SCIM, roles and custom permissions, audit log export
    - Private tenant and on-prem installation, upgrades, backups, air-gapped model setup
12. **Troubleshooting and FAQ**, one entry per error code
13. **Changelog and release notes**, including new probes and changed framework mappings

## Docs delivered per phase
A phase is not done until its docs are published. This table is the minimum.

| Phase | Docs that ship with it |
| --- | --- |
| 0 | Docs site scaffold, style guide, denylist and link-check CI, error-code framework |
| 1 | Runner install and enroll, relay and tunnel modes, direct-mode verification and egress IPs, chat API and web app target guides, API authentication |
| 2 | Both quickstarts, concepts section, dashboard walkthroughs, coverage modes, credentials guide, generated API reference |
| 3 | Compliance and framework pages, report types, first remediation guides for every Phase 1 attack family |
| 4 | RAG, multi-turn, REST and GraphQL API guides; gray-box inputs; remediation guides for the new families |
| 5 | Chained-exploit findings: how to read an attack path and its proof of concept |
| 6 | Updated coverage-mode page with measured trade-offs; "why cross-validated findings matter" |
| 7 | Agent, MCP, and multi-agent guides; `discover`; honeypot and canary explanations |
| 8 | White-box guide, `extract`, what is uploaded and what stays local, SDK integration, AI-BOM |
| 9 | CI, integrations, schedules, baselines, Burp extension |
| 10 | Administration, SSO, on-prem install and operations, the full security and trust section |

## Other deliverables
- **In-product help:** short, contextual tips in the dashboard, written by the docs team from the same source files so they never contradict the docs.
- **Sample targets:** a public, deliberately vulnerable demo chatbot and web app hosted by us, so the quickstart works before the customer connects anything real.
- **Security questionnaire pack:** prepared answers to common vendor-assessment questionnaires, built from the security and trust pages.
- **Screenshots:** generated by Playwright against a seeded demo org on every release, so they never show stale UI or real customer data.

## Process and ownership
- Each feature pull request that changes customer-visible behavior must update docs, or state why none is needed. A pull request check enforces the question.
- A technical writer owns the style guide and information architecture. Engineers write first drafts for their features; the writer edits.
- Before each release, someone who did not build the feature follows the relevant quickstart and guides from scratch on a clean machine and files every point of confusion.
- Docs analytics are privacy-preserving and self-hosted: page views, searches with no results, and "was this helpful" votes. Searches with no results become the backlog.

## CI checks on `docs/`
- Upstream-name denylist (same list as the product, including model and model-runtime names from [19-model-hosting.md](19-model-hosting.md)).
- Broken internal and external links.
- Every quickstart and API sample executed against staging.
- Generated references are up to date with the OpenAPI schema and runner CLI.
- Every error code the product can return has a troubleshooting page.
- Every probe and attack family in `taxonomy-data/` has a remediation page.
- Accessibility scan of the built site.

## Risks
- **Docs leak internals.** Samples pasted from engineering notes can include engine names or internal hostnames. The denylist check and a review step catch this.
- **Docs promise coverage we do not have.** Framework pages must say what is and is not tested; they are generated from the capability registry and gap list ([16-coverage-gaps.md](16-coverage-gaps.md)), not written from memory.
- **Remediation advice ages.** Each remediation page has an owner and a review date, and is flagged when it is more than 12 months old.