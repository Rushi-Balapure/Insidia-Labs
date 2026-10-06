# Documentation

> The docs open with the agent skill, then the CLI, then the benchmark, then Insidia Cloud. Engines are named and linked. Docs CI runs link-check plus secret and real-data checks. Install is from GitHub, as in the master plan.

Cross-cutting. The docs site is scaffolded in Phase 0, and every later phase ships the docs for its own features as part of its exit criteria.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A person, or their coding agent, can go from nothing to a first report without help. The first block on the docs home is "Using a coding agent?" with the skill install line. Under it, a human can install the CLI and run a scan. A security team can still answer what Insidia sends, stores, and where.

## Principles
- **Agent first, then human.** The skill (`skills/insidia/SKILL.md`), `llms.txt`, and `AGENTS.md` are the top of the docs. The human quickstart follows.
- **Task first.** Most pages answer "how do I...". Concepts are explained only as far as a task needs them.
- **Engines are credited.** Docs name garak, promptfoo, ZAP, and the rest, with links and licenses. A finding page names the engine that produces it.
- **Nothing hand-copied that can be generated.** The CLI reference comes from the CLI, the API reference from the OpenAPI schema, probe and taxonomy pages from `benchmark/mappings/`, and egress IPs from the deployment config.
- **Every sample runs.** Quickstart commands are executed in CI. A broken sample fails the build.
- **Plain language.** Short sentences, and the same terms as the CLI and the dashboard. Written for a reader who is competent but new to AI security.

## Tooling
- **Starlight** (Astro, MIT) in the top-level `docs/` folder, docs-as-code in the same repo, so a feature pull request includes its docs change.
- Styled with the brand kit (Sora, navy, orange, magenta) and the apple-design skill (see [04-hosted-dashboard.md](04-hosted-dashboard.md#design-system-apple-design-skill)): reduced-motion support, light and dark themes.
- Full-text search built into the static site (Pagefind, MIT), with no third-party search service receiving customer queries.
- Hosted as a static site at `docs.<our domain>`. Public by default. On-prem and enterprise-only pages sit behind sign-in.
- The dashboard links to the matching docs page from every screen, and error messages carry a stable code that links to a troubleshooting entry (`INS-RUN-003` goes to `/troubleshooting/INS-RUN-003`).
- Versioned per release. On-prem customers get docs matching the version they run.

## Information architecture
1. **Get started**
   - Using a coding agent: install the skill, the prompt to paste, what the agent will ask you to confirm
   - What Insidia tests, and what it does not
   - Install from GitHub (`uv`, `pipx`, the GHCR image) and the human quickstart: `init`, `doctor`, `scan`, `report`
   - Scope and `authorized: true`
   - Insidia Cloud, after the CLI: credits, connecting with `insidia login`, direct and runner modes
2. **Concepts**
   - Organizations, projects, targets, scans, findings
   - Connection modes (direct, runner relay, runner tunnel)
   - Test modes (black, gray, white box) and what each needs from you
   - Coverage modes (Standard, Thorough, Custom) and what "cross-validated" means
   - How findings are confirmed: oracles and canaries, in plain terms, so customers trust the results
   - Severity and scoring (CVSS for web and API, AIVSS for AI)
   - How it works: the engines we run, the gap modules we build, and where Insidia Cloud fits
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
   - Framework pages: OWASP LLM 2026, OWASP Agentic, OWASP Web and API, MITRE ATLAS and ATT&CK, NIST AI RMF and AI 600-1, EU AI Act, ISO/IEC 42001, PCI DSS. Each explains which Insidia Labs tests map to which controls (generated from `benchmark/mappings/`) and what Insidia Labs cannot prove on its own.
   - Report types (executive PDF, technical HTML, evidence pack, SARIF, JSON, AI-BOM) and how to share them with auditors
8. **Integrations**
   - CI: GitHub Actions, GitLab, generic CLI; failing a build on severity
   - Jira, Slack, webhooks (with signature verification), SIEM export
   - Burp extension (Phase 3)
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
    - Vulnerability disclosure for Insidia Labs itself
11. **Administration** (Phase 4)
    - SSO (SAML, OIDC), SCIM, roles and custom permissions, audit log export
    - Private tenant and on-prem installation, upgrades, backups, air-gapped model setup
12. **Troubleshooting and FAQ**, one entry per error code
13. **Changelog and release notes**, including new probes and changed framework mappings

## Docs delivered per phase
A phase is not done until its docs are published. This table is the minimum.

| Phase | Docs that ship with it |
| --- | --- |
| 0 | Docs site scaffold, style guide, link-check CI, error-code framework |
| 1A–1D | Install from GitHub, scope, CLI reference, target guides, the benchmark, the HTML report, engine credits |
| 1E | The agent skill at the top, MCP, `llms.txt`, the GitHub Action |
| 2A–2B | Pointing the attacker at Insidia Cloud, custom attacks, reading a pentest-agent chain |
| 2C | Dashboard walkthroughs, direct and runner modes, credentials, schedules |
| 3 | Agent, MCP, and multi-agent guides; white box, AI-BOM, and the SDK; integrations |
| 4 | SSO, private tenants, self-hosted Cloud, the security and trust section |

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
- Secret and real-data check: no planted secret, no real customer string. Engine names are expected.
- Broken internal and external links.
- Every quickstart and API sample executed against staging.
- Generated references are up to date with the OpenAPI schema and runner CLI.
- Every error code the product can return has a troubleshooting page.
- Every probe and attack family in `benchmark/mappings/` has a remediation page.
- Accessibility scan of the built site.

## Risks
- **Docs leak secrets or customer data.** Samples pasted from engineering notes can include keys or internal hostnames. The secret check and a review step catch this. Engine names are fine.
- **Docs promise coverage we do not have.** Framework pages must say what is and is not tested; they are generated from the capability registry and gap list ([16-coverage-gaps.md](16-coverage-gaps.md)), not written from memory.
- **Remediation advice ages.** Each remediation page has an owner and a review date, and is flagged when it is more than 12 months old.