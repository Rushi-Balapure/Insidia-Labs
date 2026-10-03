# Phase 3 — Taxonomy and compliance

Depends on: Phase 1 findings, Phase 2 UI shell. Blocks: sales-facing reports.
Parent: [00-master-plan.md](00-master-plan.md). IDs from [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md).

## Goal
Every finding can be pivoted by framework. A scan profile is a set of probes selected by those tags. One scan can emit an OWASP LLM 2026 report, an OWASP Web report, and an EU AI Act Art. 15 evidence pack. Wording is "compliance-ready evidence", not certification.

## Exit
- `engine/taxonomy-data/` loads into the database on boot and in CI.
- The Phase 1 fixtures produce findings tagged at least `owasp-llm:LLM01` (canary leak) and `owasp-web:A03` or `A05` (injected fixture).
- PDF, HTML, SARIF, and JSON exports download from the dashboard. SARIF has no upstream tool names.
- Coverage matrix shows which controls were tested vs not tested (not the same as passed).
- ATLAS heatmap renders tactics for the AI findings.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)). Phase 3 adds taxonomy tags to cells other phases own; it does not own cells of its own.

## Tag prefixes
`owasp-llm` (2026 LLM01–LLM10), `owasp-asi` (ASI01–ASI10), `owasp-web` (2021 or current Top 10), `owasp-api` (API Security Top 10), `atlas`, `attack`, `cwe`, `cvss`, `aivss`, `nist-rmf`, `nist-600-1`, `eu-ai-act`, `iso-42001`, `aicm`, `pci`, `dsgai`.

## Data
YAML files, one framework per directory, reviewed in PR:
```
engine/taxonomy-data/
  owasp-llm-2026.yaml      # id, title (short paraphrase we write), summary we write
  owasp-asi-2026.yaml
  owasp-web.yaml
  owasp-api.yaml
  atlas.yaml               # import structure from mitre-atlas/atlas-data; our descriptions
  attack.yaml              # technique ids we actually cite
  nist-ai-rmf.yaml
  nist-ai-600-1.yaml
  eu-ai-act.yaml           # articles 9, 10, 15 mapped to test families
  iso-42001.yaml
  pci.yaml                 # 6.4, 11.3 as evidence hooks
  probes.yaml              # insidia probe_id -> taxonomy refs, severity default, track
```
OWASP documents are CC BY-SA. Store ids and our own one-paragraph explanations. Do not paste their guide text into the repo or the PDF.

Seed `probes.yaml` from promptfoo's MIT mapping files where the mapping is a table of ids, then rename probes to Insidia Labs ids. Keep the MIT copyright header on that seed file in-tree only.

## Profiles
A profile is a named list of probe ids plus budgets. Ship:
- AI chat baseline (LLM01, LLM02, LLM08) — already partially run in Phase 1.
- OWASP LLM Top 10 2026 (all ten, depth grows in Phase 4; unmapped items show as "not covered" rather than fake passes).
- Web baseline and OWASP Web Top 10.
- EU AI Act Art. 15 robustness (points at the LLM probes that exercise robustness, with a written limitation statement).

The planner from Phase 1 reads the profile and only enqueues those probes.

## Scoring
- Classic findings: CVSS 3.1 vector stored when the probe defines one; severity derived from it.
- AI findings: AIVSS when we have enough fields; otherwise a fixed severity on the probe plus confidence from the oracle (Phase 4 fills confidence). Do not invent a CVSS score for a jailbreak.

## Reports (`engine/api` module `reports`, queue `reports`)
- Jinja2 HTML, WeasyPrint PDF.
- Sections: executive summary, scope and target, coverage matrix, findings grouped by framework, methodology limitations, evidence hashes.
- Evidence pack: zip of redacted transcripts, request/response pairs, and a manifest of hashes. Raw secrets must already be redacted by the runner.
- SARIF 2.1.0 for web and SAST-shaped findings. AI findings included with our probe id as the rule id.
- JSON export matches the public finding schema (no `engine`).

## UI
- Finding drawer shows framework chips.
- Scan page: coverage matrix.
- Report button: choose framework preset, generate, poll the Celery task, download.
- ATLAS heatmap: tactic columns, technique cells colored by open finding count. Our labels, not a vendored ATLAS Navigator build if that pulls extra licenses; a simple grid is enough.

## Tests
- Loader rejects a probe that references an unknown taxonomy id.
- Fixture scan report contains LLM01 and a web id, and the PDF text does not contain denied upstream names (keep a denylist in the test).
- Cross-org download of a report id returns 403.
- A profile that omits LLM06 shows that control as not tested, not passed.

## Risks
- Mapping quality will be wrong in places. Prefer a thin, reviewed map over generating tags with an LLM.
- "EU AI Act report" will be read as certification. The template's first paragraph must say it is test evidence mapped to articles, not a conformity assessment.
