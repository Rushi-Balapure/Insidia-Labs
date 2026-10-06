# Phase 1D — Insidia Benchmark, taxonomy, and reports

> This is Phase 1D of the free CLI. The policy files live in `benchmark/policies` and the framework mappings in `benchmark/mappings`. The CLI writes the HTML report, SARIF, JSON, and `benchmark.json` with no account. The executive PDF and the evidence-pack zip are Insidia Cloud exports (Phase 2C). Reports name the engine that produced each finding. Wording is "compliance-ready evidence", which is test evidence and not certification.

Depends on: Phase 1B findings. The Cloud download buttons depend on Phase 2C.
Parent: [00-master-plan.md](00-master-plan.md). IDs from [01-ai-redteam-coverage-spec.md](01-ai-redteam-coverage-spec.md).

## Goal
Every finding can be pivoted by framework. A benchmark policy (L1, L2, L3, or a team's own file) is a set of controls, each tested by probes. One scan emits a score per framework. 

## Exit
- `benchmark/mappings/` loads in CI, and into the Cloud database on boot.
- The sandbox fixtures produce findings tagged at least `owasp-llm:LLM01` (canary leak) and `owasp-web:A03` or `A05` (injected fixture).
- `insidia scan` writes `report.html` (works offline, summary readable with JavaScript off), `results.sarif`, `findings.json`, and `benchmark.json`. SARIF `tool.driver.name` is `Insidia` and each result names the engine in a property.
- The report's coverage matrix shows which controls were tested, which passed, and which were not tested.
- Owned matrix cells are green ([17-test-suite.md](17-test-suite.md)). This phase adds taxonomy tags to cells that other phases own.

## Tag prefixes
`owasp-llm` (2026 LLM01–LLM10), `owasp-asi` (ASI01–ASI10), `owasp-web` (2021 or current Top 10), `owasp-api` (API Security Top 10), `atlas`, `attack`, `cwe`, `cvss`, `aivss`, `nist-rmf`, `nist-600-1`, `eu-ai-act`, `iso-42001`, `aicm`, `pci`, `dsgai`.

## Data
YAML files, one framework per file, reviewed in PR. Framework mappings live in `benchmark/mappings/` (policy files live in `benchmark/policies/`):
```
benchmark/mappings/
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

Seed `probes.yaml` from promptfoo's MIT mapping files where the mapping is a table of ids. Keep promptfoo's probe ids alongside the Insidia ids, and keep the MIT copyright header on that seed file.

## Policies
A policy is a named list of controls, the probes that test each one, and budgets. Ship L1, L2, and L3 as described in the master plan, covering:
- AI chat baseline (LLM01, LLM02, LLM08) in L1.
- OWASP LLM Top 10 2026 (all ten; controls the engines do not test yet show as "not covered", never as a pass).
- OWASP Web and API Top 10.
- EU AI Act Art. 15 robustness, with a written limitation statement.

`insidia scan --policy` reads the file and only runs those probes.

## Scoring
- Classic findings: CVSS 3.1 vector stored when the probe defines one; severity derived from it.
- AI findings: AIVSS when we have enough fields; otherwise a fixed severity on the probe plus confidence from the oracle (deterministic oracles in Phase 1C, judge calibration in Phase 2B). Do not invent a CVSS score for a jailbreak.

## Reports
The CLI builder lives in `core/` and needs no server. Cloud reuses it and adds the PDF and the evidence pack on the `reports` queue.
- One self-contained HTML file (Jinja2). Sections: score per framework, scope and target, coverage matrix, findings grouped by framework, the engine and probe on each finding, methodology limitations, evidence hashes.
- SARIF 2.1.0. The rule id is the Insidia probe id; the engine name is a property.
- JSON matches the public finding schema, including `engine`.
- Cloud only: WeasyPrint executive PDF, and an evidence-pack zip of redacted transcripts and a hash manifest.

## UI
- Finding drawer shows framework chips.
- Scan page: coverage matrix.
- Report button: choose framework preset, generate, poll the Celery task, download.
- ATLAS heatmap: tactic columns, technique cells colored by open finding count. Our labels, not a vendored ATLAS Navigator build if that pulls extra licenses; a simple grid is enough.

## Tests
- Loader rejects a probe that references an unknown taxonomy id.
- Fixture scan report contains LLM01 and a web id, names the engine, and contains no raw secret from the fixture.
- Cross-org download of a report id returns 403.
- A profile that omits LLM06 shows that control as not tested, not passed.

## Risks
- Mapping quality will be wrong in places. Prefer a thin, reviewed map over generating tags with an LLM.
- "EU AI Act report" will be read as certification. The template's first paragraph must say it is test evidence mapped to articles, not a conformity assessment.
