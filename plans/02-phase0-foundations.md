# Phase 0 — Foundations (done)

> **v6. Status: done.** This phase built the Insidia Cloud foundation: API, workers, hub, and the security-first database. v6 keeps all of that and adds a local CLI (`core/`, Phase 1) under Apache-2.0. Three decisions below are superseded and kept here as history: ADR 0001 (no local mode), ADR 0004 (hide engine names), and ADR 0005 (stack is confidential). The replacements are in [00-master-plan.md](00-master-plan.md). `engine/` moved to `cloud/` in Phase 1.0. The layout list below is the Phase 0 tree; read `cloud/` wherever it says `engine/`.

Depends on: nothing. Blocks: every later phase.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A buildable monorepo with the Cloud components, a working Celery path that carries a tenant envelope, a license gate, and a written threat model. No scans yet. This phase did not build the CLI.

## Exit
- `runner/`, `engine/` (Python 3.14 API + Celery worker + Go hub), and `dashboard/` all build in CI.
- `docker compose up` brings up Postgres, RabbitMQ, Valkey, API, one Celery worker, the hub, and the docs site.
- A demo task `engine.workers.common.tasks.ping` runs with `{org_id, project_id, scan_id}` and writes one **encrypted** row that another org cannot read, and that a `pg_dump` shows only as ciphertext.
- The database foundation from [14-database-schema.md](14-database-schema.md) is in place: roles, forced RLS, the key service with envelope encryption, the plaintext-allowlist CI test, and the append-only audit table.
- ADRs and the threat model are in the repo. The license check fails the build on GPL/AGPL.

## Out of scope
Real engines, WireGuard, dashboard screens beyond a shell, SSO, billing.

## Layout to create
```
runner/                 Go module, cmd/insidia-runner
engine/api/             FastAPI app (Python 3.14, uv)
engine/workers/common/  Celery app, envelope, tenant context
engine/hub/             Go module, health only
engine/taxonomy-data/   empty README
dashboard/              Vite + React + TypeScript + Tailwind
shared/proto/           empty README (protobuf lands in Phase 1)
shared/sdk/             empty README
deploy/compose/         docker-compose.yml
deploy/ci/              or .github/workflows
engine/api/crypto/      key service client, AES-256-GCM, blind indexes, secret redactor
schema/plaintext_allowlist.yaml
docs/                   customer docs site (Starlight), see 15-customer-docs.md
internal/adr/           ADRs (not published)
internal/threat-model.md
.agents/skills/apple-design/  design skill for all dashboard work
THIRD_PARTY_NOTICES.md  published; linked from the README
```

## Steps
1. **Toolchain pins.** Python 3.14 for `engine/api` and `engine/workers`. Go 1.24+ for `runner/` and `engine/hub`. Node 22 for `dashboard/`. `uv` for Python, `ruff` + `mypy` + `pytest`, `golangci-lint`, `eslint` + `vitest`.
2. **API skeleton.** FastAPI app with `/healthz` and `/readyz`. Settings via pydantic-settings. SQLAlchemy/SQLModel + Alembic. First migration: the database roles, `orgs`, `org_keys`, `projects`, `audit_events`, and a `tenant_pings` table with an encrypted payload column. Postgres RLS, forced: `org_id = current_setting('app.org_id', true)::uuid`.
3. **Celery skeleton.** Broker on RabbitMQ (durable queues, publisher confirms, `acks_late=True`, `reject_on_worker_lost=True`, `x-max-priority`). Result backend on Postgres, storing only `{status, finding_count}`. Valkey for leases and pub/sub. Task base class reads the envelope, runs `SET LOCAL app.org_id`, and refuses to run if `org_id` is missing. Queues declared but mostly idle: `control`, `ai.fast`, `ai.heavy`, `classic.dast`, `static`, `agent`, `reports`.
4. **Demo task.** API endpoint (dev-only) enqueues `ping`. Worker inserts a row. A test uses two org ids and asserts the second session cannot see the first row.
5. **Go skeletons.** `insidia-runner version` and `insidia-hub version`. No network listeners beyond hub `/healthz` on localhost.
6. **Dashboard shell.** Vite app that fetches API `/healthz` and shows "engine reachable". No product UI, but the design tokens in `dashboard/src/design/` (spring presets, materials, type scale, severity palette) are set up following the apple-design skill.
7. **Compose.** Postgres 18, RabbitMQ, Valkey, a local KMS stand-in (Vault dev mode or a fixed test key, dev only), api, worker, hub, dashboard, docs. One command from a clean clone.
7a. **Key service.** `engine/api/crypto/` with a KMS interface (cloud KMS, Vault Transit, local dev), per-org key creation on org insert, AES-256-GCM with AAD, blind indexes, and the pepper for HMAC-stored tokens. See [14-database-schema.md](14-database-schema.md).
7b. **Docs scaffold.** Starlight site in `docs/` with the link-check CI from [15-customer-docs.md](15-customer-docs.md). The v5 engine-name denylist is retired; the secret and real-data checks stay.
8. **CI.** On push: Python lint/type/test, Go lint/test, dashboard lint/typecheck, compose config validation, license check.
9. **ADRs** (short, one decision each):
   - 0001 Cloud brain + thin runner, no local/free mode. **Superseded by v6:** the CLI is the free local product. The Cloud brain and thin runner stay for Phase 2C.
   - 0002 Relay mode vs tunnel mode.
   - 0003 Celery on RabbitMQ, Valkey (not Redis 8+), one brain, many runners, tenant envelope, fair scheduling deferred in detail to Phase 1 but the envelope exists now.
   - 0004 Use OSS engines as-is, never port; present them only as the Insidia Labs Engine; fill gaps with Insidia Labs-built modules ([16-coverage-gaps.md](16-coverage-gaps.md)). Python 3.14 for our code; lagging engines get their own image. **Superseded in part by v6:** engines are still used as-is and gaps are still ours, but they are credited by name. Cloud services stay on Python 3.14; the CLI targets Python 3.12+.
   - 0005 MIT/Apache only (MPL-2.0/BSD infrastructure after review). Stack is confidential. Attribution register honored. Runner ships no scanner code. **Superseded in part by v6:** the license allowlist stands, and the code is public under Apache-2.0, so attribution is a release requirement rather than an internal register. The runner still ships no scanner code.
   - 0006 `engine/hub` is Go inside the Python brain on purpose.
   - 0007 Two connection modes: direct (ownership-verified, egress proxy) and runner.
   - 0008 Database security: no plaintext customer values, envelope encryption per org, write-only secrets.
   - 0009 Dashboard design follows the apple-design skill.
10. **License gate.** `pip-licenses`, `go-licenses`, and `license-checker` for Node in CI, over our code and every engine image. Deny GPL, AGPL, SSPL, Elastic, BUSL, and attribution-required licenses. Allow MIT, Apache-2.0, BSD, ISC; MPL-2.0 only after review. Record the allowlist and the attribution register in `THIRD_PARTY_NOTICES.md`.
11. **Threat model** (`internal/threat-model.md`), covering:
    - Stolen runner credential scanning a host outside the allowlist.
    - Cross-org data leak via a missing envelope or a shared object-storage prefix.
    - Tunnel used as a general VPN into the customer network.
    - Customer scans a target they do not own.
    - Untrusted model output parsed by workers (injection into our parsers).
    - Secrets in logs, Celery result backend, or traces.
    - Database dump or backup theft (every customer value must be ciphertext).
    - Direct mode used for SSRF into our cloud, or to scan unverified hosts.
    - Engine containers phoning home (telemetry, remote generation) and sending a user's prompts or target addresses to a third party.
    Each item gets a mitigation owner phase (mostly 1, 2, and 10).

## Tests
- RLS isolation test (two orgs).
- Celery task rejected when `org_id` is absent.
- Transaction without `app.org_id` sees zero rows.
- Plaintext-allowlist schema test, and a `pg_dump` canary test on the demo row.
- Ciphertext moved to another row fails to decrypt (AAD).
- Audit table rejects `UPDATE` and `DELETE`.
- Health endpoints return 200 inside compose.

## Risks
- Python 3.14 wheels for SQLAlchemy, Celery, or pydantic may lag. Pin known-good versions in Phase 0; do not block on garak's Python here.
- RLS is easy to bypass with a superuser connection. App roles must not be table owners and must not have `BYPASSRLS`.
