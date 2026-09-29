# Phase 0 — Foundations

Depends on: nothing. Blocks: every later phase.
Parent: [00-master-plan.md](00-master-plan.md).

## Goal
A buildable monorepo with the three top-level components, a working Celery path that carries a tenant envelope, license and confidentiality guardrails, and a written threat model. No scans yet.

## Exit
- `runner/`, `engine/` (Python 3.14 API + Celery worker + Go hub), and `dashboard/` all build in CI.
- `docker compose up` brings up Postgres, Redis, API, one Celery worker, and the hub.
- A demo task `engine.workers.common.tasks.ping` runs with `{org_id, project_id, scan_id}` and writes one row that another org cannot read.
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
docs/adr/
docs/threat-model.md
THIRD_PARTY_NOTICES.md  internal, not linked from any UI
```

## Steps
1. **Toolchain pins.** Python 3.14 for `engine/api` and `engine/workers`. Go 1.24+ for `runner/` and `engine/hub`. Node 22 for `dashboard/`. `uv` for Python, `ruff` + `mypy` + `pytest`, `golangci-lint`, `eslint` + `vitest`.
2. **API skeleton.** FastAPI app with `/healthz` and `/readyz`. Settings via pydantic-settings. SQLAlchemy/SQLModel + Alembic. First migration: `orgs`, `projects`, and a `tenant_pings` table. Postgres RLS: `org_id = current_setting('app.current_org_id')::uuid`.
3. **Celery skeleton.** Broker and result backend on Redis. Task base class reads the envelope, sets the DB session GUC `app.current_org_id`, and refuses to run if `org_id` is missing. Queues declared but mostly idle: `control`, `ai.fast`, `ai.heavy`, `classic.dast`, `static`, `agent`, `reports`.
4. **Demo task.** API endpoint (dev-only) enqueues `ping`. Worker inserts a row. A test uses two org ids and asserts the second session cannot see the first row.
5. **Go skeletons.** `insidia-runner version` and `insidia-hub version`. No network listeners beyond hub `/healthz` on localhost.
6. **Dashboard shell.** Vite app that fetches API `/healthz` and shows "engine reachable". No product UI.
7. **Compose.** Postgres 16, Redis 7, api, worker, hub, dashboard. One command from a clean clone.
8. **CI.** On push: Python lint/type/test, Go lint/test, dashboard lint/typecheck, compose config validation, license check.
9. **ADRs** (short, one decision each):
   - 0001 Cloud brain + thin runner, no local/free mode.
   - 0002 Relay mode vs tunnel mode.
   - 0003 Celery, one brain, many runners, tenant envelope, fair scheduling deferred in detail to Phase 1 but the envelope exists now.
   - 0004 Wrap OSS engines, then port. Python 3.14 for our code; lagging engines get their own image.
   - 0005 MIT/Apache only. Stack is confidential. Notices stay internal. Runner ships no scanner code.
   - 0006 `engine/hub` is Go inside the Python brain on purpose.
10. **License gate.** `pip-licenses` and `go-licenses` (or `go-licenses` equivalent) in CI. Deny GPL, AGPL, SSPL, Elastic, BUSL. Allow MIT, Apache-2.0, BSD, ISC, MPL-2.0 only after review. Record the allowlist in `THIRD_PARTY_NOTICES.md`.
11. **Threat model** (`docs/threat-model.md`), covering:
    - Stolen runner credential scanning a host outside the allowlist.
    - Cross-org data leak via a missing envelope or a shared object-storage prefix.
    - Tunnel used as a general VPN into the customer network.
    - Customer scans a target they do not own.
    - Untrusted model output parsed by workers (injection into our parsers).
    - Secrets in logs, Celery result backend, or traces.
    Each item gets a mitigation owner phase (mostly 1, 2, and 10).

## Tests
- RLS isolation test (two orgs).
- Celery task rejected when `org_id` is absent.
- Health endpoints return 200 inside compose.

## Risks
- Python 3.14 wheels for SQLAlchemy, Celery, or pydantic may lag. Pin known-good versions in Phase 0; do not block on garak's Python here.
- RLS is easy to bypass with a superuser connection. App roles must not be table owners and must not have `BYPASSRLS`.
