# Insidia Labs

Phase 0 is the foundation: API, worker, hub, runner, dashboard shell, and docs. No scans yet.

```bash
docker compose -f deploy/compose/docker-compose.yml up --build
```

The API answers `http://127.0.0.1:8000/healthz`. The dashboard is `http://127.0.0.1:5173`. Dev endpoints and the dev master key exist only when `INSIDIA_DEV_MODE=true`.

Without Docker, from `engine/`:

```bash
uv sync
uv run ruff check .
uv run mypy api workers
uv run pytest
```

Set `INSIDIA_TEST_DATABASE_URL` to a Postgres 18 superuser URL to run the row-level security tests.