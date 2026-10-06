# Agents working in this repository

This file is for coding agents changing Insidia. The agent skill that *runs* a scan ships later, in `skills/insidia/`.

## Read first

- [plans/00-master-plan.md](plans/00-master-plan.md) is the current plan.
- [README.md](README.md) is what users see.
- [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) are the contribution and disclosure rules.

## Layout

- `cloud/` is Insidia Cloud (API, workers, hub).
- `benchmark/` is the scanner benchmark and the framework mappings.
- `core/` is the `insidia` CLI package (Python 3.12+).
- `site/` is the marketing site. `dashboard/` is the hosted product UI.

## Rules

- Keep a scan inside the declared scope. Localhost is the default. Do not add a path that scans an arbitrary host without `authorized: true`.
- Name the engine that produced a finding. Mask secrets as `[TYPE len=N fp=xxxxxxxx]`. Do not log prompts or raw tokens.
- Dependencies must be MIT, Apache-2.0, BSD, ISC, or reviewed MPL-2.0.
- Move files with `git mv`. Do not rewrite history.
- Do not commit `.env` files, customer data, or the `.cursor/` directory.
- The Insidia Labs name and logo are trademarks. They are not covered by Apache-2.0. See [NOTICE](NOTICE).

## Checks before you finish

From `cloud/`: `uv run ruff check .`, `uv run mypy api workers`, and `uv run pytest`.

From `core/`: `uv run ruff check .`, `uv run mypy insidia`, and `uv run pytest`.

From the repository root: `uv run --project cloud ruff check benchmark` and `uv run --project cloud python -m pytest benchmark`.

The matrix registry is generated. After a change to validity or ownership, run:

```bash
uv run --project cloud python -m benchmark.matrix.cells --write
```

Then `--check` must pass.
