# Contributing

Insidia Labs is Apache-2.0. Contributions are welcome.

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/), version 1.1. Add this line to each commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` does that. There is no CLA.

By signing off, you certify that you can submit the change under the Apache License, Version 2.0.

## What to change

- The CLI lives in `core/`. The benchmark lives in `benchmark/`.
- Insidia Cloud lives in `cloud/`. Python there is 3.14. The CLI package is Python 3.12+.
- Do not add a dependency whose license is outside MIT, Apache-2.0, BSD, ISC, or a reviewed MPL-2.0. GPL, AGPL, SSPL, and Elastic-licensed code fail CI.
- A scan must stay inside the scope in `insidia.yaml`. Do not weaken that check.
- Credit an engine by name when a finding comes from it. Mask secrets. Do not log prompts.

## Checks

From `core/`:

```bash
uv sync
uv run ruff check .
uv run mypy insidia
uv run pytest
```

From `cloud/`:

```bash
uv sync
uv run ruff check .
uv run mypy api workers
uv run pytest
```

The scanner benchmark, from the repository root:

```bash
uv run --project cloud ruff check benchmark
uv run --project cloud python -m pytest benchmark
```

`INSIDIA_TEST_DATABASE_URL` must be a Postgres 18 superuser URL to run the row-level security tests.
