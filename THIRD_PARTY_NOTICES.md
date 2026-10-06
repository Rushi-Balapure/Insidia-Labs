# Internal attribution register. Not linked from the product or the docs site.

Direct dependencies are MIT, Apache-2.0, BSD, ISC, or MPL-2.0 after review.
GPL, AGPL, SSPL, Elastic, and BUSL are denied.

## Infrastructure that requires attribution

| Component | License | Obligation |
| --- | --- | --- |
| RabbitMQ | MPL-2.0 | Keep the license and copyright notice with any distribution that includes RabbitMQ. |
| PostgreSQL | PostgreSQL License | Keep the license notice. |
| Valkey | BSD-3 | Keep the copyright and license notice. |
| Celery | BSD-3 | Keep the copyright and license notice. |

## Engine code

| Component | License |
| --- | --- |
| FastAPI, Starlette, Uvicorn, Pydantic, Alembic, cryptography, psycopg | MIT or Apache-2.0 or BSD, as published by each project |
| PyYAML | MIT | The CLI reads `insidia.yaml` with PyYAML. Keep its copyright and license notice. |

The runner and the hub use only the Go standard library in Phase 0.
The dashboard uses React and Vite (MIT).
The docs site uses Astro and Starlight (MIT).

Engines added in later phases are recorded here before their image is built.
