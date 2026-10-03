"""Open a worker transaction with the tenant set for this task."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from api.db import engines_from
from api.settings import get_settings
from sqlalchemy import Connection, text

current_org_id: ContextVar[str | None] = ContextVar("current_org_id", default=None)


@contextmanager
def tenant_transaction() -> Iterator[Connection]:
    org_id = current_org_id.get()
    if not org_id:
        raise ValueError("task envelope is missing org_id")
    _, _, worker_engine = engines_from(get_settings())
    with worker_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('app.org_id', :org_id, true)"),
            {"org_id": org_id},
        )
        yield conn
