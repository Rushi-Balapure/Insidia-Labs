"""Celery application. Every task must carry a tenant envelope."""

from api.settings import get_settings
from celery import Celery, Task
from kombu import Exchange, Queue

from workers.common.tenant import current_org_id

_QUEUES = (
    "control",
    "ai.fast",
    "ai.heavy",
    "classic.dast",
    "static",
    "agent",
    "reports",
)


class TenantTask(Task):  # type: ignore[misc]
    """Refuse work that has no org, then bind that org for tenant_transaction."""

    def __call__(self, *args: object, **kwargs: object) -> object:
        envelope = args[0] if args else kwargs.get("envelope")
        org_id = envelope.get("org_id") if isinstance(envelope, dict) else None
        if not org_id:
            raise ValueError("task envelope is missing org_id")
        token = current_org_id.set(str(org_id))
        try:
            return super().__call__(*args, **kwargs)
        finally:
            current_org_id.reset(token)


def _queues() -> tuple[Queue, ...]:
    return tuple(
        Queue(
            name,
            Exchange(name, type="direct"),
            routing_key=name,
            queue_arguments={"x-max-priority": 10},
            durable=True,
        )
        for name in _QUEUES
    )


def make_celery() -> Celery:
    settings = get_settings()
    app = Celery("insidia", task_cls=TenantTask)
    app.conf.update(
        broker_url=settings.broker_url,
        result_backend=settings.celery_database_url,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_queue="control",
        task_queues=_queues(),
        broker_transport_options={"confirm_publish": True},
        result_expires=3600,
        accept_content=["json"],
        task_serializer="json",
        result_serializer="json",
    )
    return app


celery_app = make_celery()

# Imported after the app exists so the task decorator can register ping.
from workers.common import tasks as _tasks  # noqa: E402,F401
