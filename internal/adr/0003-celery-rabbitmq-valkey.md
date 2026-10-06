# 0003 Celery, RabbitMQ, and Valkey

Scans are Celery canvases. RabbitMQ is the broker (MPL-2.0, attribution required). Valkey is the cache and progress bus. Redis 8+ is rejected because its license is not MIT, Apache, BSD, or reviewed MPL. Every task carries `{org_id, project_id, scan_id}` and refuses to run without `org_id`. Fair scheduling across orgs is Phase 2C. The result backend stores status only.
