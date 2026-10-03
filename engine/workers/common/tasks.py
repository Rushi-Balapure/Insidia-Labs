"""Demo task: encrypt one payload into tenant_pings under the envelope org."""

from __future__ import annotations

import uuid

from api.crypto import KeyService, LocalDevKms, encrypt, make_aad
from api.db import engines_from
from api.settings import get_settings
from sqlalchemy import text

from workers.common.celery_app import celery_app
from workers.common.tenant import tenant_transaction


@celery_app.task(name="engine.workers.common.tasks.ping")  # type: ignore[untyped-decorator]
def ping(envelope: dict[str, str], payload: str) -> dict[str, int | str]:
    org_id = uuid.UUID(envelope["org_id"])
    project_id = uuid.UUID(envelope["project_id"])
    scan_id = uuid.UUID(envelope["scan_id"])
    settings = get_settings()
    _, keys_engine, _ = engines_from(settings)
    keys = KeyService(LocalDevKms(settings.master_key), keys_engine)
    dek, version = keys.data_key(org_id)
    row_id = uuid.uuid4()
    blob = encrypt(
        payload.encode(),
        key=dek,
        key_version=version,
        aad=make_aad(str(org_id), "tenant_pings", "payload_enc", str(row_id)),
    )
    with tenant_transaction() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tenant_pings
                  (id, org_id, project_id, scan_id, payload_enc, key_version)
                VALUES
                  (:id, :org_id, :project_id, :scan_id, :payload_enc, :key_version)
                """
            ),
            {
                "id": row_id,
                "org_id": org_id,
                "project_id": project_id,
                "scan_id": scan_id,
                "payload_enc": blob,
                "key_version": version,
            },
        )
    return {"status": "ok", "finding_count": 0}
