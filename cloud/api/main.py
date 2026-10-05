"""Insidia Labs API. Phase 0 serves health checks and a dev-only tenant ping."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from api.crypto import KeyService, LocalDevKms, encrypt, make_aad
from api.db import engines_from
from api.settings import get_settings


class PingRequest(BaseModel):
    org_id: uuid.UUID
    project_id: uuid.UUID
    scan_id: uuid.UUID
    payload: str


class PingAccepted(BaseModel):
    task_id: str


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    get_settings()
    yield


app = FastAPI(title="Insidia Labs", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    settings = get_settings()
    api_engine, _, _ = engines_from(settings)
    try:
        with api_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready"}


@app.post("/dev/orgs")
def create_org(name: str, region: str = "us") -> dict[str, str]:
    """Dev-only signup. Creates an org and its wrapped keys."""
    settings = get_settings()
    if not settings.dev_endpoints:
        raise HTTPException(status_code=404, detail="not found")
    api_engine, keys_engine, _ = engines_from(settings)
    org_id = uuid.uuid4()
    kms = LocalDevKms(settings.master_key)
    # The org row must exist before its data key (org_keys.org_id is a foreign key).
    # The placeholder is ciphertext under the master key and is replaced in the next step.
    placeholder = encrypt(
        b"",
        key=settings.master_key,
        key_version=1,
        aad=make_aad(str(org_id), "orgs", "name_enc", str(org_id)),
    )
    with api_engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO orgs (id, name_enc, region)
                VALUES (:id, :name_enc, :region)
                """
            ),
            {"id": org_id, "name_enc": placeholder, "region": region},
        )
    keys = KeyService(kms, keys_engine)
    keys.ensure_org_keys(org_id)
    dek, version = keys.data_key(org_id)
    name_blob = encrypt(
        name.encode(),
        key=dek,
        key_version=version,
        aad=make_aad(str(org_id), "orgs", "name_enc", str(org_id)),
    )
    project_id = uuid.uuid4()
    project_blob = encrypt(
        b"default",
        key=dek,
        key_version=version,
        aad=make_aad(str(org_id), "projects", "name_enc", str(project_id)),
    )
    with api_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('app.org_id', :org_id, true)"),
            {"org_id": str(org_id)},
        )
        conn.execute(
            text("UPDATE orgs SET name_enc = :name_enc WHERE id = :id"),
            {"id": org_id, "name_enc": name_blob},
        )
        conn.execute(
            text(
                """
                INSERT INTO projects (id, org_id, name_enc)
                VALUES (:id, :org_id, :name_enc)
                """
            ),
            {"id": project_id, "org_id": org_id, "name_enc": project_blob},
        )
    return {"org_id": str(org_id), "project_id": str(project_id)}


@app.post("/dev/ping", response_model=PingAccepted)
def dev_ping(body: PingRequest) -> PingAccepted:
    settings = get_settings()
    if not settings.dev_endpoints:
        raise HTTPException(status_code=404, detail="not found")
    from workers.common.tasks import ping

    async_result = ping.delay(
        {
            "org_id": str(body.org_id),
            "project_id": str(body.project_id),
            "scan_id": str(body.scan_id),
        },
        body.payload,
    )
    return PingAccepted(task_id=str(async_result.id))
