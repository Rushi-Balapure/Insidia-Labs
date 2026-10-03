"""RLS and ciphertext tests. They run when INSIDIA_TEST_DATABASE_URL points at Postgres 18."""

from __future__ import annotations

import os
import subprocess
import uuid
from collections.abc import Iterator

import pytest
from api.crypto.envelope import CryptoError, decrypt, make_aad
from api.crypto.kms import DEV_MASTER_KEY
from api.settings import get_settings
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

pytestmark = pytest.mark.skipif(
    not os.environ.get("INSIDIA_TEST_DATABASE_URL"),
    reason="set INSIDIA_TEST_DATABASE_URL to a Postgres 18 superuser URL",
)


@pytest.fixture(scope="module")
def migrated_database() -> Iterator[str]:
    url = os.environ["INSIDIA_TEST_DATABASE_URL"]
    os.environ["INSIDIA_DEV_MODE"] = "true"
    os.environ["INSIDIA_MIGRATION_DATABASE_URL"] = url
    get_settings.cache_clear()
    subprocess.run(["uv", "run", "alembic", "upgrade", "head"], check=True, cwd=".")  # noqa: S603,S607
    yield url
    get_settings.cache_clear()


def _app_url(user: str, password: str, super_url: str) -> str:
    rest = super_url.split("@", 1)[1]
    return f"postgresql+psycopg://{user}:{password}@{rest}"


def test_second_org_cannot_read_the_ping(migrated_database: str) -> None:
    from workers.common.tasks import ping

    os.environ["INSIDIA_DEV_MODE"] = "true"
    os.environ["INSIDIA_DEV_ENDPOINTS"] = "true"
    get_settings.cache_clear()
    from api.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    first = client.post("/dev/orgs", params={"name": "canary-org-one"}).json()
    second = client.post("/dev/orgs", params={"name": "canary-org-two"}).json()
    scan_id = str(uuid.uuid4())
    ping(
        {
            "org_id": first["org_id"],
            "project_id": first["project_id"],
            "scan_id": scan_id,
        },
        "canary-plaintext-ping",
    )
    worker = create_engine(_app_url("app_worker", "app_worker_dev_only", migrated_database))
    with worker.begin() as conn:
        conn.execute(
            text("SELECT set_config('app.org_id', :org_id, true)"),
            {"org_id": second["org_id"]},
        )
        rows = conn.execute(text("SELECT payload_enc FROM tenant_pings")).all()
    assert rows == []
    with worker.connect() as conn:
        unset = conn.execute(text("SELECT payload_enc FROM tenant_pings")).all()
    assert unset == []


def test_dump_hides_plaintext_and_aad_blocks_a_swap(migrated_database: str) -> None:
    from workers.common.tasks import ping

    os.environ["INSIDIA_DEV_MODE"] = "true"
    get_settings.cache_clear()
    from api.main import app
    from fastapi.testclient import TestClient

    created = TestClient(app).post("/dev/orgs", params={"name": "dump-canary-org"}).json()
    ping(
        {
            "org_id": created["org_id"],
            "project_id": created["project_id"],
            "scan_id": str(uuid.uuid4()),
        },
        "dump-canary-plaintext",
    )
    owner = create_engine(migrated_database)
    with owner.connect() as conn:
        blob = conn.execute(text("SELECT payload_enc, id, org_id FROM tenant_pings")).one()
        dump = subprocess.run(  # noqa: S603
            ["pg_dump", "--data-only", "--table", "tenant_pings", migrated_database],
            check=False,
            capture_output=True,
            text=True,
        )
    if dump.returncode == 0:
        assert "dump-canary-plaintext" not in dump.stdout
    else:
        raw = bytes(blob.payload_enc)
        assert b"dump-canary-plaintext" not in raw
    from api.crypto.keys import KeyService
    from api.crypto.kms import LocalDevKms
    from api.db import make_engine

    keys = KeyService(LocalDevKms(DEV_MASTER_KEY), make_engine(get_settings().keys_database_url))
    dek, _version = keys.data_key(uuid.UUID(created["org_id"]))
    wrong = make_aad(created["org_id"], "tenant_pings", "payload_enc", str(uuid.uuid4()))
    with pytest.raises(CryptoError):
        decrypt(bytes(blob.payload_enc), key=dek, aad=wrong)


def test_audit_update_is_rejected(migrated_database: str) -> None:
    owner = create_engine(migrated_database)
    org_id = uuid.uuid4()
    digest = b"\x00" * 32
    try:
        with owner.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO orgs (id, name_enc, region) VALUES (:id, :name_enc, 'us')"
                ),
                {"id": org_id, "name_enc": b"\x00"},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO audit_events
                      (org_id, actor_type, action, key_version, prev_hash, row_hash)
                    VALUES
                      (:org_id, 'system', 'phase0.test', 1, :digest, :digest)
                    """
                ),
                {"org_id": org_id, "digest": digest},
            )
            conn.execute(
                text("UPDATE audit_events SET action = 'tamper' WHERE org_id = :org_id"),
                {"org_id": org_id},
            )
    except ProgrammingError as exc:
        assert "append-only" in str(exc)
        return
    raise AssertionError("audit update was accepted")
