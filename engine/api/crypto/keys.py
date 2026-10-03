"""Per-org key creation and a short in-memory unwrap cache."""

from __future__ import annotations

import time
import uuid
from typing import Final

from sqlalchemy import Engine, text

from api.crypto.envelope import KEY_LEN
from api.crypto.kms import Kms, new_data_key

_PURPOSES: Final[tuple[str, ...]] = ("data", "secrets", "blind_index")
_CACHE_SECONDS = 300


class KeyService:
    def __init__(self, kms: Kms, keys_engine: Engine) -> None:
        self._kms = kms
        self._engine = keys_engine
        self._cache: dict[tuple[uuid.UUID, str], tuple[bytes, int, float]] = {}

    def ensure_org_keys(self, org_id: uuid.UUID) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"),
                {"org_id": str(org_id)},
            )
            existing = conn.execute(
                text("SELECT purpose FROM org_keys WHERE org_id = :org_id AND state = 'active'"),
                {"org_id": org_id},
            ).scalars()
            have = set(existing)
            for purpose in _PURPOSES:
                if purpose in have:
                    continue
                wrapped = self._kms.wrap(new_data_key())
                conn.execute(
                    text(
                        """
                        INSERT INTO org_keys
                          (org_id, purpose, key_version, wrapped_key, kms_key_ref, state)
                        VALUES
                          (:org_id, :purpose, 1, :wrapped_key, :kms_key_ref, 'active')
                        """
                    ),
                    {
                        "org_id": org_id,
                        "purpose": purpose,
                        "wrapped_key": wrapped,
                        "kms_key_ref": self._kms.key_ref,
                    },
                )

    def data_key(self, org_id: uuid.UUID, purpose: str = "data") -> tuple[bytes, int]:
        if purpose not in _PURPOSES:
            raise ValueError("unknown key purpose")
        cached = self._cache.get((org_id, purpose))
        now = time.monotonic()
        if cached is not None and now - cached[2] < _CACHE_SECONDS:
            return cached[0], cached[1]
        with self._engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"),
                {"org_id": str(org_id)},
            )
            row = conn.execute(
                text(
                    """
                    SELECT wrapped_key, key_version FROM org_keys
                    WHERE org_id = :org_id AND purpose = :purpose AND state = 'active'
                    ORDER BY key_version DESC
                    LIMIT 1
                    """
                ),
                {"org_id": org_id, "purpose": purpose},
            ).one()
        dek = self._kms.unwrap(bytes(row.wrapped_key))
        if len(dek) != KEY_LEN:
            raise ValueError("unwrapped key is not 256 bits")
        version = int(row.key_version)
        self._cache[(org_id, purpose)] = (dek, version, now)
        return dek, version
